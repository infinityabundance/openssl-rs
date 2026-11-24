#!/usr/bin/env python3
"""policy_engine.py -- a deterministic policy engine: conjunction, denial by default.

Why this tool exists
--------------------
A release policy written as a score is a policy that hides which obligation
failed.  ``0.83`` does not say whether the independent verification was missing
or the threshold was met by aliases, and a candidate can raise the number by
strengthening an obligation nobody asked about.  A score also gives a decision
procedure the one thing the ETP constitution forbids: a way for a missing
evaluation to average into a pass.

The rule
--------
A policy is a **conjunction of obligations**, never a weighted sum.

  * every obligation is evaluated, in a recorded canonical order (ascending by
    id), against a record it names;
  * the decision is ``ADMIT`` only when every *required* obligation is ``MET``;
  * the default is **deny**, and a policy that does not declare
    ``default: "deny"`` is refused;
  * an obligation whose record is absent, unreadable or unresolvable is
    ``UNKNOWN`` and the decision is ``DENY`` with
    ``PE_REFUSED_OBLIGATION_UNEVALUATED`` -- it is never skipped;
  * ``UNKNOWN`` is never ``MET``, and ``NOT_APPLICABLE`` on a required
    obligation is never a pass;
  * two sources of one fact must agree, or the fact is ``UNKNOWN``
    (``PE_REFUSED_CONTRADICTION``);
  * the policy is **pinned separately**, and the pin is what makes a policy
    admissible: an unrecorded policy, an amended policy, a policy the candidate's
    own producer established or pinned, and a policy that waives an obligation
    for the candidate it decides are each refused.  A candidate may not choose
    the policy that judges it.

Determinism
-----------
Obligations are evaluated and printed in canonical order; output arrays are
sorted; a decision contains no timestamp; the engine evaluates the policy twice
and refuses with ``PE_REFUSED_NONDETERMINISTIC`` when the two canonical byte
strings differ.  Two runs of ``evaluate`` over the same records are byte
identical.

What this tool does not establish
---------------------------------
It does not re-run the tools that produced the records, verify a signature,
decide whether a record is true, or establish that the policy's author is an
independent party.  ``source.tool`` names the recorded producer; the engine
checks that the tool exists and computes the record's digest, and nothing more.
The pin lives in the same tree as the policy, so a writer who can amend both is
not detected without an external root: that obligation belongs to A12.

Exit status
-----------
``0`` when the decision is ``ADMIT`` (or a requested check passed), ``1`` when
it is ``DENY`` or a refusal fired, ``2`` for a usage or unreadable-input error.
The code and the decision are always printed.

Usage
-----
    python3 forensics/tools/policy_engine.py evaluate [--json]
    python3 forensics/tools/policy_engine.py explain A12.independent-attestation
    python3 forensics/tools/policy_engine.py verify-pin
    python3 forensics/tools/policy_engine.py verify-decision

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = "forensics/tools/policy_engine.py"

POLICY_SCHEMA = "openssl-rs/a20/policy/1"
PIN_SCHEMA = "openssl-rs/a20/policy-pin/1"
DECISION_SCHEMA = "openssl-rs/a20/decision/1"
CONTROLS_SCHEMA = "openssl-rs/a20/controls/1"

DEFAULT_POLICY = REPO_ROOT / "evidence/a20/POLICY.json"
DEFAULT_PIN = REPO_ROOT / "evidence/a20/POLICY-PIN.json"
DEFAULT_DECISION = REPO_ROOT / "evidence/a20/DECISION.json"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
CODE_OK = "PE_OK"
CODE_USAGE = "PE_USAGE"

DECISION_ADMIT = "ADMIT"
DECISION_DENY = "DENY"

STATE_MET = "MET"
STATE_UNMET = "UNMET"
STATE_UNKNOWN = "UNKNOWN"
STATE_NOT_APPLICABLE = "NOT_APPLICABLE"
STATES = (STATE_MET, STATE_UNMET, STATE_UNKNOWN, STATE_NOT_APPLICABLE)

# ---------------------------------------------------------------------------
# Refusal codes.  Each is stable and names the wrong conclusion it prevents.
# The document (docs/POLICY-ENGINE.md) must name every code here, and the test
# suite refuses a code that appears in one and not the other.
# ---------------------------------------------------------------------------

REFUSALS: dict[str, dict[str, str]] = {
    "PE_REFUSED_POLICY_INVALID": {
        "condition": "the policy is not a well-formed record of the declared schema, "
                     "carries a field the schema does not admit, or its recorded digest "
                     "does not match its bytes",
        "prevents": "that a document the engine cannot read is treated as a policy with "
                    "the obligations it happens to contain, and that bytes other than the "
                    "recorded policy are evaluated under its name",
    },
    "PE_REFUSED_PIN_INVALID": {
        "condition": "the pin is malformed: no policy digest, no pinning identity or role, "
                     "no candidate, or a field outside the declared schema",
        "prevents": "that an unreadable pin reads as a pin, so that 'the policy was "
                    "recorded' is satisfied by a record that names nothing",
    },
    "PE_REFUSED_POLICY_UNRECORDED": {
        "condition": "no pin records this policy, the pin names another policy id or path, "
                     "or the pin names a role that may not record a release policy",
        "prevents": "that a policy nobody recorded is evaluated as if it were the "
                    "project's policy, and that a policy is recorded by a party with no "
                    "authority to do so",
    },
    "PE_REFUSED_POLICY_AMENDED": {
        "condition": "the policy's current digest differs from the digest the pin records",
        "prevents": "that obligations are removed or weakened after the pin and the "
                    "amended policy is still presented as the pinned one",
    },
    "PE_REFUSED_POLICY_FROM_CANDIDATE": {
        "condition": "the policy was established or pinned by the candidate's own producer, "
                     "or by the producer role",
        "prevents": "that the candidate picks the policy that decides it, which is the "
                    "one substitution that makes every other obligation meaningless",
    },
    "PE_REFUSED_CANDIDATE_UNKNOWN": {
        "condition": "the candidate under test, or the producer that established it, is "
                     "not recorded, so the previous rule cannot be evaluated",
        "prevents": "that an unknown candidate reads as 'not the candidate's policy' and "
                    "the self-selection rule is silently unexercised",
    },
    "PE_REFUSED_SCORE": {
        "condition": "the policy carries a score, weight, threshold or other aggregation "
                     "key, or declares `scores` as anything but false",
        "prevents": "that obligations are combined into a number, where a passing "
                    "obligation hides a failing one and a missing evaluation averages in",
    },
    "PE_REFUSED_DEFAULT_ALLOW": {
        "condition": "the policy's `default` is not `deny`",
        "prevents": "that an obligation the policy forgot to declare, or failed to "
                    "evaluate, is admitted because the default is permissive",
    },
    "PE_REFUSED_DUPLICATE_OBLIGATION": {
        "condition": "two obligations in the policy share an id",
        "prevents": "that one obligation's result is counted twice, or that a duplicate "
                    "id silently overwrites the obligation it duplicates",
    },
    "PE_REFUSED_SELF_WAIVER": {
        "condition": "an obligation waives itself for the candidate the decision is about "
                     "(its identity or commit appears in the waiver)",
        "prevents": "that the policy exempts the very candidate it judges, which is the "
                    "permissive policy chosen for itself by another name",
    },
    "PE_REFUSED_OBLIGATION_UNEVALUATED": {
        "condition": "the obligation's record is absent, unreadable, not JSON, the declared "
                     "producing tool is absent, or its locator does not resolve",
        "prevents": "that an obligation nobody could read is skipped and the decision is "
                    "taken over the remaining obligations only",
    },
    "PE_REFUSED_OBLIGATION_UNKNOWN": {
        "condition": "the record resolves but a condition the predicate needs is absent or "
                     "of the wrong shape, so the obligation's result cannot be determined",
        "prevents": "that an unevaluable obligation is read as satisfied, and that a "
                    "missing field is read as a false condition",
    },
    "PE_REFUSED_OBLIGATION_NOT_APPLICABLE": {
        "condition": "a required obligation's applicability condition is false",
        "prevents": "that a required obligation is declared inapplicable to avoid "
                    "evaluating it; inapplicability is recorded and is never a pass",
    },
    "PE_REFUSED_CONTRADICTION": {
        "condition": "two sources declared to record the same fact disagree about whether "
                     "the fact holds",
        "prevents": "that one of two disagreeing records is preferred by order, rank or "
                     "timestamp, or that the disagreement is averaged into a positive result",
    },
    "PE_REFUSED_ORDER": {
        "condition": "the policy's obligation ids are not strictly ascending by id, or a "
                     "decision's order differs from the policy's canonical order",
        "prevents": "that two decisions over the same policy are compared over different "
                    "orders, and that an obligation is added, dropped or reordered after "
                     "the decision and the record still reads as that decision",
    },
    "PE_REFUSED_NONDETERMINISTIC": {
        "condition": "two evaluations of the same policy over the same records produce "
                     "different canonical bytes",
        "prevents": "that a decision is reproducible only by accident, and that a run "
                    "which happens to admit is quoted as the decision procedure's result",
    },
}

REFUSAL_CODES = tuple(REFUSALS)

FORBIDDEN_KEYS = {
    "score", "scores_total", "weight", "weighted", "weighting", "threshold",
    "confidence", "rank", "ranking", "aggregate", "composite", "grade",
    "level_score", "modality_rank", "modality_order",
}

POLICY_FIELDS = {
    "schema", "policyId", "version", "digest", "default", "scores",
    "obligations", "provenance",
}
OBLIGATION_FIELDS = {
    "id", "description", "required", "source", "predicate", "fact",
    "corroboration", "applicableWhen", "waivers",
}
SOURCE_FIELDS = {"tool", "record", "locator"}
PROVENANCE_FIELDS = {"establishedBy", "recordedAt", "independentOfCandidate"}
ESTABLISHED_BY_FIELDS = {"role", "identity"}
WAIVER_FIELDS = {"identity", "reason"}

PIN_FIELDS = {
    "schema", "policyId", "policyDigest", "policyPath", "pinnedAt", "pinnedBy",
    "candidate", "note",
}
PINNED_BY_FIELDS = {"role", "identity"}
PIN_CANDIDATE_FIELDS = {"commit", "producedBy"}

PREDICATE_OPS = ("eq", "none", "count-at-least", "all-in", "all")
CONDITION_OPS = (
    "eq", "neq", "lt", "lte", "gt", "gte", "in", "present", "absent",
    "empty", "nonempty", "truthy", "falsy", "eq-field",
)

PINNING_ROLES = ("maintainer",)
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class ToolError(Exception):
    """A usage or unreadable-input error, reported with exit status 2."""


# ---------------------------------------------------------------------------
# Canonical form and digests
# ---------------------------------------------------------------------------
def canonical(value: Any) -> str:
    """The one serialisation this tool hashes, compares and prints."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def policy_digest(policy: Mapping[str, Any]) -> str:
    """The digest of a policy, over everything except the digest field itself."""
    body = {key: value for key, value in policy.items() if key != "digest"}
    return digest(body)


def decision_bytes(decision: Mapping[str, Any]) -> bytes:
    """The bytes a decision is compared and written as."""
    return (json.dumps(decision, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


# ---------------------------------------------------------------------------
# Strict JSON
# ---------------------------------------------------------------------------
def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate object key {key!r}")
        seen[key] = value
    return seen


def _reject_constant(token: str) -> Any:
    raise ValueError(f"non-finite number {token!r}")


def parse_json(raw: bytes) -> Any:
    """Decode strict UTF-8 and parse, refusing duplicate keys and non-finites."""
    text = raw.decode("utf-8")
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)


def filesystem_reader(root: Path) -> Callable[[str], tuple[bytes | None, str | None]]:
    """Read record bytes from the repository, never outside it."""
    base = root.resolve()

    def read(relative: str) -> tuple[bytes | None, str | None]:
        if not isinstance(relative, str) or not relative:
            return None, "no record path"
        candidate = (base / relative).resolve()
        try:
            candidate.relative_to(base)
        except ValueError:
            return None, f"{relative!r} escapes the repository"
        if not candidate.is_file():
            return None, f"{relative!r} is absent"
        try:
            return candidate.read_bytes(), None
        except OSError as error:
            return None, f"{relative!r} is unreadable: {error.strerror}"

    return read


def memory_reader(records: Mapping[str, Any]) -> Callable[[str], tuple[bytes | None, str | None]]:
    """A reader over in-memory records; used only by control-only fixtures."""

    def read(relative: str) -> tuple[bytes | None, str | None]:
        if relative not in records:
            return None, f"{relative!r} is absent"
        return canonical(records[relative]).encode("utf-8"), None

    return read


# ---------------------------------------------------------------------------
# JSON pointers and member conditions
# ---------------------------------------------------------------------------
def resolve_pointer(value: Any, pointer: str) -> tuple[bool, Any]:
    """Resolve an RFC 6901 pointer; ``""`` is the value itself."""
    if pointer in ("", "/"):
        return True, value
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return False, None
    current = value
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not token.isdigit():
                return False, None
            index = int(token)
            if index >= len(current):
                return False, None
            current = current[index]
        elif isinstance(current, Mapping):
            if token not in current:
                return False, None
            current = current[token]
        else:
            return False, None
    return True, current


def _field(member: Any, dotted: str) -> tuple[bool, Any]:
    current = member
    for part in dotted.split("."):
        if isinstance(current, Mapping):
            if part not in current:
                return False, None
            current = current[part]
        elif isinstance(current, list):
            if not part.isdigit() or int(part) >= len(current):
                return False, None
            current = current[int(part)]
        else:
            return False, None
    return True, current


def _comparable(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def condition_holds(member: Any, condition: Mapping[str, Any]) -> bool | None:
    """True / False, or None when the condition cannot be determined.

    A missing field is None for every operator except ``present``/``absent``,
    which exist precisely to ask whether the record states a value.  That is
    what stops an absent field from being read as a false condition.
    """
    op = condition["op"]
    if op == "eq-field":
        first_ok, first = _field(member, condition["field"])
        second_ok, second = _field(member, condition["other"])
        if not (first_ok and second_ok):
            return None
        return first == second
    found, value = _field(member, condition["field"])
    if op == "present":
        return found and value is not None
    if op == "absent":
        return not (found and value is not None)
    if not found:
        return None
    if op in ("empty", "nonempty"):
        if not isinstance(value, (list, Mapping, str)):
            return None
        empty = len(value) == 0
        return empty if op == "empty" else not empty
    if op == "truthy":
        return bool(value)
    if op == "falsy":
        return not bool(value)
    if op == "in":
        return any(canonical(value) == canonical(item) for item in condition["value"])
    if op in ("eq", "neq"):
        equal = canonical(value) == canonical(condition["value"])
        return equal if op == "eq" else not equal
    if not _comparable(value) or not _comparable(condition["value"]):
        return None
    if op == "gt":
        return value > condition["value"]
    if op == "gte":
        return value >= condition["value"]
    if op == "lt":
        return value < condition["value"]
    if op == "lte":
        return value <= condition["value"]
    raise ToolError(f"unknown condition operator {op!r}")


def _counted(items: Sequence[Any], where: Sequence[Mapping[str, Any]]) -> tuple[int, int, list[str]]:
    """(matches, unevaluable, example ids) over the members that match every condition."""
    matches = 0
    unevaluable = 0
    examples: list[str] = []
    for item in items:
        verdict = True
        for condition in where:
            outcome = condition_holds(item, condition)
            if outcome is None:
                verdict = None
                break
            if not outcome:
                verdict = False
                break
        if verdict is True:
            matches += 1
            if isinstance(item, Mapping):
                label = item.get("id")
            else:
                label = None
            if isinstance(label, str) and len(examples) < 3:
                examples.append(label)
        elif verdict is None:
            unevaluable += 1
    return matches, unevaluable, sorted(examples)


# ---------------------------------------------------------------------------
# Predicates
# ---------------------------------------------------------------------------
def apply_predicate(located: Any, predicate: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate one predicate over the value its source locator resolved to.

    Returns ``{"state": MET|UNMET|UNKNOWN, "observed": {...}, "detail": str}``.
    """
    op = predicate["op"]

    if op == "eq":
        found, value = resolve_pointer(located, predicate["path"])
        if not found:
            return _unknown(
                {"pointer": predicate["path"], "expected": predicate["value"]},
                f"pointer {predicate['path']!r} does not resolve",
            )
        expected = predicate["value"]
        holds = canonical(value) == canonical(expected)
        return {
            "state": STATE_MET if holds else STATE_UNMET,
            "observed": {"value": value, "expected": expected},
            "detail": "the recorded value is the required one" if holds
                      else "the recorded value is not the required one",
        }

    if op in ("none", "count-at-least", "all-in"):
        if not isinstance(located, list):
            return _unknown(
                {"located": type(located).__name__},
                "the locator does not resolve to a list of members",
            )
        members = located
        if op == "all-in":
            field = predicate["field"]
            allowed = list(predicate["allowed"])
            violations: list[str] = []
            unreadable = 0
            for item in members:
                found, value = _field(item, field)
                if not found:
                    unreadable += 1
                    continue
                if value not in allowed:
                    label = item.get("id") if isinstance(item, Mapping) else None
                    violations.append(label if isinstance(label, str) else canonical(value))
            if not members:
                return _unknown(
                    {"members": 0},
                    "the population is empty, so the obligation was not exercised",
                )
            observed = {
                "members": len(members),
                "violations": len(violations),
                "unreadable": unreadable,
                "examples": sorted(violations)[:3],
                "allowed": allowed,
            }
            if violations:
                return {"state": STATE_UNMET, "observed": observed,
                        "detail": f"{len(violations)} member(s) are not in the admitted set"}
            if unreadable:
                return _unknown(observed, f"{unreadable} member(s) do not record the field")
            return {"state": STATE_MET, "observed": observed,
                    "detail": "every member is in the admitted set"}

        where = predicate.get("where") or []
        matches, unevaluable, examples = _counted(members, where)
        if op == "none":
            observed = {
                "members": len(members), "matches": matches,
                "unevaluable": unevaluable, "examples": examples,
                "vacuous": len(members) == 0,
            }
            if matches:
                return {"state": STATE_UNMET, "observed": observed,
                        "detail": f"{matches} member(s) match the forbidden condition"}
            if unevaluable:
                return _unknown(observed, f"{unevaluable} member(s) cannot be decided")
            if not members:
                return {"state": STATE_MET, "observed": observed,
                        "detail": "no member exists, so no member matches (vacuous)"}
            return {"state": STATE_MET, "observed": observed,
                    "detail": "no member matches the forbidden condition"}

        at_least = predicate["atLeast"]
        observed = {
            "members": len(members), "count": matches,
            "unevaluable": unevaluable, "atLeast": at_least, "examples": examples,
        }
        if unevaluable:
            return _unknown(observed, f"{unevaluable} member(s) cannot be decided")
        if matches >= at_least:
            return {"state": STATE_MET, "observed": observed,
                    "detail": f"{matches} qualifying member(s), at least {at_least} required"}
        return {"state": STATE_UNMET, "observed": observed,
                "detail": f"{matches} qualifying member(s), at least {at_least} required"}

    if op == "all":
        results = [apply_predicate(located, sub) for sub in predicate["of"]]
        observed = {"of": [result["observed"] for result in results]}
        states = [result["state"] for result in results]
        if STATE_UNMET in states:
            failing = [str(index) for index, state in enumerate(states) if state == STATE_UNMET]
            return {"state": STATE_UNMET, "observed": observed,
                    "detail": f"constituent predicate(s) {','.join(failing)} do not hold"}
        if STATE_UNKNOWN in states:
            return _unknown(observed, "a constituent predicate cannot be decided")
        return {"state": STATE_MET, "observed": observed,
                "detail": "every constituent predicate holds"}

    raise ToolError(f"unknown predicate operator {op!r}")


def _unknown(observed: Any, detail: str) -> dict[str, Any]:
    return {"state": STATE_UNKNOWN, "observed": observed, "detail": detail}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _check_fields(
    value: Any, allowed: Iterable[str], required: Iterable[str], label: str,
    where: str, problems: list[dict[str, Any]], code: str = "PE_REFUSED_POLICY_INVALID",
) -> bool:
    if not isinstance(value, Mapping):
        problems.append(_problem(code, f"{where}: {label} is not an object"))
        return False
    allowed_set = set(allowed)
    unknown = sorted(set(value) - allowed_set)
    if unknown:
        problems.append(_problem(code, f"{where}: {label} carries unknown field(s) {unknown}"))
    missing = sorted(set(required) - set(value))
    if missing:
        problems.append(_problem(code, f"{where}: {label} omits required field(s) {missing}"))
    return not unknown and not missing


def _problem(code: str, detail: str, obligation: str | None = None) -> dict[str, Any]:
    return {"code": code, "detail": detail, "obligation": obligation}


def _forbidden_keys(value: Any, path: str = "") -> list[str]:
    """Every score-shaped key anywhere in the policy."""
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            here = f"{path}/{key}" if path else key
            if key in FORBIDDEN_KEYS:
                found.append(here)
            found.extend(_forbidden_keys(item, here))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_forbidden_keys(item, f"{path}/{index}"))
    return found


def validate_source(
    value: Any, where: str, problems: list[dict[str, Any]],
) -> bool:
    if not _check_fields(value, SOURCE_FIELDS, ("tool", "record", "locator"), "source", where, problems):
        return False
    if not _is_text(value.get("tool")):
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: source.tool is not a path"))
        return False
    record = value.get("record")
    if not _is_text(record) or record.startswith("/") or ".." in record.split("/"):
        problems.append(_problem(
            "PE_REFUSED_POLICY_INVALID",
            f"{where}: source.record {record!r} is not a repository-relative path",
        ))
        return False
    locator = value.get("locator")
    if not isinstance(locator, str) or (locator not in ("", "/") and not locator.startswith("/")):
        problems.append(_problem(
            "PE_REFUSED_POLICY_INVALID", f"{where}: source.locator {locator!r} is not a pointer"
        ))
        return False
    return True


def validate_condition(value: Any, where: str, problems: list[dict[str, Any]]) -> bool:
    required = ("field", "op", "other") if isinstance(value, Mapping) and value.get("op") == "eq-field" else ("field", "op")
    if not isinstance(value, Mapping):
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: condition is not an object"))
        return False
    op = value.get("op")
    if op not in CONDITION_OPS:
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: unknown condition op {op!r}"))
        return False
    if not _is_text(value.get("field")):
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: condition.field is not a path"))
        return False
    if op == "eq-field":
        if not _is_text(value.get("other")):
            problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: condition.other is not a path"))
            return False
        extras = set(value) - {"field", "op", "other"}
    elif op in ("in",):
        if not isinstance(value.get("value"), list):
            problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: `in` needs a list value"))
            return False
        extras = set(value) - {"field", "op", "value"}
    elif op in ("present", "absent", "empty", "nonempty", "truthy", "falsy"):
        extras = set(value) - {"field", "op"}
    else:
        if "value" not in value:
            problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: condition {op!r} needs a value"))
            return False
        extras = set(value) - {"field", "op", "value"}
    if extras:
        problems.append(_problem(
            "PE_REFUSED_POLICY_INVALID", f"{where}: condition carries unknown field(s) {sorted(extras)}"
        ))
        return False
    return True


def validate_predicate(
    value: Any, where: str, problems: list[dict[str, Any]],
) -> bool:
    if not isinstance(value, Mapping):
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: predicate is not an object"))
        return False
    op = value.get("op")
    if op not in PREDICATE_OPS:
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: unknown predicate op {op!r}"))
        return False
    if op == "all":
        if set(value) != {"op", "of"} or not isinstance(value.get("of"), list) or not value["of"]:
            problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: `all` needs a non-empty `of`"))
            return False
        return all(
            validate_predicate(sub, f"{where}/of/{index}", problems)
            for index, sub in enumerate(value["of"])
        )
    if op == "eq":
        extras = set(value) - {"op", "path", "value"}
        ok = "path" in value and "value" in value and not extras
        if not ok:
            problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: `eq` needs path and value only"))
            return False
        return True
    if op == "all-in":
        extras = set(value) - {"op", "path", "field", "allowed"}
        ok = (
            _is_text(value.get("field"))
            and isinstance(value.get("allowed"), list)
            and bool(value["allowed"])
            and not extras
        )
        if not ok:
            problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: malformed `all-in`"))
        return ok
    extras = set(value) - {"op", "path", "where", "atLeast"}
    if extras:
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: malformed {op}"))
        return False
    where_list = value.get("where")
    if where_list is not None and not isinstance(where_list, list):
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: `where` is not a list"))
        return False
    for index, condition in enumerate(where_list or []):
        if not validate_condition(condition, f"{where}/where/{index}", problems):
            return False
    if op == "count-at-least":
        at_least = value.get("atLeast")
        if not isinstance(at_least, int) or isinstance(at_least, bool) or at_least < 1:
            problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: `atLeast` is not a positive integer"))
            return False
    return True


def validate_obligation(
    value: Any, where: str, problems: list[dict[str, Any]],
) -> bool:
    if not _check_fields(
        value, OBLIGATION_FIELDS, ("id", "description", "required", "source", "predicate"),
        "obligation", where, problems,
    ):
        return False
    if not _is_text(value["id"]) or not ID_RE.match(value["id"]):
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: id is not a stable identifier"))
        return False
    if not _is_text(value["description"]):
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: description is empty"))
        return False
    if not isinstance(value["required"], bool):
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: required is not a boolean"))
        return False
    ok = validate_source(value["source"], where, problems)
    ok = validate_predicate(value["predicate"], f"{where}/predicate", problems) and ok
    if "fact" in value and not _is_text(value["fact"]):
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: fact is not a label"))
        ok = False
    if "applicableWhen" in value:
        conditions = value["applicableWhen"]
        if not isinstance(conditions, list) or not conditions:
            problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: applicableWhen is not a non-empty list"))
            ok = False
        else:
            for index, condition in enumerate(conditions):
                ok = validate_condition(condition, f"{where}/applicableWhen/{index}", problems) and ok
    if "corroboration" in value:
        entries = value["corroboration"]
        if not isinstance(entries, list) or not entries:
            problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: corroboration is not a non-empty list"))
            ok = False
        else:
            for index, entry in enumerate(entries):
                here = f"{where}/corroboration/{index}"
                if not _check_fields(
                    entry, SOURCE_FIELDS | {"predicate"}, ("tool", "record", "locator", "predicate"),
                    "corroborating source", here, problems,
                ):
                    ok = False
                    continue
                ok = validate_source(
                    {key: entry[key] for key in SOURCE_FIELDS}, here, problems
                ) and ok
                ok = validate_predicate(entry["predicate"], f"{here}/predicate", problems) and ok
    if "waivers" in value:
        entries = value["waivers"]
        if not isinstance(entries, list) or not entries:
            problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{where}: waivers is not a non-empty list"))
            ok = False
        else:
            for index, entry in enumerate(entries):
                here = f"{where}/waivers/{index}"
                if not _check_fields(entry, WAIVER_FIELDS, ("identity", "reason"), "waiver", here, problems):
                    ok = False
                    continue
                if not _is_text(entry["identity"]) or not _is_text(entry["reason"]):
                    problems.append(_problem("PE_REFUSED_POLICY_INVALID", f"{here}: waiver is empty"))
                    ok = False
    return ok


def validate_policy(policy: Any) -> list[dict[str, Any]]:
    """Structural problems with a policy.  A structural problem is a refusal."""
    problems: list[dict[str, Any]] = []
    if not _check_fields(
        policy, POLICY_FIELDS,
        ("schema", "policyId", "version", "digest", "default", "scores", "obligations", "provenance"),
        "policy", "policy", problems,
    ):
        return problems
    for key in _forbidden_keys(policy):
        problems.append(_problem("PE_REFUSED_SCORE", f"policy: a score-shaped key at {key!r}"))
    if policy["schema"] != POLICY_SCHEMA:
        problems.append(_problem(
            "PE_REFUSED_POLICY_INVALID",
            f"policy: schema {policy['schema']!r} is not {POLICY_SCHEMA!r}",
        ))
    if not _is_text(policy["policyId"]):
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", "policy: policyId is empty"))
    if not isinstance(policy["version"], int) or isinstance(policy["version"], bool) or policy["version"] < 1:
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", "policy: version is not a positive integer"))
    if not isinstance(policy["digest"], str) or not DIGEST_RE.match(policy["digest"]):
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", "policy: digest is not a sha256 hex string"))
    elif policy["digest"] != policy_digest(policy):
        problems.append(_problem(
            "PE_REFUSED_POLICY_INVALID",
            "policy: the recorded digest does not match the policy's bytes",
        ))
    if policy["default"] != "deny":
        problems.append(_problem(
            "PE_REFUSED_DEFAULT_ALLOW",
            f"policy: default is {policy['default']!r}; a policy must deny by default",
        ))
    if policy["scores"] is not False:
        problems.append(_problem(
            "PE_REFUSED_SCORE", f"policy: scores is {policy['scores']!r}, not false"
        ))
    _check_fields(
        policy["provenance"], PROVENANCE_FIELDS,
        ("establishedBy", "recordedAt", "independentOfCandidate"), "provenance", "policy", problems,
    )
    if isinstance(policy["provenance"], Mapping):
        provenance = policy["provenance"]
        established = provenance.get("establishedBy")
        _check_fields(
            established, ESTABLISHED_BY_FIELDS, ("role", "identity"),
            "establishedBy", "policy/provenance", problems,
        )
        if isinstance(established, Mapping):
            if not _is_text(established.get("role")) or not _is_text(established.get("identity")):
                problems.append(_problem("PE_REFUSED_POLICY_INVALID", "policy: establishedBy is incomplete"))
        if not isinstance(provenance.get("recordedAt"), str) or not DATE_RE.match(str(provenance.get("recordedAt"))):
            problems.append(_problem("PE_REFUSED_POLICY_INVALID", "policy: provenance.recordedAt is not a date"))
        if not isinstance(provenance.get("independentOfCandidate"), bool):
            problems.append(_problem(
                "PE_REFUSED_POLICY_INVALID", "policy: provenance.independentOfCandidate is not a boolean"
            ))

    obligations = policy["obligations"]
    if not isinstance(obligations, list) or not obligations:
        problems.append(_problem("PE_REFUSED_POLICY_INVALID", "policy: obligations is not a non-empty list"))
        return problems

    ids: list[str] = []
    for index, obligation in enumerate(obligations):
        if not validate_obligation(obligation, f"policy/obligations/{index}", problems):
            continue
        ids.append(obligation["id"])
    if len(set(ids)) != len(ids):
        duplicates = sorted({item for item in ids if ids.count(item) > 1})
        problems.append(_problem(
            "PE_REFUSED_DUPLICATE_OBLIGATION",
            f"policy: duplicate obligation id(s) {duplicates}",
        ))
    elif ids != sorted(ids):
        problems.append(_problem(
            "PE_REFUSED_ORDER",
            "policy: obligation ids are not in canonical (ascending by id) order",
        ))
    return problems


def validate_pin(pin: Any) -> list[dict[str, Any]]:
    problems: list[dict[str, Any]] = []
    if not _check_fields(
        pin, PIN_FIELDS,
        ("schema", "policyId", "policyDigest", "policyPath", "pinnedAt", "pinnedBy", "candidate"),
        "pin", "pin", problems, code="PE_REFUSED_PIN_INVALID",
    ):
        return problems
    if pin["schema"] != PIN_SCHEMA:
        problems.append(_problem("PE_REFUSED_PIN_INVALID", f"pin: schema {pin['schema']!r} is not {PIN_SCHEMA!r}"))
    if not _is_text(pin["policyId"]):
        problems.append(_problem("PE_REFUSED_PIN_INVALID", "pin: policyId is empty"))
    if not isinstance(pin["policyDigest"], str) or not DIGEST_RE.match(pin["policyDigest"]):
        problems.append(_problem("PE_REFUSED_PIN_INVALID", "pin: policyDigest is not a sha256 hex string"))
    if not _is_text(pin["policyPath"]):
        problems.append(_problem("PE_REFUSED_PIN_INVALID", "pin: policyPath is empty"))
    if not isinstance(pin["pinnedAt"], str) or not DATE_RE.match(str(pin["pinnedAt"])):
        problems.append(_problem("PE_REFUSED_PIN_INVALID", "pin: pinnedAt is not a date"))
    _check_fields(
        pin["pinnedBy"], PINNED_BY_FIELDS, ("role", "identity"),
        "pinnedBy", "pin", problems, code="PE_REFUSED_PIN_INVALID",
    )
    pinned_by = pin["pinnedBy"] if isinstance(pin["pinnedBy"], Mapping) else {}
    if not _is_text(pinned_by.get("role")) or not _is_text(pinned_by.get("identity")):
        problems.append(_problem("PE_REFUSED_PIN_INVALID", "pin: pinnedBy is incomplete"))
    _check_fields(
        pin["candidate"], PIN_CANDIDATE_FIELDS, ("commit", "producedBy"),
        "candidate", "pin", problems, code="PE_REFUSED_PIN_INVALID",
    )
    candidate = pin["candidate"] if isinstance(pin["candidate"], Mapping) else {}
    if not _is_text(candidate.get("commit")) or not _is_text(candidate.get("producedBy")):
        problems.append(_problem("PE_REFUSED_PIN_INVALID", "pin: candidate is incomplete"))
    if "note" in pin and not isinstance(pin["note"], str):
        problems.append(_problem("PE_REFUSED_PIN_INVALID", "pin: note is not text"))
    return problems


# ---------------------------------------------------------------------------
# Candidate resolution
# ---------------------------------------------------------------------------
PRODUCER_LOCATOR = "/actions/release/context/evidenceProducer"
PRODUCER_RECORD = "evidence/a14/AUTHORISATION.json"


def resolve_candidate(
    root: Path = REPO_ROOT, commit: str | None = None, producer: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The candidate under test: its commit and the producer that established it.

    The producer identity is read from A14's own record rather than asserted by
    the caller, so 'the policy is not the candidate's own' is a statement about a
    recorded fact.  Absence is a refusal, never an empty identity that compares
    unequal to nothing.
    """
    problems: list[dict[str, Any]] = []
    identity = producer
    source_record = None
    if identity is None:
        record = root / PRODUCER_RECORD
        if record.is_file():
            try:
                document = parse_json(record.read_bytes())
            except (OSError, UnicodeDecodeError, ValueError) as error:
                problems.append(_problem(
                    "PE_REFUSED_CANDIDATE_UNKNOWN",
                    f"the producer record {PRODUCER_RECORD!r} is unreadable: {error}",
                ))
                document = None
            if document is not None:
                found, value = resolve_pointer(document, PRODUCER_LOCATOR)
                if found and _is_text(value):
                    identity = value
                    source_record = {"record": PRODUCER_RECORD, "locator": PRODUCER_LOCATOR}
        if identity is None and not problems:
            problems.append(_problem(
                "PE_REFUSED_CANDIDATE_UNKNOWN",
                f"no producer identity is recorded at {PRODUCER_RECORD}#{PRODUCER_LOCATOR}",
            ))
    if not _is_text(commit):
        problems.append(_problem("PE_REFUSED_CANDIDATE_UNKNOWN", "no candidate commit is recorded"))
    candidate = {
        "commit": commit if _is_text(commit) else None,
        "producedBy": {
            "identity": identity if _is_text(identity) else None,
            "record": source_record["record"] if source_record else None,
            "locator": source_record["locator"] if source_record else None,
        },
    }
    return candidate, problems


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
class _RecordCache:
    def __init__(self, reader: Callable[[str], tuple[bytes | None, str | None]]):
        self._reader = reader
        self._digests: dict[str, str] = {}
        self._values: dict[str, Any] = {}
        self._errors: dict[str, str] = {}

    def read(self, path: str) -> tuple[Any, str, str | None]:
        """(value, record digest or '', error)."""
        if path in self._errors:
            return None, self._digests.get(path, ""), self._errors[path]
        if path in self._values:
            return self._values[path], self._digests[path], None
        raw, error = self._reader(path)
        if raw is None:
            self._errors[path] = error or "absent"
            return None, "", self._errors[path]
        self._digests[path] = hashlib.sha256(raw).hexdigest()
        try:
            value = parse_json(raw)
        except (UnicodeDecodeError, ValueError) as parse_error:
            self._errors[path] = f"{path!r} is not strict JSON: {parse_error}"
            return None, self._digests[path], self._errors[path]
        self._values[path] = value
        return value, self._digests[path], None


def _source_of(source: Mapping[str, Any]) -> dict[str, Any]:
    return {"tool": source["tool"], "record": source["record"], "locator": source["locator"]}


def _evaluate_obligation(
    obligation: Mapping[str, Any],
    cache: _RecordCache,
    root: Path,
) -> dict[str, Any]:
    """One obligation's recorded result.  Every failure path is UNKNOWN, never MET."""
    identifier = obligation["id"]
    entry: dict[str, Any] = {
        "id": identifier,
        "required": obligation["required"],
        "source": _source_of(obligation["source"]),
        "fact": obligation.get("fact"),
        "recordSha256": None,
        "observed": None,
        "detail": "",
        "corroboration": [],
        "applicability": None,
        "waivers": obligation.get("waivers") or [],
    }
    codes: list[str] = []

    def unknown(state_detail: str, code: str, observed: Any = None) -> dict[str, Any]:
        entry["state"] = STATE_UNKNOWN
        entry["detail"] = state_detail
        entry["observed"] = observed
        entry["codes"] = [code]
        return entry

    tool_path = root / obligation["source"]["tool"]
    if not tool_path.is_file():
        return unknown(
            f"the declared producing tool {obligation['source']['tool']!r} is absent",
            "PE_REFUSED_OBLIGATION_UNEVALUATED",
        )

    value, record_digest, error = cache.read(obligation["source"]["record"])
    entry["recordSha256"] = record_digest or None
    if error is not None:
        return unknown(
            f"the source record is not readable: {error}",
            "PE_REFUSED_OBLIGATION_UNEVALUATED",
        )
    found, located = resolve_pointer(value, obligation["source"]["locator"])
    if not found:
        return unknown(
            f"the locator {obligation['source']['locator']!r} does not resolve in the record",
            "PE_REFUSED_OBLIGATION_UNEVALUATED",
        )

    if "applicableWhen" in obligation:
        applicable = True
        for condition in obligation["applicableWhen"]:
            outcome = condition_holds(located, condition) if isinstance(located, Mapping) else None
            if outcome is None:
                entry["applicability"] = "UNKNOWN"
                return unknown(
                    "the applicability condition cannot be decided",
                    "PE_REFUSED_OBLIGATION_UNKNOWN",
                )
            if not outcome:
                applicable = False
                break
        entry["applicability"] = "APPLICABLE" if applicable else "NOT_APPLICABLE"
        if not applicable:
            entry["state"] = STATE_NOT_APPLICABLE
            entry["detail"] = "the obligation's applicability condition is false"
            entry["observed"] = {"applicableWhen": obligation["applicableWhen"]}
            entry["codes"] = (
                ["PE_REFUSED_OBLIGATION_NOT_APPLICABLE"] if obligation["required"] else []
            )
            return entry

    result = apply_predicate(located, obligation["predicate"])
    entry["state"] = result["state"]
    entry["observed"] = result["observed"]
    entry["detail"] = result["detail"]
    if result["state"] == STATE_UNKNOWN:
        codes.append("PE_REFUSED_OBLIGATION_UNKNOWN")

    for corroborating in obligation.get("corroboration") or []:
        conforming: dict[str, Any] = {
            "source": _source_of(corroborating),
            "recordSha256": None,
            "state": STATE_UNKNOWN,
            "observed": None,
            "detail": "",
        }
        corr_value, corr_digest, corr_error = cache.read(corroborating["record"])
        conforming["recordSha256"] = corr_digest or None
        if corr_error is not None:
            conforming["detail"] = f"the corroborating record is not readable: {corr_error}"
            codes.append("PE_REFUSED_OBLIGATION_UNEVALUATED")
        else:
            corr_found, corr_located = resolve_pointer(corr_value, corroborating["locator"])
            if not corr_found:
                conforming["detail"] = "the corroborating locator does not resolve"
                codes.append("PE_REFUSED_OBLIGATION_UNEVALUATED")
            else:
                corr_result = apply_predicate(corr_located, corroborating["predicate"])
                conforming["state"] = corr_result["state"]
                conforming["observed"] = corr_result["observed"]
                conforming["detail"] = corr_result["detail"]
                if corr_result["state"] == STATE_UNKNOWN:
                    codes.append("PE_REFUSED_OBLIGATION_UNKNOWN")
        entry["corroboration"].append(conforming)
        if conforming["state"] in (STATE_MET, STATE_UNMET) and result["state"] in (STATE_MET, STATE_UNMET):
            if conforming["state"] != result["state"]:
                codes.append("PE_REFUSED_CONTRADICTION")
                entry["state"] = STATE_UNKNOWN
                entry["detail"] = (
                    f"the primary source gives {result['state']} and the corroborating source "
                    f"{conforming['source']['record']} gives {conforming['state']}; the fact is "
                    "not established"
                )

    entry["codes"] = sorted(set(codes))
    return entry


def _evaluate_once(
    policy: Mapping[str, Any],
    pin: Mapping[str, Any] | None,
    candidate: Mapping[str, Any],
    reader: Callable[[str], tuple[bytes | None, str | None]],
    root: Path,
    action: str,
    policy_path: str | None,
) -> dict[str, Any]:
    problems: list[dict[str, Any]] = []

    policy_problems = validate_policy(policy)
    problems.extend(policy_problems)

    pin_problems: list[dict[str, Any]] = []
    if pin is None:
        problems.append(_problem(
            "PE_REFUSED_POLICY_UNRECORDED",
            "no pin records this policy; a policy nobody recorded may not decide a release",
        ))
    else:
        pin_problems = validate_pin(pin)
        problems.extend(pin_problems)

    if pin is not None and not pin_problems:
        if pin["policyId"] != policy.get("policyId"):
            problems.append(_problem(
                "PE_REFUSED_POLICY_UNRECORDED",
                f"the pin records policy {pin['policyId']!r}, not {policy.get('policyId')!r}",
            ))
        if policy_path is not None and pin["policyPath"] != policy_path:
            problems.append(_problem(
                "PE_REFUSED_POLICY_UNRECORDED",
                f"the pin records the policy at {pin['policyPath']!r}, not {policy_path!r}",
            ))
        if pin["pinnedBy"]["role"] not in PINNING_ROLES:
            problems.append(_problem(
                "PE_REFUSED_POLICY_UNRECORDED",
                f"the pin is recorded by role {pin['pinnedBy']['role']!r}; only "
                f"{list(PINNING_ROLES)} may pin a release policy",
            ))
        if pin["policyDigest"] != policy.get("digest"):
            problems.append(_problem(
                "PE_REFUSED_POLICY_AMENDED",
                f"the pin records digest {pin['policyDigest']}, the policy is "
                f"{policy.get('digest')}; the policy was amended after the pin",
            ))

    producer = (candidate.get("producedBy") or {}).get("identity")
    if not _is_text(candidate.get("commit")) or not _is_text(producer):
        problems.append(_problem(
            "PE_REFUSED_CANDIDATE_UNKNOWN",
            "the candidate's commit or producer is unrecorded, so the policy's origin "
            "cannot be compared with the candidate",
        ))
    else:
        provenance = policy.get("provenance") or {}
        established = provenance.get("establishedBy") or {}
        if established.get("identity") == producer:
            problems.append(_problem(
                "PE_REFUSED_POLICY_FROM_CANDIDATE",
                f"the policy was established by {producer!r}, the candidate's own producer",
            ))
        if established.get("role") == "producer":
            problems.append(_problem(
                "PE_REFUSED_POLICY_FROM_CANDIDATE",
                "the policy was established in the producer role, which belongs to the candidate",
            ))
        if pin is not None and isinstance(pin.get("pinnedBy"), Mapping):
            if pin["pinnedBy"].get("identity") == producer:
                problems.append(_problem(
                    "PE_REFUSED_POLICY_FROM_CANDIDATE",
                    f"the policy was pinned by {producer!r}, the candidate's own producer",
                ))

    obligations = policy.get("obligations")
    evaluable = (
        isinstance(obligations, list)
        and bool(obligations)
        and all(isinstance(item, Mapping) for item in obligations)
        and not any(
            problem["code"] in ("PE_REFUSED_POLICY_INVALID", "PE_REFUSED_DUPLICATE_OBLIGATION",
                                "PE_REFUSED_ORDER")
            for problem in policy_problems
        )
    )

    entries: list[dict[str, Any]] = []
    if evaluable:
        cache = _RecordCache(reader)
        prepared = _sort_obligations(obligations)
        for obligation in prepared:
            entry = _evaluate_obligation(obligation, cache, root)
            entries.append(entry)
            for code in entry.get("codes") or []:
                problems.append(_problem(code, entry["detail"], obligation["id"]))
            for waiver in obligation.get("waivers") or []:
                if waiver["identity"] in (producer, candidate.get("commit")):
                    problems.append(_problem(
                        "PE_REFUSED_SELF_WAIVER",
                        f"obligation {obligation['id']!r} waives itself for "
                        f"{waiver['identity']!r}, the candidate it decides",
                        obligation["id"],
                    ))

    order = [entry["id"] for entry in entries]
    required = [entry for entry in entries if entry["required"]]
    codes = sorted({problem["code"] for problem in problems})
    admit = (
        not problems
        and bool(required)
        and all(entry["state"] == STATE_MET for entry in required)
    )
    decision = {
        "schema": DECISION_SCHEMA,
        "action": action,
        "candidate": {
            "commit": candidate.get("commit"),
            "producedBy": candidate.get("producedBy"),
        },
        "codes": codes,
        "decision": DECISION_ADMIT if admit else DECISION_DENY,
        "default": policy.get("default"),
        "met": sorted(entry["id"] for entry in entries if entry["state"] == STATE_MET),
        "notApplicable": sorted(
            entry["id"] for entry in entries if entry["state"] == STATE_NOT_APPLICABLE
        ),
        "obligationCount": len(entries),
        "obligations": entries,
        "order": order,
        "policyDigest": policy.get("digest"),
        "policyId": policy.get("policyId"),
        "policyVersion": policy.get("version"),
        "pinDigest": digest(pin) if pin is not None else None,
        "problems": sorted(
            problems,
            key=lambda item: (item.get("obligation") or "", item["code"], item["detail"]),
        ),
        "requiredCount": len(required),
        "scores": policy.get("scores"),
        "unmet": sorted(entry["id"] for entry in entries if entry["state"] == STATE_UNMET),
        "unknown": sorted(entry["id"] for entry in entries if entry["state"] == STATE_UNKNOWN),
    }
    return decision


def _sort_obligations(obligations: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return sorted(obligations, key=lambda item: item["id"])


def evaluate(
    policy: Mapping[str, Any],
    pin: Mapping[str, Any] | None,
    candidate: Mapping[str, Any],
    *,
    reader: Callable[[str], tuple[bytes | None, str | None]] | None = None,
    root: Path = REPO_ROOT,
    action: str = "release",
    policy_path: str | None = None,
    runs: int = 2,
) -> dict[str, Any]:
    """Evaluate the policy, twice, and refuse a nondeterministic result."""
    if runs < 1:
        raise ToolError("runs must be at least 1")
    read = reader or filesystem_reader(root)
    first = _evaluate_once(policy, pin, candidate, read, root, action, policy_path)
    for _ in range(runs - 1):
        again = _evaluate_once(policy, pin, candidate, read, root, action, policy_path)
        if canonical(again) != canonical(first):
            first["codes"] = sorted(set(first["codes"]) | {"PE_REFUSED_NONDETERMINISTIC"})
            first["decision"] = DECISION_DENY
            first["problems"] = sorted(
                first["problems"] + [_problem(
                    "PE_REFUSED_NONDETERMINISTIC",
                    "two evaluations of the same policy over the same records differ",
                )],
                key=lambda item: (item.get("obligation") or "", item["code"], item["detail"]),
            )
            break
    return first


def verify_pin(
    policy: Mapping[str, Any],
    pin: Mapping[str, Any] | None,
    candidate: Mapping[str, Any],
    policy_path: str | None = None,
) -> list[dict[str, Any]]:
    """The pin checks alone, without evaluating obligations."""
    problems: list[dict[str, Any]] = []
    if pin is None:
        return [_problem("PE_REFUSED_POLICY_UNRECORDED", "no pin records this policy")]
    pin_problems = validate_pin(pin)
    problems.extend(pin_problems)
    if pin_problems:
        return problems
    if pin["policyId"] != policy.get("policyId"):
        problems.append(_problem(
            "PE_REFUSED_POLICY_UNRECORDED",
            f"the pin records policy {pin['policyId']!r}, not {policy.get('policyId')!r}",
        ))
    if policy_path is not None and pin["policyPath"] != policy_path:
        problems.append(_problem(
            "PE_REFUSED_POLICY_UNRECORDED",
            f"the pin records the policy at {pin['policyPath']!r}, not {policy_path!r}",
        ))
    if pin["pinnedBy"]["role"] not in PINNING_ROLES:
        problems.append(_problem(
            "PE_REFUSED_POLICY_UNRECORDED",
            f"the pin is recorded by role {pin['pinnedBy']['role']!r}",
        ))
    if pin["policyDigest"] != policy.get("digest"):
        problems.append(_problem(
            "PE_REFUSED_POLICY_AMENDED",
            f"the pin records digest {pin['policyDigest']}, the policy is {policy.get('digest')}",
        ))
    producer = (candidate.get("producedBy") or {}).get("identity")
    if _is_text(producer):
        if pin["pinnedBy"]["identity"] == producer:
            problems.append(_problem(
                "PE_REFUSED_POLICY_FROM_CANDIDATE",
                f"the policy was pinned by {producer!r}, the candidate's own producer",
            ))
    return problems


def verify_decision(
    decision: Mapping[str, Any], policy: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Refuse a decision whose order differs from the policy's canonical order."""
    problems: list[dict[str, Any]] = []
    obligations = policy.get("obligations") or []
    expected = sorted(
        item["id"] for item in obligations if isinstance(item, Mapping) and _is_text(item.get("id"))
    )
    recorded_order = decision.get("order")
    if recorded_order != expected:
        problems.append(_problem(
            "PE_REFUSED_ORDER",
            f"the decision's order {recorded_order!r} is not the policy's order {expected!r}",
        ))
    entry_ids = [
        entry.get("id") for entry in decision.get("obligations") or [] if isinstance(entry, Mapping)
    ]
    if entry_ids != expected:
        problems.append(_problem(
            "PE_REFUSED_ORDER",
            f"the decision's obligations are ordered {entry_ids!r}, not {expected!r}",
        ))
    return problems


# ---------------------------------------------------------------------------
# Controls (control-only fixtures; never part of the real decision)
# ---------------------------------------------------------------------------
CONTROL_TOOL = TOOL_PATH
CONTROL_PRODUCER = "P-CONTROL-PRODUCER"
CONTROL_MAINTAINER = "P-CONTROL-MAINTAINER"
CONTROL_COMMIT = "c" * 40


def control_provenance() -> dict[str, Any]:
    return {
        "establishedBy": {"role": "maintainer", "identity": CONTROL_MAINTAINER},
        "recordedAt": "2026-11-24",
        "independentOfCandidate": False,
    }


def control_policy(obligations: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema": POLICY_SCHEMA,
        "policyId": "control-policy",
        "version": 1,
        "default": "deny",
        "scores": False,
        "obligations": copy.deepcopy(obligations),
        "provenance": control_provenance(),
    }
    body.update(overrides)
    body["digest"] = policy_digest(body)
    return body


def control_pin(policy: Mapping[str, Any], **overrides: Any) -> dict[str, Any]:
    pin: dict[str, Any] = {
        "schema": PIN_SCHEMA,
        "policyId": policy["policyId"],
        "policyDigest": policy["digest"],
        "policyPath": "evidence/a20/CONTROL-POLICY.json",
        "pinnedAt": "2026-11-24",
        "pinnedBy": {"role": "maintainer", "identity": CONTROL_MAINTAINER},
        "candidate": {"commit": CONTROL_COMMIT, "producedBy": CONTROL_PRODUCER},
    }
    pin.update(overrides)
    return pin


def control_candidate(identity: str | None = CONTROL_PRODUCER) -> dict[str, Any]:
    return {
        "commit": CONTROL_COMMIT,
        "producedBy": {
            "identity": identity,
            "record": PRODUCER_RECORD,
            "locator": PRODUCER_LOCATOR,
        },
    }


def _control_obligation(
    identifier: str,
    record: str,
    predicate: Mapping[str, Any],
    locator: str = "/facts",
    **extra: Any,
) -> dict[str, Any]:
    obligation = {
        "id": identifier,
        "description": f"control obligation {identifier}",
        "required": True,
        "source": {"tool": CONTROL_TOOL, "record": record, "locator": locator},
        "predicate": predicate,
    }
    obligation.update(extra)
    return obligation


def controls() -> list[dict[str, Any]]:
    """One control per refusal code, plus a positive that reaches ADMIT.

    Every fixture is synthetic and built here.  A control is not evidence about
    any real record; it is evidence that the decision procedure refuses the named
    wrong conclusion when it is presented.
    """
    closed = {"facts": {"state": "CLOSED"}}
    open_record = {"facts": {"state": "OPEN"}}
    skipped = {"facts": {"state": "CLOSED", "mode": "skip"}}
    members_none = {"facts": [{"id": "m1", "flag": False}, {"id": "m2", "flag": False}]}
    members_one = {"facts": [{"id": "m1", "flag": True}]}

    met = _control_obligation(
        "C01.met", "control/closed.json", {"op": "eq", "path": "/state", "value": "CLOSED"}
    )
    none_met = _control_obligation(
        "C02.none", "control/members-none.json",
        {"op": "none", "path": "/facts", "where": [{"field": "flag", "op": "truthy"}]},
    )

    fixtures: list[dict[str, Any]] = []

    def add(
        identifier: str, code: str, description: str, decision: Mapping[str, Any],
        extra: Any = None,
    ) -> None:
        observed = sorted(set(decision["codes"]))
        fixtures.append({
            "id": identifier,
            "kind": "control-only",
            "code": code,
            "description": description,
            "observed": {
                "codes": observed,
                "decision": decision["decision"],
                "unmet": decision["unmet"],
                "unknown": decision["unknown"],
                "notApplicable": decision["notApplicable"],
            },
            "established": code in observed,
            "extra": extra,
        })

    base_records = {
        "control/closed.json": closed,
        "control/open.json": open_record,
        "control/skipped.json": skipped,
        "control/members-none.json": members_none,
        "control/members-one.json": members_one,
    }

    # PE_REFUSED_POLICY_INVALID: a field the schema does not admit.
    policy = control_policy([met, none_met])
    policy["note"] = "an extra field"
    policy["digest"] = policy_digest(policy)
    add("policy-invalid", "PE_REFUSED_POLICY_INVALID",
        "a policy carrying a field outside the declared schema",
        evaluate(policy, control_pin(policy), control_candidate(),
                 reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_PIN_INVALID: a pin with no policy digest.
    policy = control_policy([met, none_met])
    pin = control_pin(policy)
    del pin["policyDigest"]
    add("pin-invalid", "PE_REFUSED_PIN_INVALID",
        "a pin that records no policy digest",
        evaluate(policy, pin, control_candidate(), reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_POLICY_UNRECORDED: no pin at all.
    policy = control_policy([met, none_met])
    add("policy-unrecorded", "PE_REFUSED_POLICY_UNRECORDED",
        "a policy that no pin records",
        evaluate(policy, None, control_candidate(), reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_POLICY_AMENDED: the pin names another digest.
    policy = control_policy([met, none_met])
    pin = control_pin(policy, policyDigest="a" * 64)
    add("policy-amended", "PE_REFUSED_POLICY_AMENDED",
        "a policy whose digest differs from the pin after an obligation was dropped",
        evaluate(policy, pin, control_candidate(), reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_POLICY_FROM_CANDIDATE: the candidate's producer established it.
    policy = control_policy([met, none_met])
    policy["provenance"]["establishedBy"] = {"role": "maintainer", "identity": CONTROL_PRODUCER}
    policy["digest"] = policy_digest(policy)
    add("policy-from-candidate", "PE_REFUSED_POLICY_FROM_CANDIDATE",
        "a policy established by the candidate's own producer",
        evaluate(policy, control_pin(policy), control_candidate(),
                 reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_CANDIDATE_UNKNOWN: the producer is unrecorded.
    policy = control_policy([met, none_met])
    add("candidate-unknown", "PE_REFUSED_CANDIDATE_UNKNOWN",
        "a candidate whose producer is unrecorded, so self-selection cannot be excluded",
        evaluate(policy, control_pin(policy), control_candidate(identity=None),
                 reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_SCORE: a score policy.
    policy = control_policy([met, none_met], scores=True)
    add("score-policy", "PE_REFUSED_SCORE",
        "a policy that declares itself scored",
        evaluate(policy, control_pin(policy), control_candidate(),
                 reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_SCORE: a weight on an obligation.
    policy = control_policy([met, none_met])
    policy["obligations"][0]["weight"] = 0.5
    policy["digest"] = policy_digest(policy)
    add("weighted-obligation", "PE_REFUSED_SCORE",
        "a policy that weights one obligation against another",
        evaluate(policy, control_pin(policy), control_candidate(),
                 reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_DEFAULT_ALLOW: a default-allow policy.
    policy = control_policy([met, none_met], default="allow")
    add("default-allow", "PE_REFUSED_DEFAULT_ALLOW",
        "a policy whose default is to allow",
        evaluate(policy, control_pin(policy), control_candidate(),
                 reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_DUPLICATE_OBLIGATION: the same id twice.
    policy = control_policy([met, dict(met)])
    add("duplicate-obligation", "PE_REFUSED_DUPLICATE_OBLIGATION",
        "a policy that counts one obligation twice",
        evaluate(policy, control_pin(policy), control_candidate(),
                 reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_SELF_WAIVER: the policy waives itself for the candidate.
    policy = control_policy([
        met,
        _control_obligation(
            "C03.waived", "control/open.json",
            {"op": "eq", "path": "/state", "value": "CLOSED"},
            waivers=[{"identity": CONTROL_PRODUCER, "reason": "the candidate is exempt"}],
        ),
    ])
    add("self-waiver", "PE_REFUSED_SELF_WAIVER",
        "a policy that waives an obligation for the candidate it decides",
        evaluate(policy, control_pin(policy), control_candidate(),
                 reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_OBLIGATION_UNEVALUATED: the record is absent, treated as a pass.
    policy = control_policy([
        met,
        _control_obligation(
            "C07.missing", "control/missing.json",
            {"op": "eq", "path": "/state", "value": "CLOSED"},
        ),
    ])
    add("unevaluated-as-pass", "PE_REFUSED_OBLIGATION_UNEVALUATED",
        "an obligation whose record is absent and which is not read as MET",
        evaluate(policy, control_pin(policy), control_candidate(),
                 reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_OBLIGATION_UNKNOWN: a condition the record cannot decide.
    policy = control_policy([
        met,
        _control_obligation(
            "C04.unknown", "control/members-none.json",
            {"op": "none", "path": "/facts", "where": [{"field": "absent_field", "op": "truthy"}]},
        ),
    ])
    add("unknown-never-met", "PE_REFUSED_OBLIGATION_UNKNOWN",
        "an obligation whose condition the record cannot decide",
        evaluate(policy, control_pin(policy), control_candidate(),
                 reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_OBLIGATION_NOT_APPLICABLE: a required obligation declared inapplicable.
    policy = control_policy([
        met,
        _control_obligation(
            "C05.inapplicable", "control/skipped.json",
            {"op": "eq", "path": "/state", "value": "CLOSED"},
            applicableWhen=[{"field": "mode", "op": "eq", "value": "apply"}],
        ),
    ])
    add("required-not-applicable", "PE_REFUSED_OBLIGATION_NOT_APPLICABLE",
        "a required obligation declared inapplicable, which is not a pass",
        evaluate(policy, control_pin(policy), control_candidate(),
                 reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_CONTRADICTION: two sources of one fact disagree.
    policy = control_policy([
        met,
        _control_obligation(
            "C06.contradiction", "control/open.json",
            {"op": "eq", "path": "/state", "value": "CLOSED"},
            corroboration=[{
                "tool": CONTROL_TOOL,
                "record": "control/closed.json",
                "locator": "/facts",
                "predicate": {"op": "eq", "path": "/state", "value": "CLOSED"},
            }],
        ),
    ])
    add("contradiction", "PE_REFUSED_CONTRADICTION",
        "two sources of one fact that disagree",
        evaluate(policy, control_pin(policy), control_candidate(),
                 reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_ORDER: the policy's ids are not in canonical order.
    policy = control_policy([none_met, met])
    add("policy-order", "PE_REFUSED_ORDER",
        "a policy whose obligations are not in canonical order",
        evaluate(policy, control_pin(policy), control_candidate(),
                 reader=memory_reader(base_records), runs=1))

    # PE_REFUSED_ORDER: a decision whose order differs from the policy's.
    policy = control_policy([met, none_met])
    decision = evaluate(policy, control_pin(policy), control_candidate(),
                        reader=memory_reader(base_records), runs=1)
    reordered = json.loads(json.dumps(decision))
    reordered["obligations"] = list(reversed(reordered["obligations"]))
    reordered["order"] = list(reversed(reordered["order"]))
    order_problems = verify_decision(reordered, policy)
    fixtures.append({
        "id": "decision-order",
        "kind": "control-only",
        "code": "PE_REFUSED_ORDER",
        "description": "a decision whose obligations are reordered against its policy",
        "observed": {
            "codes": sorted({problem["code"] for problem in order_problems}),
            "decision": DECISION_DENY,
            "unmet": [],
            "unknown": [],
            "notApplicable": [],
        },
        "established": any(problem["code"] == "PE_REFUSED_ORDER" for problem in order_problems),
        "extra": None,
    })

    # PE_REFUSED_NONDETERMINISTIC: a reader that changes between runs.
    policy = control_policy([met, none_met])
    calls = {"n": 0}

    def alternating(relative: str) -> tuple[bytes | None, str | None]:
        if relative == "control/closed.json":
            calls["n"] += 1
            body = closed if calls["n"] <= 1 else open_record
            return canonical(body).encode("utf-8"), None
        return memory_reader(base_records)(relative)

    add("nondeterministic", "PE_REFUSED_NONDETERMINISTIC",
        "a decision that differs between two evaluations of the same policy",
        evaluate(policy, control_pin(policy), control_candidate(),
                 reader=alternating, runs=2))

    # Positive control: every obligation MET reaches ADMIT.
    policy = control_policy([met, none_met])
    decision = evaluate(policy, control_pin(policy), control_candidate(),
                        reader=memory_reader(base_records), runs=2)
    fixtures.append({
        "id": "positive-admit",
        "kind": "control-only",
        "code": None,
        "description": "a synthetic policy whose obligations all reach MET reaches ADMIT",
        "observed": {
            "codes": sorted(set(decision["codes"])),
            "decision": decision["decision"],
            "unmet": decision["unmet"],
            "unknown": decision["unknown"],
            "notApplicable": decision["notApplicable"],
        },
        "established": decision["decision"] == DECISION_ADMIT and not decision["codes"],
        "extra": None,
    })
    return fixtures


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def _load(path: Path, label: str) -> Any:
    if not path.is_file():
        raise ToolError(f"{label} {str(path)!r} is absent")
    try:
        return parse_json(path.read_bytes())
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ToolError(f"{label} {str(path)!r} is unreadable: {error}") from error


def load_policy(path: Path | None = None) -> dict[str, Any]:
    document = _load(path or DEFAULT_POLICY, "policy")
    if not isinstance(document, dict):
        raise ToolError("the policy is not an object")
    return document


def load_pin(path: Path | None = None) -> dict[str, Any] | None:
    if path is None:
        return _load(DEFAULT_PIN, "pin") if DEFAULT_PIN.is_file() else None
    if not path.is_file():
        return None
    document = _load(path, "pin")
    if not isinstance(document, dict):
        raise ToolError("the pin is not an object")
    return document


def _relative(path: Path | None, default: Path) -> str:
    target = (path or default).resolve()
    try:
        return target.relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return target.as_posix()


# ---------------------------------------------------------------------------
# Printing
# ---------------------------------------------------------------------------
def _codes_text(codes: Iterable[str]) -> str:
    listing = sorted(set(codes))
    return ",".join(listing) if listing else "NONE"


def _obligation_line(entry: Mapping[str, Any]) -> str:
    return (
        f"obligation: id={entry['id']} state={entry['state']} "
        f"required={str(entry['required']).lower()} "
        f"record={entry['source']['record']}#{entry['source']['locator']} "
        f"observed={canonical(entry['observed'])} codes={_codes_text(entry.get('codes') or [])}"
    )


def print_decision(decision: Mapping[str, Any]) -> None:
    print(
        f"policy: id={decision['policyId']} version={decision['policyVersion']} "
        f"digest={decision['policyDigest']} default={decision['default']} "
        f"scores={str(decision['scores']).lower()} pin={decision['pinDigest']}"
    )
    print(
        f"decision: {decision['decision']} codes={_codes_text(decision['codes'])} "
        f"obligations={decision['obligationCount']} required={decision['requiredCount']} "
        f"met={len(decision['met'])} unmet={len(decision['unmet'])} "
        f"unknown={len(decision['unknown'])} notApplicable={len(decision['notApplicable'])}"
    )
    for entry in decision["obligations"]:
        print("  " + _obligation_line(entry))
    for problem in decision["problems"]:
        suffix = f" obligation={problem['obligation']}" if problem.get("obligation") else ""
        print(f"  refusal: code={problem['code']}{suffix} detail={problem['detail']}")
    print(f"  unmet: {','.join(decision['unmet']) if decision['unmet'] else 'NONE'}")
    print(f"  unknown: {','.join(decision['unknown']) if decision['unknown'] else 'NONE'}")
    print(
        f"  notApplicable: "
        f"{','.join(decision['notApplicable']) if decision['notApplicable'] else 'NONE'}"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _candidate_from(args: argparse.Namespace, pin: Mapping[str, Any] | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    commit = args.candidate
    if commit is None and pin is not None:
        candidate_block = pin.get("candidate") or {}
        if isinstance(candidate_block, Mapping):
            commit = candidate_block.get("commit")
    return resolve_candidate(REPO_ROOT, commit=commit, producer=args.producer)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def common(target: argparse.ArgumentParser) -> None:
        target.add_argument("--policy", default=None)
        target.add_argument("--pin", default=None)
        target.add_argument("--candidate", default=None)
        target.add_argument("--producer", default=None)
        target.add_argument("--action", default="release")

    evaluate_parser = sub.add_parser("evaluate", help="evaluate the pinned policy")
    common(evaluate_parser)
    evaluate_parser.add_argument("--json", action="store_true")

    explain_parser = sub.add_parser("explain", help="explain one obligation")
    explain_parser.add_argument("obligation")
    common(explain_parser)
    explain_parser.add_argument("--json", action="store_true")

    pin_parser = sub.add_parser("verify-pin", help="verify the policy against its pin")
    common(pin_parser)
    pin_parser.add_argument("--json", action="store_true")

    decision_parser = sub.add_parser("verify-decision", help="verify a recorded decision")
    decision_parser.add_argument("--decision", default=None)
    decision_parser.add_argument("--policy", default=None)

    args = parser.parse_args(argv)

    try:
        if args.command == "verify-decision":
            policy_path = Path(args.policy) if args.policy else DEFAULT_POLICY
            policy = load_policy(policy_path)
            decision_path = Path(args.decision) if args.decision else DEFAULT_DECISION
            decision = _load(decision_path, "decision")
            if not isinstance(decision, dict):
                raise ToolError("the decision is not an object")
            problems = verify_decision(decision, policy)
            codes = sorted({problem["code"] for problem in problems})
            print(
                f"decision-check: code={','.join(codes) if codes else CODE_OK} "
                f"decision={decision.get('decision')} order={len(decision.get('order') or [])}"
            )
            for problem in problems:
                print(f"  refusal: code={problem['code']} detail={problem['detail']}")
            return EXIT_REFUSED if problems else EXIT_OK

        policy_path = Path(args.policy) if args.policy else DEFAULT_POLICY
        policy = load_policy(policy_path)
        pin = load_pin(Path(args.pin) if args.pin else None)
        candidate, candidate_problems = _candidate_from(args, pin)
        policy_relative = _relative(policy_path, DEFAULT_POLICY)

        if args.command == "verify-pin":
            problems = verify_pin(policy, pin, candidate, policy_relative) + candidate_problems
            decision = evaluate(
                policy, pin, candidate, root=REPO_ROOT, action=args.action,
                policy_path=policy_relative,
            )
            codes = sorted({problem["code"] for problem in problems})
            pinned_by = pin.get("pinnedBy") if isinstance(pin, Mapping) else None
            pinned_candidate = pin.get("candidate") if isinstance(pin, Mapping) else None
            if getattr(args, "json", False):
                print(json.dumps(
                    {"pinCheck": "REFUSED" if problems else CODE_OK,
                     "codes": codes, "problems": problems, "decision": decision},
                    indent=2, sort_keys=True,
                ))
                return EXIT_REFUSED if problems else EXIT_OK
            print(
                f"pin: policyId={policy.get('policyId')} policyDigest={policy.get('digest')} "
                f"pinDigest={decision['pinDigest']} "
                f"pinnedBy={(pinned_by or {}).get('identity') if isinstance(pinned_by, Mapping) else None} "
                f"candidate={(pinned_candidate or {}).get('commit') if isinstance(pinned_candidate, Mapping) else None}"
            )
            print(f"pin-check: code={','.join(codes) if codes else CODE_OK} problems={len(problems)}")
            for problem in problems:
                print(f"  refusal: code={problem['code']} detail={problem['detail']}")
            print(
                f"decision: {decision['decision']} codes={_codes_text(decision['codes'])} "
                f"unmet={','.join(decision['unmet']) if decision['unmet'] else 'NONE'}"
            )
            return EXIT_REFUSED if problems else EXIT_OK

        decision = evaluate(
            policy, pin, candidate, root=REPO_ROOT, action=args.action,
            policy_path=policy_relative,
        )

        if args.command == "evaluate":
            if args.json:
                print(json.dumps(decision, indent=2, sort_keys=True))
            else:
                print_decision(decision)
            return EXIT_OK if decision["decision"] == DECISION_ADMIT else EXIT_REFUSED

        identifier = args.obligation
        entries = {entry["id"]: entry for entry in decision["obligations"]}
        if identifier not in entries:
            print(
                f"explain: code={CODE_USAGE} detail=no obligation with id {identifier!r} "
                f"is in policy {decision['policyId']}"
            )
            return EXIT_USAGE
        entry = entries[identifier]
        if args.json:
            print(json.dumps(
                {"decision": decision["decision"], "codes": decision["codes"], "obligation": entry},
                indent=2, sort_keys=True,
            ))
        else:
            print(
                f"obligation: id={entry['id']} state={entry['state']} "
                f"required={str(entry['required']).lower()} "
                f"codes={_codes_text(entry.get('codes') or [])}"
            )
            print(f"  source: tool={entry['source']['tool']} record={entry['source']['record']} "
                  f"locator={entry['source']['locator']} recordSha256={entry['recordSha256']}")
            print(f"  observed: {canonical(entry['observed'])}")
            print(f"  detail: {entry['detail']}")
            for corroborating in entry["corroboration"]:
                where = corroborating["source"]["record"]
                if corroborating["source"]["locator"]:
                    where = f"{where}#{corroborating['source']['locator']}"
                print(
                    f"  corroboration: record={where} "
                    f"state={corroborating['state']} "
                    f"observed={canonical(corroborating['observed'])}"
                )
            print(
                f"decision: {decision['decision']} codes={_codes_text(decision['codes'])} "
                f"unmet={','.join(decision['unmet']) if decision['unmet'] else 'NONE'}"
            )
        return EXIT_OK if entry["state"] == STATE_MET else EXIT_REFUSED
    except ToolError as error:
        print(f"{CODE_USAGE}: {error}")
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
