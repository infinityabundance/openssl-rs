#!/usr/bin/env python3
"""Independence roles, assignments and refusal machinery (ETP-T8).

The checker separates two questions that a single "signed by" field conflates:

* is the assignment record structurally admissible (``validate``); and
* is every *asserted* independence supported by distinct parties (``check``).

An assignment may honestly record that independence is absent.  That record is
admissible; the independence assertion it carries is refused.  Refusal is a
finding about the claim, not a defect in the record.

Six refusal rules are enforced, each naming the assignment and the field:

``IND_REVIEW_UNSUPPORTED``          independent review with no reviewer identity,
                                    role or artefact;
``IND_ADJUDICATOR_IS_AUTHOR``       adjudicator and author are not distinct where
                                    the claim class requires it;
``IND_REVIEWERS_ALIASED``           two "reviewers" share an identity or signing key;
``IND_THRESHOLD_ALIASED``           a distinct-party threshold is met only by aliases
                                    of one party (same account, key or infrastructure
                                    operator);
``IND_REPRODUCER_CONTAMINATED``     an "independent" reproduction used this
                                    repository's working environment or an artefact
                                    this project produced instead of a rebuild from
                                    the frozen package;
``IND_DISSENT_DROPPED``             a retained dissent is absent from the aggregate.

Dissent is conservative: the aggregate of an assignment is the worse of its
asserted verdict and every retained dissent attached to it.  A recorded aggregate
that is better than the computed meet is refused.

Python 3.11 standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_ROLES = "openssl-rs/etp-t8/roles/1"
SCHEMA_ASSIGNMENTS = "openssl-rs/etp-t8/assignments/1"

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLES_PATH = REPO_ROOT / "evidence" / "etp-t8" / "ROLES.json"
ASSIGNMENTS_PATH = REPO_ROOT / "evidence" / "etp-t8" / "ASSIGNMENTS.json"

SAMENESS_LEVELS = (
    "same_agent",
    "same_organisation",
    "same_infrastructure",
    "same_key",
)

ROLE_IDS = (
    "author",
    "proof_producer",
    "instrument_author",
    "evidence_producer",
    "adjudicator",
    "reviewer",
    "independent_reproducer",
    "release_authority",
    "revocation_authority",
)

# Lower rank is worse.  Aggregation takes the minimum.
VERDICT_RANK = {
    "REFUTED": 0,
    "CONTRADICTED": 0,
    "NOT_ESTABLISHED": 1,
    "RISK_ACCEPTED": 1,
    "SUPERSEDED": 1,
    "PARTIAL": 2,
    "ESTABLISHED": 3,
    "SAFETY_DISCHARGED": 4,
    "SAFE_COMPATIBLE": 5,
}

RANK_VERDICT = {
    0: "CONTRADICTED",
    1: "NOT_ESTABLISHED",
    2: "PARTIAL",
    3: "ESTABLISHED",
    4: "SAFETY_DISCHARGED",
    5: "SAFE_COMPATIBLE",
}

CLAIM_CLASSES = {
    "ORDINARY_CLAIM": {
        "description": "A documentary or measured claim that does not assert independence.",
        "required_distinct": [],
    },
    "SAFETY_DISCHARGED": {
        "description": "A reusable unsafe boundary whose obligations are declared discharged.",
        "required_distinct": [
            {"roles": ["adjudicator", "author"], "must_differ_at": ["same_agent"]},
            {"roles": ["adjudicator", "evidence_producer"], "must_differ_at": ["same_agent"]},
            {"roles": ["adjudicator", "instrument_author"], "must_differ_at": ["same_agent"]},
        ],
    },
    "SAFE_COMPATIBLE_RELEASE": {
        "description": "A consumer-family graduation or release decision.",
        "required_distinct": [
            {"roles": ["adjudicator", "author"], "must_differ_at": ["same_agent"]},
            {"roles": ["adjudicator", "evidence_producer"], "must_differ_at": ["same_agent"]},
            {"roles": ["independent_reproducer", "author"], "must_differ_at": list(SAMENESS_LEVELS)},
            {"roles": ["independent_reproducer", "evidence_producer"], "must_differ_at": list(SAMENESS_LEVELS)},
            {"roles": ["release_authority", "author"], "must_differ_at": ["same_agent"]},
            {"roles": ["release_authority", "adjudicator"], "must_differ_at": ["same_agent"]},
        ],
    },
    "INDEPENDENT_ADJUDICATION": {
        "description": "An adjudication that asserts independence from the claim it judges.",
        "required_distinct": [
            {"roles": ["adjudicator", "author"], "must_differ_at": ["same_agent"]},
            {"roles": ["adjudicator", "evidence_producer"], "must_differ_at": ["same_agent"]},
            {"roles": ["independent_reproducer", "author"], "must_differ_at": list(SAMENESS_LEVELS)},
        ],
    },
    "RELEASE_DECISION": {
        "description": "A release-gate decision that is not a SAFE_COMPATIBLE graduation.",
        "required_distinct": [
            {"roles": ["release_authority", "author"], "must_differ_at": ["same_agent"]},
        ],
    },
}

RULE_IDS = (
    "IND_REVIEW_UNSUPPORTED",
    "IND_ADJUDICATOR_IS_AUTHOR",
    "IND_REVIEWERS_ALIASED",
    "IND_THRESHOLD_ALIASED",
    "IND_REPRODUCER_CONTAMINATED",
    "IND_DISSENT_DROPPED",
)

STRUCTURAL_RULE_IDS = (
    "IND_ROLES_SCHEMA",
    "IND_ASSIGNMENTS_SCHEMA",
    "IND_ROLE_UNKNOWN",
    "IND_CLAIM_CLASS_UNKNOWN",
    "IND_ASSIGNMENT_DUPLICATE",
    "IND_PARTY_UNKNOWN",
    "IND_ASSIGNMENT_SHAPE",
    "IND_SAMENESS_MISMATCH",
    "IND_ROLE_UNFILLED",
    "IND_REQUIRED_ROLE_ABSENT",
    "IND_ROLE_NOT_DISTINCT",
    "IND_THRESHOLD_UNKNOWN",
    "IND_DISSENT_UNATTACHED",
    "IND_DISSENT_UNRETAINED",
    "IND_DISSENT_REMOVED_BY_TARGET",
    "IND_DISSENT_OVERRIDDEN",
    "IND_AGGREGATE_MISMATCH",
    "IND_JSON_DUPLICATE_KEY",
    "IND_JSON_NON_FINITE",
    "IND_DOC_UNREADABLE",
)


class DocumentError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Refusal:
    code: str
    assignment: str
    field: str
    detail: str

    def line(self) -> str:
        return (
            f"REFUSED {self.code} assignment={self.assignment} "
            f"field={self.field}: {self.detail}"
        )


# ---------------------------------------------------------------------------
# document handling


def load_json_strict(path: Path) -> Any:
    """Load a document that must have exactly one meaning."""

    def pairs_hook(pairs):
        seen: set[str] = set()
        for key, _ in pairs:
            if key in seen:
                raise DocumentError(
                    "IND_JSON_DUPLICATE_KEY", f"{path}: duplicate key {key!r}"
                )
            seen.add(key)
        return dict(pairs)

    def reject_constant(token):
        raise DocumentError("IND_JSON_NON_FINITE", f"{path}: non-finite number {token}")

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DocumentError("IND_DOC_UNREADABLE", f"{path}: {exc}") from exc
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise DocumentError("IND_DOC_UNREADABLE", f"{path}: not UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise DocumentError("IND_DOC_UNREADABLE", f"{path}: {exc}") from exc


def canonical(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def dump_json(payload: Any) -> str:
    return (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )


# ---------------------------------------------------------------------------
# party sameness


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def same_level(left: dict, right: dict, level: str) -> str:
    """Return SAME, DIFFERENT or UNKNOWN for one sameness level.

    UNKNOWN means distinctness is not established: absence of a declaration is
    never read as evidence of difference.
    """

    if left is right:
        return "SAME"

    if level == "same_agent":
        pairs = (
            ("identity", "identity"),
            ("account", "account"),
        )
        known: list[bool] = []
        for key_a, key_b in pairs:
            a, b = left.get(key_a), right.get(key_b)
            if _nonempty(a) and _nonempty(b):
                known.append(a.strip().lower() == b.strip().lower())
        if any(known):
            return "SAME"
        if known and not any(known):
            return "DIFFERENT"
        return "UNKNOWN"

    if level == "same_organisation":
        a, b = left.get("organisation"), right.get("organisation")
        if _nonempty(a) and _nonempty(b):
            return "SAME" if a.strip().lower() == b.strip().lower() else "DIFFERENT"
        return "UNKNOWN"

    if level == "same_infrastructure":
        for key in ("infrastructure_operator", "infrastructure"):
            a, b = left.get(key), right.get(key)
            if _nonempty(a) and _nonempty(b):
                if a.strip().lower() == b.strip().lower():
                    return "SAME"
                if key == "infrastructure_operator":
                    # Two distinct operators are different infrastructure even
                    # if one URL is not recorded.
                    return "DIFFERENT"
        a, b = left.get("infrastructure"), right.get("infrastructure")
        if _nonempty(a) and _nonempty(b):
            return "DIFFERENT"
        return "UNKNOWN"

    if level == "same_key":
        a, b = left.get("signing_key"), right.get("signing_key")
        if _nonempty(a) and _nonempty(b):
            return "SAME" if a.strip() == b.strip() else "DIFFERENT"
        return "UNKNOWN"

    return "UNKNOWN"


def sameness(left: dict, right: dict) -> dict[str, str]:
    return {level: same_level(left, right, level) for level in SAMENESS_LEVELS}


def _party(assignments_doc: dict, party_id: str) -> dict | None:
    parties = assignments_doc.get("parties")
    if not isinstance(parties, dict):
        return None
    party = parties.get(party_id)
    return party if isinstance(party, dict) else None


def _filled(assignment: dict, role: str) -> dict | None:
    filled = assignment.get("filled")
    if not isinstance(filled, dict):
        return None
    entry = filled.get(role)
    if not isinstance(entry, dict):
        return None
    if entry.get("status", "FILLED") == "ABSENT":
        return None
    return entry


def _filled_party(assignments_doc: dict, assignment: dict, role: str) -> dict | None:
    entry = _filled(assignment, role)
    if entry is None:
        return None
    party_id = entry.get("party")
    if not isinstance(party_id, str):
        return None
    return _party(assignments_doc, party_id)


def assignment_same_party(assignments_doc: dict, assignment: dict) -> str:
    """Return SAME, DIFFERENT or NOT_ESTABLISHED for every filled role."""

    parties: list[dict] = []
    for role in ROLE_IDS:
        party = _filled_party(assignments_doc, assignment, role)
        if party is not None and not any(party is seen for seen in parties):
            parties.append(party)
    if len(parties) < 2:
        return "SAME"
    states = [same_level(parties[left], parties[right], "same_agent")
              for left in range(len(parties))
              for right in range(left + 1, len(parties))]
    if any(state == "UNKNOWN" for state in states):
        return "NOT_ESTABLISHED"
    if any(state == "DIFFERENT" for state in states):
        return "DIFFERENT"
    return "SAME"


def _dedupe(findings: list[Refusal]) -> list[Refusal]:
    seen: set[tuple[str, str, str]] = set()
    kept: list[Refusal] = []
    for item in findings:
        key = (item.code, item.assignment, item.field)
        if key in seen:
            continue
        seen.add(key)
        kept.append(item)
    return kept


# ---------------------------------------------------------------------------
# role document


def validate_roles(roles_doc: Any) -> list[Refusal]:
    findings: list[Refusal] = []

    def refuse(code: str, field: str, detail: str) -> None:
        findings.append(Refusal(code, "ROLES", field, detail))

    if not isinstance(roles_doc, dict):
        refuse("IND_ROLES_SCHEMA", "-", "the role document is not a JSON object")
        return findings
    if roles_doc.get("schema") != SCHEMA_ROLES:
        refuse("IND_ROLES_SCHEMA", "schema", f"expected {SCHEMA_ROLES!r}")
    if roles_doc.get("kind") != "independence-role-definitions":
        refuse("IND_ROLES_SCHEMA", "kind", "kind is not independence-role-definitions")

    levels = [item.get("id") for item in roles_doc.get("sameness_levels", [])]
    for level in SAMENESS_LEVELS:
        if level not in levels:
            refuse("IND_ROLES_SCHEMA", "sameness_levels", f"level {level!r} is absent")

    roles = roles_doc.get("roles")
    if not isinstance(roles, list):
        refuse("IND_ROLES_SCHEMA", "roles", "roles is not a list")
        return findings
    seen: set[str] = set()
    for role in roles:
        if not isinstance(role, dict) or not _nonempty(role.get("id")):
            refuse("IND_ROLES_SCHEMA", "roles", "a role has no id")
            continue
        role_id = role["id"]
        if role_id in seen:
            refuse("IND_ROLES_SCHEMA", "roles", f"duplicate role {role_id!r}")
        seen.add(role_id)
        for field in ("may_assert", "may_sign"):
            if not isinstance(role.get(field), list):
                refuse("IND_ROLES_SCHEMA", f"roles[{role_id}].{field}", "not a list")
    for role_id in ROLE_IDS:
        if role_id not in seen:
            refuse("IND_ROLES_SCHEMA", "roles", f"required role {role_id!r} is absent")

    classes = roles_doc.get("claim_classes")
    if not isinstance(classes, list):
        refuse("IND_ROLES_SCHEMA", "claim_classes", "claim_classes is not a list")
        return findings
    class_ids: set[str] = set()
    for item in classes:
        if not isinstance(item, dict) or not _nonempty(item.get("id")):
            refuse("IND_ROLES_SCHEMA", "claim_classes", "a claim class has no id")
            continue
        class_ids.add(item["id"])
        pairs = item.get("required_distinct")
        if not isinstance(pairs, list):
            refuse(
                "IND_ROLES_SCHEMA",
                f"claim_classes[{item['id']}].required_distinct",
                "not a list",
            )
            continue
        for pair in pairs:
            roles_pair = pair.get("roles") if isinstance(pair, dict) else None
            levels_pair = pair.get("must_differ_at") if isinstance(pair, dict) else None
            if (
                not isinstance(roles_pair, list)
                or len(roles_pair) != 2
                or any(role not in ROLE_IDS for role in roles_pair)
            ):
                refuse(
                    "IND_ROLES_SCHEMA",
                    f"claim_classes[{item['id']}].required_distinct",
                    "a distinctness pair does not name two known roles",
                )
            if (
                not isinstance(levels_pair, list)
                or not levels_pair
                or any(level not in SAMENESS_LEVELS for level in levels_pair)
            ):
                refuse(
                    "IND_ROLES_SCHEMA",
                    f"claim_classes[{item['id']}].required_distinct",
                    "a distinctness pair names no known sameness level",
                )
    for class_id in CLAIM_CLASSES:
        if class_id not in class_ids:
            refuse("IND_ROLES_SCHEMA", "claim_classes", f"class {class_id!r} is absent")

    rules = [item.get("id") for item in roles_doc.get("rules", [])]
    for rule_id in RULE_IDS:
        if rule_id not in rules:
            refuse("IND_ROLES_SCHEMA", "rules", f"rule {rule_id!r} is absent")
    if roles_doc.get("external_independence_present") is not False:
        refuse(
            "IND_ROLES_SCHEMA",
            "external_independence_present",
            "the record must state whether external independence exists today",
        )
    return findings


# ---------------------------------------------------------------------------
# assignment document


def _class_pairs(roles_doc: dict, class_id: str) -> list[dict]:
    for item in roles_doc.get("claim_classes", []):
        if item.get("id") == class_id:
            return item.get("required_distinct", [])
    return []


def _verdict_rank(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    return VERDICT_RANK.get(value)


def aggregate(assignments_doc: dict) -> dict:
    """Compute the conservative meet of asserted verdicts and retained dissents."""

    assignments = assignments_doc.get("assignments", [])
    retained: dict[str, list[dict]] = {}
    for dissent in assignments_doc.get("dissents", []):
        if isinstance(dissent, dict) and dissent.get("retained") is True:
            retained.setdefault(dissent.get("assignment"), []).append(dissent)

    per_assignment: dict[str, dict] = {}
    cohort_ranks: dict[str, int] = {}
    overall: int | None = None
    for assignment in assignments:
        ident = assignment.get("id")
        if not isinstance(ident, str):
            continue
        base = _verdict_rank(assignment.get("asserted_verdict"))
        entries = [base] if base is not None else []
        for dissent in retained.get(ident, []):
            rank = _verdict_rank(dissent.get("position"))
            if rank is not None:
                entries.append(rank)
        if not entries:
            continue
        worst = min(entries)
        per_assignment[ident] = {"verdict": RANK_VERDICT[worst]}
        class_id = assignment.get("class")
        if isinstance(class_id, str):
            cohort_ranks[class_id] = (
                worst
                if class_id not in cohort_ranks
                else min(cohort_ranks[class_id], worst)
            )
        overall = worst if overall is None else min(overall, worst)

    cohorts = {
        class_id: {"verdict": RANK_VERDICT[rank]}
        for class_id, rank in sorted(cohort_ranks.items())
    }
    included = sorted(
        dissent.get("id")
        for items in retained.values()
        for dissent in items
        if isinstance(dissent.get("id"), str)
    )
    return {
        "per_assignment": per_assignment,
        "cohorts": cohorts,
        "overall": {"verdict": RANK_VERDICT[overall] if overall is not None else None},
        "included_dissents": included,
    }


def _resolve_threshold_parties(
    assignments_doc: dict, assignment: dict, references: Any
) -> list[dict] | None:
    if not isinstance(references, list):
        return None
    parties: list[dict] = []
    for reference in references:
        if not isinstance(reference, str):
            return None
        if reference.startswith("role:"):
            party = _filled_party(assignments_doc, assignment, reference.split(":", 1)[1])
        elif reference.startswith("party:"):
            party = _party(assignments_doc, reference.split(":", 1)[1])
        else:
            party = _party(assignments_doc, reference)
        if party is None:
            return None
        parties.append(party)
    return parties


def _alias_count(parties: list[dict]) -> int:
    """Count equivalence classes under account / key / infrastructure aliasing."""

    parent = list(range(len(parties)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    for left in range(len(parties)):
        for right in range(left + 1, len(parties)):
            for key in ("identity", "account", "signing_key", "infrastructure_operator"):
                a, b = parties[left].get(key), parties[right].get(key)
                if _nonempty(a) and _nonempty(b):
                    same = a.strip().lower() == b.strip().lower()
                    if key == "signing_key":
                        same = a.strip() == b.strip()
                    if same:
                        union(left, right)
    return len({find(index) for index in range(len(parties))})


def independence_findings(assignments_doc: dict, roles_doc: dict) -> list[Refusal]:
    findings: list[Refusal] = []

    def refuse(code: str, assignment: str, field: str, detail: str) -> None:
        findings.append(Refusal(code, assignment, field, detail))

    for assignment in assignments_doc.get("assignments", []):
        if not isinstance(assignment, dict):
            continue
        ident = assignment.get("id") if isinstance(assignment.get("id"), str) else "?"
        class_id = assignment.get("class")
        pairs = _class_pairs(roles_doc, class_id) if isinstance(class_id, str) else []

        # Required distinctness for the claim class.
        for pair in pairs:
            role_a, role_b = pair.get("roles", ["?", "?"])
            levels = pair.get("must_differ_at", [])
            party_a = _filled_party(assignments_doc, assignment, role_a)
            party_b = _filled_party(assignments_doc, assignment, role_b)
            if party_a is None or party_b is None:
                missing = role_a if party_a is None else role_b
                refuse(
                    "IND_REQUIRED_ROLE_ABSENT",
                    ident,
                    f"filled.{missing}",
                    f"{class_id} requires a distinct {missing}; the role is absent",
                )
                continue
            record = sameness(party_a, party_b)
            failed = [level for level in levels if record[level] != "DIFFERENT"]
            if failed:
                code = (
                    "IND_ADJUDICATOR_IS_AUTHOR"
                    if {role_a, role_b} == {"adjudicator", "author"}
                    else "IND_ROLE_NOT_DISTINCT"
                )
                refuse(
                    code,
                    ident,
                    f"filled.{role_a}|filled.{role_b}",
                    f"{role_a} and {role_b} are not distinct at "
                    + ", ".join(failed)
                    + " (recorded "
                    + ", ".join(f"{level}={record[level]}" for level in SAMENESS_LEVELS)
                    + ")",
                )

        # Rule 1: asserted independent review needs a reviewer identity, role and artefact.
        if assignment.get("claimed_independence") is True:
            reviewers = assignment.get("reviewers")
            if not isinstance(reviewers, list) or not reviewers:
                refuse(
                    "IND_REVIEW_UNSUPPORTED",
                    ident,
                    "reviewers",
                    "the assignment asserts independence and names no reviewer record",
                )
            else:
                for index, reviewer in enumerate(reviewers):
                    if not isinstance(reviewer, dict):
                        refuse(
                            "IND_REVIEW_UNSUPPORTED",
                            ident,
                            f"reviewers[{index}]",
                            "reviewer is not a record",
                        )
                        continue
                    for field in ("identity", "role", "artefact"):
                        if not _nonempty(reviewer.get(field)):
                            refuse(
                                "IND_REVIEW_UNSUPPORTED",
                                ident,
                                f"reviewers[{index}].{field}",
                                f"the reviewer record has no {field}",
                            )

            # Rule 3: two reviewers may not share an identity or signing key.
            if isinstance(reviewers, list):
                for left in range(len(reviewers)):
                    for right in range(left + 1, len(reviewers)):
                        a, b = reviewers[left], reviewers[right]
                        if not isinstance(a, dict) or not isinstance(b, dict):
                            continue
                        for key in ("identity", "account"):
                            if (
                                _nonempty(a.get(key))
                                and _nonempty(b.get(key))
                                and a[key].strip().lower() == b[key].strip().lower()
                            ):
                                refuse(
                                    "IND_REVIEWERS_ALIASED",
                                    ident,
                                    f"reviewers[{left}].{key}|reviewers[{right}].{key}",
                                    f"two reviewers share the same {key}",
                                )
                        key_a = _nonempty(a.get("signing_key"))
                        key_b = _nonempty(b.get("signing_key"))
                        if key_a and key_b and a["signing_key"].strip() == b["signing_key"].strip():
                            refuse(
                                "IND_REVIEWERS_ALIASED",
                                ident,
                                f"reviewers[{left}].signing_key|reviewers[{right}].signing_key",
                                "two reviewers share the same signing key",
                            )

            # Rule 4: a distinct-party threshold may not be met by aliases.
            threshold = assignment.get("threshold")
            if isinstance(threshold, dict):
                required = threshold.get("required_distinct_parties")
                if isinstance(required, int) and required > 1:
                    parties = _resolve_threshold_parties(
                        assignments_doc, assignment, threshold.get("satisfied_by")
                    )
                    if parties is None:
                        refuse(
                            "IND_THRESHOLD_UNKNOWN",
                            ident,
                            "threshold.satisfied_by",
                            "a threshold reference does not resolve to a known party",
                        )
                    elif _alias_count(parties) < required:
                        refuse(
                            "IND_THRESHOLD_ALIASED",
                            ident,
                            "threshold.satisfied_by",
                            f"{required} distinct parties required; the references "
                            f"collapse to {_alias_count(parties)} after account, key "
                            "and infrastructure aliasing",
                        )

        # Rule 5: independent reproduction must rebuild from the frozen package.
        reproduction = assignment.get("reproduction")
        if isinstance(reproduction, dict) and reproduction.get("claimed_independent") is True:
            if reproduction.get("used_project_working_environment") is True:
                refuse(
                    "IND_REPRODUCER_CONTAMINATED",
                    ident,
                    "reproduction.used_project_working_environment",
                    "the reproduction ran in this repository's working environment",
                )
            if reproduction.get("used_project_produced_artefact") is True:
                refuse(
                    "IND_REPRODUCER_CONTAMINATED",
                    ident,
                    "reproduction.used_project_produced_artefact",
                    "the reproduction consumed an artefact this project produced",
                )
            if reproduction.get("rebuilt_from_frozen_package") is not True:
                refuse(
                    "IND_REPRODUCER_CONTAMINATED",
                    ident,
                    "reproduction.rebuilt_from_frozen_package",
                    "the reproduction does not state a rebuild from the frozen package",
                )

    return _dedupe(findings)


def _structural_findings(assignments_doc: Any, roles_doc: dict) -> list[Refusal]:
    findings: list[Refusal] = []

    def refuse(code: str, assignment: str, field: str, detail: str) -> None:
        findings.append(Refusal(code, assignment, field, detail))

    if not isinstance(assignments_doc, dict):
        refuse("IND_ASSIGNMENTS_SCHEMA", "ASSIGNMENTS", "-", "not a JSON object")
        return findings
    if assignments_doc.get("schema") != SCHEMA_ASSIGNMENTS:
        refuse(
            "IND_ASSIGNMENTS_SCHEMA",
            "ASSIGNMENTS",
            "schema",
            f"expected {SCHEMA_ASSIGNMENTS!r}",
        )
    if assignments_doc.get("kind") != "independence-role-assignments":
        refuse(
            "IND_ASSIGNMENTS_SCHEMA",
            "ASSIGNMENTS",
            "kind",
            "kind is not independence-role-assignments",
        )

    parties = assignments_doc.get("parties")
    if not isinstance(parties, dict) or not parties:
        refuse("IND_ASSIGNMENTS_SCHEMA", "ASSIGNMENTS", "parties", "no parties recorded")
        parties = {}

    assignments = assignments_doc.get("assignments")
    if not isinstance(assignments, list) or not assignments:
        refuse(
            "IND_ASSIGNMENTS_SCHEMA", "ASSIGNMENTS", "assignments", "no assignments recorded"
        )
        return findings

    known_classes = {item.get("id") for item in roles_doc.get("claim_classes", [])}
    seen: set[str] = set()
    for index, assignment in enumerate(assignments):
        if not isinstance(assignment, dict):
            refuse(
                "IND_ASSIGNMENT_SHAPE",
                f"assignments[{index}]",
                "-",
                "assignment is not a record",
            )
            continue
        ident = assignment.get("id")
        if not _nonempty(ident):
            refuse("IND_ASSIGNMENT_SHAPE", f"assignments[{index}]", "id", "no id")
            continue
        if ident in seen:
            refuse("IND_ASSIGNMENT_DUPLICATE", ident, "id", "duplicate assignment id")
        seen.add(ident)
        if not _nonempty(assignment.get("artefact")):
            refuse("IND_ASSIGNMENT_SHAPE", ident, "artefact", "no artefact path")
        if assignment.get("class") not in known_classes:
            refuse(
                "IND_CLAIM_CLASS_UNKNOWN",
                ident,
                "class",
                f"unknown claim class {assignment.get('class')!r}",
            )
        if _verdict_rank(assignment.get("asserted_verdict")) is None:
            refuse(
                "IND_ASSIGNMENT_SHAPE",
                ident,
                "asserted_verdict",
                f"unknown verdict {assignment.get('asserted_verdict')!r}",
            )
        filled = assignment.get("filled")
        if not isinstance(filled, dict):
            refuse("IND_ASSIGNMENT_SHAPE", ident, "filled", "no filled role map")
            filled = {}
        for role, entry in filled.items():
            if role not in ROLE_IDS:
                refuse("IND_ROLE_UNKNOWN", ident, f"filled.{role}", f"unknown role {role!r}")
                continue
            if not isinstance(entry, dict):
                refuse("IND_ASSIGNMENT_SHAPE", ident, f"filled.{role}", "not a record")
                continue
            if entry.get("status", "FILLED") not in ("FILLED", "ABSENT"):
                refuse(
                    "IND_ASSIGNMENT_SHAPE",
                    ident,
                    f"filled.{role}.status",
                    f"unknown status {entry.get('status')!r}",
                )
            party_id = entry.get("party")
            if entry.get("status", "FILLED") != "ABSENT" and party_id not in parties:
                refuse(
                    "IND_PARTY_UNKNOWN",
                    ident,
                    f"filled.{role}.party",
                    f"party {party_id!r} is not declared",
                )

        # Recorded sameness must equal computed sameness.
        recorded_overall = assignment.get("same_party")
        if recorded_overall is not None:
            computed_overall = assignment_same_party(assignments_doc, assignment)
            if recorded_overall != computed_overall:
                refuse(
                    "IND_SAMENESS_MISMATCH",
                    ident,
                    "same_party",
                    f"recorded {recorded_overall!r} but computed {computed_overall!r}",
                )
        recorded = assignment.get("sameness")
        if isinstance(recorded, dict):
            for role_a, role_b in (
                ("author", "adjudicator"),
                ("author", "evidence_producer"),
                ("author", "independent_reproducer"),
                ("author", "release_authority"),
                ("adjudicator", "independent_reproducer"),
                ("adjudicator", "release_authority"),
            ):
                key = f"{role_a}|{role_b}"
                if key not in recorded:
                    continue
                party_a = _filled_party(assignments_doc, assignment, role_a)
                party_b = _filled_party(assignments_doc, assignment, role_b)
                if party_a is None or party_b is None:
                    # A missing role is reported by the independence rules; there is
                    # no pair to compare here.
                    continue
                computed = sameness(party_a, party_b)
                if computed != recorded[key]:
                    refuse(
                        "IND_SAMENESS_MISMATCH",
                        ident,
                        f"sameness.{key}",
                        f"recorded {recorded[key]} but computed {computed}",
                    )

    # Dissent records.
    dissents = assignments_doc.get("dissents")
    if not isinstance(dissents, list):
        refuse("IND_ASSIGNMENTS_SCHEMA", "ASSIGNMENTS", "dissents", "not a list")
        dissents = []
    assignment_by_id = {a.get("id"): a for a in assignments if isinstance(a, dict)}
    dissent_ids: set[str] = set()
    for index, dissent in enumerate(dissents):
        if not isinstance(dissent, dict) or not _nonempty(dissent.get("id")):
            refuse("IND_ASSIGNMENT_SHAPE", f"dissents[{index}]", "id", "no dissent id")
            continue
        dissent_id = dissent["id"]
        if dissent_id in dissent_ids:
            refuse("IND_ASSIGNMENT_DUPLICATE", dissent_id, "id", "duplicate dissent id")
        dissent_ids.add(dissent_id)
        target = dissent.get("assignment")
        if target not in assignment_by_id:
            refuse(
                "IND_DISSENT_UNATTACHED",
                dissent_id,
                "assignment",
                f"dissent is not attached to an existing assignment ({target!r})",
            )
        if dissent.get("retained") is not True:
            refuse(
                "IND_DISSENT_UNRETAINED",
                dissent_id,
                "retained",
                "a recorded dissent is not marked retained",
            )
        if _verdict_rank(dissent.get("position")) is None:
            refuse(
                "IND_ASSIGNMENT_SHAPE",
                dissent_id,
                "position",
                f"unknown dissent position {dissent.get('position')!r}",
            )
        if not _nonempty(dissent.get("party")):
            refuse("IND_ASSIGNMENT_SHAPE", dissent_id, "party", "no dissenting party")
        if not _nonempty(dissent.get("dissented_from")):
            refuse(
                "IND_ASSIGNMENT_SHAPE",
                dissent_id,
                "dissented_from",
                "no dissented-from party",
            )

        for request_index, request in enumerate(dissent.get("removal_requests", []) or []):
            if not isinstance(request, dict):
                refuse(
                    "IND_ASSIGNMENT_SHAPE",
                    dissent_id,
                    f"removal_requests[{request_index}]",
                    "not a record",
                )
                continue
            if request.get("accepted") is not True:
                continue
            requester = request.get("requested_by")
            if requester != dissent.get("party"):
                refuse(
                    "IND_DISSENT_REMOVED_BY_TARGET",
                    dissent_id,
                    f"removal_requests[{request_index}].requested_by",
                    f"removal was accepted for {requester!r}; a dissent may only be "
                    "withdrawn by the party that recorded it",
                )

    # The recorded aggregate must be the computed conservative meet.
    recorded_aggregate = assignments_doc.get("aggregate")
    computed = aggregate(assignments_doc)
    if not isinstance(recorded_aggregate, dict):
        refuse("IND_ASSIGNMENTS_SCHEMA", "ASSIGNMENTS", "aggregate", "no aggregate record")
    else:
        included = recorded_aggregate.get("included_dissents")
        if not isinstance(included, list):
            refuse(
                "IND_ASSIGNMENTS_SCHEMA",
                "ASSIGNMENTS",
                "aggregate.included_dissents",
                "no dissent inclusion list",
            )
            included = []
        for dissent in dissents:
            if not isinstance(dissent, dict) or dissent.get("retained") is not True:
                continue
            if dissent.get("id") not in included:
                refuse(
                    "IND_DISSENT_DROPPED",
                    dissent.get("id", "?"),
                    "aggregate.included_dissents",
                    "a retained dissent is absent from the aggregate",
                )
        recorded_overall = (
            recorded_aggregate.get("overall", {}).get("verdict")
            if isinstance(recorded_aggregate.get("overall"), dict)
            else None
        )
        if recorded_overall != computed["overall"]["verdict"]:
            refuse(
                "IND_AGGREGATE_MISMATCH",
                "ASSIGNMENTS",
                "aggregate.overall.verdict",
                f"recorded {recorded_overall!r} but the conservative meet is "
                f"{computed['overall']['verdict']!r}",
            )
        recorded_cohorts = recorded_aggregate.get("cohorts")
        if isinstance(recorded_cohorts, dict):
            for class_id, cohort in computed["cohorts"].items():
                recorded = recorded_cohorts.get(class_id)
                recorded_verdict = (
                    recorded.get("verdict") if isinstance(recorded, dict) else None
                )
                if recorded_verdict != cohort["verdict"]:
                    refuse(
                        "IND_AGGREGATE_MISMATCH",
                        "ASSIGNMENTS",
                        f"aggregate.cohorts.{class_id}.verdict",
                        f"recorded {recorded_verdict!r} but the conservative meet is "
                        f"{cohort['verdict']!r}",
                    )
        recorded_per = recorded_aggregate.get("per_assignment")
        if isinstance(recorded_per, dict):
            for ident, entry in computed["per_assignment"].items():
                target = assignment_by_id.get(ident, {})
                has_dissent = any(
                    isinstance(d, dict)
                    and d.get("assignment") == ident
                    and d.get("retained") is True
                    for d in dissents
                )
                if not has_dissent:
                    continue
                recorded = recorded_per.get(ident)
                recorded_verdict = (
                    recorded.get("verdict") if isinstance(recorded, dict) else None
                )
                if recorded_verdict != entry["verdict"]:
                    refuse(
                        "IND_AGGREGATE_MISMATCH",
                        ident,
                        f"aggregate.per_assignment.{ident}.verdict",
                        f"recorded {recorded_verdict!r} but the dissent-inclusive "
                        f"meet is {entry['verdict']!r}",
                    )
                ranks = [
                    _verdict_rank(d.get("position"))
                    for d in dissents
                    if isinstance(d, dict)
                    and d.get("assignment") == ident
                    and d.get("retained") is True
                ]
                base = _verdict_rank(target.get("asserted_verdict"))
                floor = min([r for r in ranks if r is not None] or [base])
                if recorded_verdict is not None and (
                    _verdict_rank(recorded_verdict) or 0
                ) > floor:
                    refuse(
                        "IND_DISSENT_OVERRIDDEN",
                        ident,
                        f"aggregate.per_assignment.{ident}.verdict",
                        f"the aggregate {recorded_verdict!r} is better than a retained "
                        f"dissent at rank {floor}",
                    )

    return _dedupe(findings)


def validate(assignments_doc: Any, roles_doc: dict) -> list[Refusal]:
    """Structural admissibility plus the six independence refusal rules."""

    findings = _structural_findings(assignments_doc, roles_doc)
    if isinstance(assignments_doc, dict):
        findings.extend(independence_findings(assignments_doc, roles_doc))
    return _dedupe(findings)


def validate_structure(assignments_doc: Any, roles_doc: dict) -> list[Refusal]:
    """Structural admissibility only.  An honest record of absent independence passes."""

    return _dedupe(_structural_findings(assignments_doc, roles_doc))


# ---------------------------------------------------------------------------
# summary


def summarize(assignments_doc: dict) -> dict:
    assignments = [
        item for item in assignments_doc.get("assignments", []) if isinstance(item, dict)
    ]
    same_party_adjudicator = 0
    not_established_adjudicator = 0
    for assignment in assignments:
        author = _filled_party(assignments_doc, assignment, "author")
        adjudicator = _filled_party(assignments_doc, assignment, "adjudicator")
        if author is None or adjudicator is None:
            continue
        state = same_level(author, adjudicator, "same_agent")
        if state == "SAME":
            same_party_adjudicator += 1
        elif state == "UNKNOWN":
            not_established_adjudicator += 1

    parties = assignments_doc.get("parties", {})
    declared = [
        party_id
        for party_id, party in parties.items()
        if isinstance(party, dict) and party.get("declared") is True
    ]
    asserting = [
        item.get("id")
        for item in assignments
        if item.get("claimed_independence") is True
    ]
    return {
        "assignments": len(assignments),
        "same_party_adjudicator": same_party_adjudicator,
        "adjudicator_distinctness_not_established": not_established_adjudicator,
        "declared_parties": len(declared),
        "external_parties": sum(
            1
            for party_id, party in parties.items()
            if isinstance(party, dict) and party.get("trust_domain") == "external"
        ),
        "independence_asserted_by": sorted(asserting),
        "retained_dissents": sum(
            1
            for dissent in assignments_doc.get("dissents", [])
            if isinstance(dissent, dict) and dissent.get("retained") is True
        ),
    }


# ---------------------------------------------------------------------------
# seed

RECEIPTS = (
    ("RCP-ETP0", "evidence/etp0/RECEIPT.md", "PARTIAL", "NONE",
     "Baseline inventory; status PARTIAL. The receipt records no separate adjudicator."),
    ("RCP-ETP2", "evidence/etp2/RECEIPT.md", "ESTABLISHED", "EXECUTION",
     "Two independently initialised builds in one venue are independent executions, not distinct parties."),
    ("RCP-ETP5", "evidence/etp5/RECEIPT.md", "PARTIAL", "NONE",
     "The receipt states that independence is not claimed."),
    ("RCP-ETP6", "evidence/etp6/RECEIPT.md", "PARTIAL", "NONE",
     "The receipt records EXTERNAL_REVIEW_PENDING and states that the clean-room replay is a self-reproduction."),
    ("RCP-ETP7", "evidence/etp7/RECEIPT.md", "PARTIAL", "NONE",
     "The release gate records NOT_RUN items and no external release authority."),
    ("RCP-ETP-T1", "evidence/etp-t1/RECEIPT.md", "ESTABLISHED", "NONE",
     "The traceability graph is produced and adjudicated by the same party."),
    ("RCP-ETP-T2", "evidence/etp-t2/RECEIPT.md", "ESTABLISHED", "NONE",
     "The hazard register is produced and adjudicated by the same party."),
    ("RCP-ETP-T3", "evidence/etp-t3/RECEIPT.md", "ESTABLISHED", "NONE",
     "The refinement architecture is produced and adjudicated by the same party."),
    ("RCP-ETP-T4", "evidence/etp-t4/RECEIPT.md", "ESTABLISHED", "NONE",
     "The unsafe-site classification is produced and adjudicated by the same party."),
    ("RCP-ETP-T5", "evidence/etp-t5/RECEIPT.md", "PARTIAL", "REFERENCE_DIVERSITY",
     "The independent reference is an independent model written by the same party, not a distinct reviewer."),
    ("RCP-ETP-T6", "evidence/etp-t6/RECEIPT.md", "ESTABLISHED", "NONE",
     "The binary-assurance matrix is produced and adjudicated by the same party."),
    ("RCP-ETP-T7", "evidence/etp-t7/RECEIPT.md", "ESTABLISHED", "NONE",
     "The side-channel receipt is produced and adjudicated by the same party."),
    ("RCP-HAZ-16", "evidence/haz-16/RECEIPT.md", "PARTIAL", "NONE",
     "The panic-atomicity barrier remains CLAIMED_NO_EVIDENCE; no independent review."),
)


def _base_roles_filled() -> dict:
    return {
        "author": {"status": "FILLED", "party": "P-CAMPAIGN", "identity": None, "declared": False},
        "proof_producer": {"status": "FILLED", "party": "P-CAMPAIGN", "identity": None, "declared": False},
        "instrument_author": {"status": "FILLED", "party": "P-CAMPAIGN", "identity": None, "declared": False},
        "evidence_producer": {"status": "FILLED", "party": "P-CAMPAIGN", "identity": None, "declared": False},
        "adjudicator": {"status": "FILLED", "party": "P-CAMPAIGN", "identity": None, "declared": False},
        "independent_reproducer": {"status": "ABSENT", "party": None, "identity": None, "declared": False},
        "release_authority": {"status": "ABSENT", "party": None, "identity": None, "declared": False},
        "revocation_authority": {"status": "ABSENT", "party": None, "identity": None, "declared": False},
    }


def _same(parties_doc: dict, assignment: dict, left: str, right: str) -> dict:
    a = _filled_party(parties_doc, assignment, left)
    b = _filled_party(parties_doc, assignment, right)
    return sameness(a, b) if a is not None and b is not None else {}


def seed(
    repo_root: Path,
    generated_utc: str,
    graduation_path: Path | None = None,
    claims_path: Path | None = None,
) -> dict:
    claims_doc = load_json_strict(
        claims_path or repo_root / "evidence" / "etp" / "claims.json"
    )
    b85c = load_json_strict(repo_root / "evidence" / "b85c-adjudication.json")
    graduation = load_json_strict(
        graduation_path
        or repo_root / "evidence" / "SAFE-COMPATIBLE-openssh-b85c.json"
    )

    parties = {
        "P-CAMPAIGN": {
            "declared": False,
            "identity": None,
            "account": None,
            "organisation": None,
            "infrastructure": "repository working environment and openssl-rs-court-tools:1",
            "infrastructure_operator": "repository working environment",
            "signing_key": None,
            "trust_domain": "project",
            "note": "No identity string, account, organisation or signing key is declared in any artefact. The record does not invent one.",
        },
        "P-PRINCIPAL": {
            "declared": False,
            "identity": None,
            "account": None,
            "organisation": None,
            "infrastructure": None,
            "infrastructure_operator": None,
            "signing_key": None,
            "trust_domain": "undeclared",
            "note": "The graduation record names a 'decision-maker (campaign principal)' and states no identity, organisation, infrastructure or key. Distinctness from P-CAMPAIGN is not established, so it is not claimed.",
        },
    }

    context = {"parties": parties}

    assignments: list[dict] = []
    for claim in claims_doc.get("claims", []):
        verdict = claim.get("verdict", {})
        state = verdict.get("state") if isinstance(verdict, dict) else None
        filled = _base_roles_filled()
        for role in ("proof_producer", "instrument_author", "release_authority", "revocation_authority"):
            filled[role] = {"status": "ABSENT", "party": None, "identity": None, "declared": False}
        assignment = {
            "id": f"A-{claim.get('id')}",
            "artefact": f"evidence/etp/claims.json#{claim.get('id')}",
            "class": "ORDINARY_CLAIM",
            "asserted_verdict": state,
            "claimed_independence": False,
            "independence_kind": "NONE",
            "independence_required": [],
            "filled": filled,
            "same_party": "SAME",
            "sameness": {
                "author|adjudicator": _same(context, {"filled": filled}, "author", "adjudicator"),
            },
            "reviewers": [],
            "reproduction": {"claimed_independent": False},
            "finding": "The claim and its verdict are recorded in one document by the same undeclared producing party; no separate adjudicator identity exists.",
        }
        assignments.append(assignment)

    for suffix, path, verdict, kind, note in RECEIPTS:
        filled = _base_roles_filled()
        assignment = {
            "id": f"A-{suffix}",
            "artefact": path,
            "class": "ORDINARY_CLAIM",
            "asserted_verdict": verdict,
            "claimed_independence": False,
            "independence_kind": kind,
            "independence_required": [],
            "filled": filled,
            "same_party": "SAME",
            "sameness": {
                "author|adjudicator": _same(context, {"filled": filled}, "author", "adjudicator"),
            },
            "reviewers": [],
            "reproduction": {"claimed_independent": False},
            "finding": note,
        }
        assignments.append(assignment)

    adjudication_filled = _base_roles_filled()
    adjudication_filled["reviewer"] = {
        "status": "FILLED",
        "party": "P-CAMPAIGN",
        "identity": None,
        "declared": False,
    }
    adjudication_filled["independent_reproducer"] = {
        "status": "FILLED",
        "party": "P-CAMPAIGN",
        "identity": None,
        "declared": False,
    }
    adjudication = {
        "id": "A-ADJ-B85C",
        "artefact": "evidence/b85c-adjudication.json",
        "class": "INDEPENDENT_ADJUDICATION",
        "asserted_verdict": "NOT_ESTABLISHED",
        "claimed_independence": True,
        "independence_kind": "REVIEW_AND_REPRODUCTION",
        "independence_required": ["adjudicator", "independent_reproducer"],
        "filled": adjudication_filled,
        "same_party": "SAME",
        "sameness": {},
        "reviewers": [
            {
                "id": "RV-B85C-1",
                "role": "independent adversarial adjudicator",
                "identity": None,
                "artefact": "evidence/b85c-adjudication.json",
                "party": "P-CAMPAIGN",
                "signing_key": None,
            }
        ],
        "threshold": {
            "required_distinct_parties": 2,
            "satisfied_by": ["role:author", "role:adjudicator"],
        },
        "reproduction": {
            "claimed_independent": True,
            "rebuilt_from_frozen_package": False,
            "used_project_working_environment": True,
            "used_project_produced_artefact": True,
            "procedure": "re-executed the acceptance predicate by importing forensics/tools/consumer_closure.py and re-hashed stored artefacts",
            "trust_domain": "same repository working environment",
        },
        "finding": "The adjudication asserts independence, names no reviewer identity, organisation or key, ran in this repository's working environment against stored project artefacts, and is filled by the same undeclared party as the source it judges.",
    }
    adjudication["sameness"] = {
        "author|adjudicator": _same(context, adjudication, "author", "adjudicator"),
        "author|evidence_producer": _same(context, adjudication, "author", "evidence_producer"),
        "author|independent_reproducer": _same(context, adjudication, "author", "independent_reproducer"),
        "adjudicator|independent_reproducer": _same(context, adjudication, "adjudicator", "independent_reproducer"),
    }
    assignments.append(adjudication)

    release_filled = _base_roles_filled()
    release_filled["release_authority"] = {
        "status": "FILLED",
        "party": "P-PRINCIPAL",
        "identity": None,
        "declared": False,
    }
    release_filled["revocation_authority"] = {
        "status": "FILLED",
        "party": "P-CAMPAIGN",
        "identity": None,
        "declared": False,
    }
    asserted = (
        graduation.get("verdict", {}).get("value")
        or graduation.get("classification", {}).get("state")
        or "SAFE_COMPATIBLE"
    )
    risk_accepted = asserted == "RISK_ACCEPTED"
    release = {
        "id": "A-REL-OPENSSH-B85C",
        "artefact": "evidence/SAFE-COMPATIBLE-openssh-b85c.json",
        "class": "ORDINARY_CLAIM" if risk_accepted else "SAFE_COMPATIBLE_RELEASE",
        "asserted_verdict": asserted,
        "claimed_independence": False,
        "independence_kind": "NONE" if risk_accepted else "RELEASE",
        "independence_required": [] if risk_accepted else [
            "adjudicator", "independent_reproducer", "release_authority"
        ],
        "filled": release_filled,
        "same_party": "NOT_ESTABLISHED",
        "sameness": {},
        "reviewers": [],
        "reproduction": {"claimed_independent": False},
        "finding": (
            "ETP-T15 reclassification: the record is a principal risk acceptance "
            "(RISK_ACCEPTED), not a SAFE_COMPATIBLE graduation. It asserts no "
            "independence and requires no distinct party; the absence of an "
            "independent acceptance is recorded, not repaired."
            if risk_accepted else
            "The record itself states that the graduation is a principal-decided "
            "risk acceptance, not an independent acceptance. The release authority "
            "declares no identity, organisation, infrastructure or key."
        ),
    }
    release["sameness"] = {
        "author|adjudicator": _same(context, release, "author", "adjudicator"),
        "author|evidence_producer": _same(context, release, "author", "evidence_producer"),
        "author|release_authority": _same(context, release, "author", "release_authority"),
        "adjudicator|release_authority": _same(context, release, "adjudicator", "release_authority"),
    }
    assignments.append(release)

    dissents = [
        {
            "id": "D-OPENSSH-B85C",
            "assignment": "A-REL-OPENSSH-B85C",
            "artefact": "evidence/b85c-adjudication.json",
            "party": "P-CAMPAIGN",
            "role": "adjudicator",
            "dissented_from": "decision-maker (campaign principal)",
            "position": "NOT_ESTABLISHED",
            "recorded_utc": "2026-11-17T12:54:00Z",
            "retained": True,
            "statement": "The b85c adjudication returned NOT ESTABLISHED against the OpenSSH SAFE_COMPATIBLE graduation; the graduation record preserves that dissent unchanged and states that it is not withdrawn or reinterpreted.",
            "removal_requests": [],
        }
    ]

    document: dict = {
        "schema": SCHEMA_ASSIGNMENTS,
        "kind": "independence-role-assignments",
        "generated_utc": generated_utc,
        "source_identity": {
            "commit": "bf8c6437128b2d3ab0bf76d76aa5b529532de84f",
            "branch": "staging",
            "worktree_clean_tracked_files": True,
        },
        "roles_document": "evidence/etp-t8/ROLES.json",
        "parties": parties,
        "assignments": assignments,
        "dissents": dissents,
        "aggregate": {},
    }
    document["aggregate"] = aggregate(document)
    document["summary"] = summarize(document)
    document["expected_refusal_codes"] = sorted(
        {item.code for item in independence_findings(document, _seed_roles())}
    )
    return document


def _seed_roles() -> dict:
    return {
        "claim_classes": [
            {"id": class_id, **value} for class_id, value in CLAIM_CLASSES.items()
        ]
    }


# ---------------------------------------------------------------------------
# command line


def _roles_document() -> dict:
    return load_json_strict(ROLES_PATH)


def _assignments_document() -> dict:
    return load_json_strict(ASSIGNMENTS_PATH)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("validate", "check", "seed", "report", "aggregate")
    )
    parser.add_argument("--roles", default=str(ROLES_PATH))
    parser.add_argument("--assignments", default=str(ASSIGNMENTS_PATH))
    parser.add_argument("--repo", default=str(REPO_ROOT))
    parser.add_argument("--generated-utc", default="2026-11-23T00:00:00Z")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        roles_doc = load_json_strict(Path(args.roles))
        roles_findings = validate_roles(roles_doc)
        if roles_findings:
            for item in roles_findings:
                print(item.line())
            return 2
        if args.command == "seed":
            document = seed(Path(args.repo), args.generated_utc)
            Path(args.assignments).write_text(dump_json(document), encoding="utf-8")
            print(f"SEEDED {args.assignments}")
            return 0

        assignments_doc = load_json_strict(Path(args.assignments))
        if args.command == "validate":
            findings = validate_structure(assignments_doc, roles_doc)
            for item in findings:
                print(item.line())
            print(
                {
                    "status": "PASS" if not findings else "REFUSED",
                    "assignments": len(assignments_doc.get("assignments", [])),
                    "structural_refusals": len(findings),
                }
            )
            return 0 if not findings else 1
        if args.command == "check":
            findings = validate(assignments_doc, roles_doc)
            for item in findings:
                print(item.line())
            summary = summarize(assignments_doc)
            print(
                {
                    "status": "PASS" if not findings else "REFUSED",
                    "assignments": summary["assignments"],
                    "refusals": len(findings),
                    "same_party_adjudicator": summary["same_party_adjudicator"],
                    "external_parties": summary["external_parties"],
                }
            )
            return 0 if not findings else 1
        if args.command == "report":
            payload = {
                "summary": summarize(assignments_doc),
                "aggregate": aggregate(assignments_doc),
                "refusals": [item.__dict__ for item in validate(assignments_doc, roles_doc)],
            }
            print(dump_json(payload) if args.json else payload)
            return 0
        if args.command == "aggregate":
            print(dump_json(aggregate(assignments_doc)))
            return 0
    except DocumentError as exc:
        print(f"REFUSED {exc.code}: {exc.detail}")
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
