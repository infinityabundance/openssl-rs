#!/usr/bin/env python3
"""authorisation.py -- a signature authorises nothing until a role does.

What this tool decides
----------------------
A signature establishes that a key signed a statement.  It does not establish
that the signer holds the role the action requires, that the role covers the
action's scope, that the role was valid when the action was taken, or that the
required separation of duties holds.  This tool decides *authorisation*: whether
the signatures offered for one action satisfy that action's role policy.

The rule
--------
An action is ``AUTHORISED`` only when every one of the following holds, in this
order:

  1. the signature is verified (an unverified signature is refused before its
     role is considered -- ``RA_REFUSED_SIGNATURE_UNVERIFIED``);
  2. the signer's identity token is established by a tracked record
     (``RA_REFUSED_IDENTITY_UNRECORDED``);
  3. the role named at signing is one of the seven roles
     (``RA_REFUSED_ROLE_UNKNOWN``) and is assigned to that identity
     (``RA_REFUSED_ROLE_NOT_ASSIGNED``), valid at the action time
     (``RA_REFUSED_EXPIRED``, ``RA_REFUSED_REVOKED``);
  4. the signature and the assignment both cover the action's scope
     (``RA_REFUSED_SCOPE_EXCEEDED``);
  5. the role is one the action requires (``RA_REFUSED_WRONG_ROLE``);
  6. the producer of the evidence is not the signer whose authorisation is
     required (``RA_REFUSED_SELF_AUTHORISATION``), and no identity occupies both
     sides of a required separation (``RA_REFUSED_SEPARATION``);
  7. the valid signatures are distinct signers and meet the action's minimum
     (``RA_REFUSED_DUPLICATE_SIGNER``, ``RA_REFUSED_INSUFFICIENT_SIGNERS``).

An unknown action is ``RA_REFUSED_ACTION_UNKNOWN``.  An action whose policy is
declared ``NOT_RUN`` returns the ``NOT_RUN`` outcome; ``NOT_RUN`` is not a pass.
A ``None`` signature list means the action was not attempted and is also
``NOT_RUN``; an empty list means it was attempted with no signatures and is
refused.

Distinct signers are counted by *party*, not by identity token: two aliases of
one undeclared party are one signer.  This is conservative in the direction the
project needs -- it can never manufacture a second signer from a second label.

The seven roles
---------------
``maintainer``, ``producer`` (source/build/analysis/proof producer),
``instrument_reviewer``, ``adjudicator``, ``external_reproducer``,
``release_authority`` and ``revocation_authority``.

The producer of the evidence being adjudicated, the author of an instrument
being reviewed, and the sole author of a release are all the ``producer``
identity in that action's context.  That keeps the role vocabulary to the seven
named roles while making each separation constraint nameable.

What this tool does not establish
---------------------------------
It does not verify a cryptographic signature (the caller supplies ``verified``
and the verification record); it does not decide that a role *should* exist; it
does not establish that an identity is a distinct organisation; and it does not
make a real action authorised.  A signature by the right role is necessary for
authorisation, never sufficient for truth, independence or safety.

Usage
-----
    python3 forensics/tools/authorisation.py roles IDENTITY [--at DATE]
    python3 forensics/tools/authorisation.py authorise ACTION [SIGNATURES] [--json]
    python3 forensics/tools/authorisation.py explain ACTION [--json]

Exit status: 0 when the action is ``AUTHORISED`` (or a ``roles``/``explain``
query finds its subject); 1 when it is refused, not run, or absent; 2 for a
usage or unreadable-input error.  The ``authorise`` command always prints the
outcome and every code.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLES_RECORD = REPO_ROOT / "evidence/a14/ROLES.json"
AUTHORISATION_RECORD = REPO_ROOT / "evidence/a14/AUTHORISATION.json"

SCHEMA = "openssl-rs/a14/authorisation-decision/1"

# The seven roles the queue names.  A role outside this tuple is unknown, not
# merely unassigned: inventing a role label must never authorise an action.
ROLES: tuple[str, ...] = (
    "maintainer",
    "producer",
    "instrument_reviewer",
    "adjudicator",
    "external_reproducer",
    "release_authority",
    "revocation_authority",
)

# The action policy.  ``separation`` pairs must be filled by different parties;
# ``selfAuthorisation`` refuses the producer of the evidence as the signer whose
# authorisation is required.  ``minDistinctSigners`` counts parties, not tokens.
ACTIONS: dict[str, dict[str, Any]] = {
    "release": {
        "description": "a release or graduated release decision",
        "requiredRoles": ["release_authority", "adjudicator"],
        "minDistinctSigners": 2,
        "separation": [
            {
                "roles": ["release_authority", "producer"],
                "why": "the release authority must not be the sole author of the release",
            },
            {
                "roles": ["release_authority", "adjudicator"],
                "why": "a release decision and its adjudication are two signatures, not one",
            },
        ],
        "selfAuthorisation": False,
    },
    "claim-promotion": {
        "description": "promotion of a claim's verdict over its evidence",
        "requiredRoles": ["adjudicator"],
        "minDistinctSigners": 1,
        "separation": [
            {
                "roles": ["adjudicator", "producer"],
                "why": "the adjudicator must not be the producer of the evidence being adjudicated",
            },
        ],
        "selfAuthorisation": True,
    },
    "consumer-graduation": {
        "description": "graduation of a consumer family (SAFE_COMPATIBLE)",
        "requiredRoles": ["adjudicator", "external_reproducer"],
        "minDistinctSigners": 2,
        "separation": [
            {
                "roles": ["adjudicator", "producer"],
                "why": "the adjudicator must not be the producer of the evidence being adjudicated",
            },
            {
                "roles": ["external_reproducer", "producer"],
                "why": "an external reproduction must not consume the producing party's own run",
            },
            {
                "roles": ["adjudicator", "external_reproducer"],
                "why": "the adjudicator and the external reproducer are two signatures, not one",
            },
        ],
        "selfAuthorisation": True,
    },
    "instrument-qualification": {
        "description": "qualification or re-qualification of an instrument",
        "requiredRoles": ["instrument_reviewer"],
        "minDistinctSigners": 1,
        "separation": [
            {
                "roles": ["instrument_reviewer", "producer"],
                "why": "the instrument reviewer must not be the instrument's author",
            },
        ],
        "selfAuthorisation": False,
    },
    "evidence-correction": {
        "description": "correction of a recorded evidence artefact",
        "requiredRoles": ["maintainer"],
        "minDistinctSigners": 1,
        "separation": [
            {
                "roles": ["maintainer", "producer"],
                "why": "a correction must not be made solely by the producer whose evidence is corrected",
            },
        ],
        "selfAuthorisation": True,
    },
    "revocation": {
        "description": "revocation, withdrawal or supersession of a claim",
        "requiredRoles": ["revocation_authority"],
        "minDistinctSigners": 1,
        "separation": [
            {
                "roles": ["revocation_authority", "producer"],
                "why": "a producer may not revoke its own claim in a way that erases the record",
            },
        ],
        "selfAuthorisation": True,
    },
}

# Every refusal code, with the wrong conclusion it prevents.  The order is the
# order a reader should apply them in; ``authorise`` reports codes in this order.
REFUSAL_CODES: dict[str, str] = {
    "RA_REFUSED_SIGNATURE_UNVERIFIED": (
        "a signature whose cryptographic validity was not checked authorising an "
        "action; prevents an unverified signature from borrowing a role"
    ),
    "RA_REFUSED_IDENTITY_UNRECORDED": (
        "an identity token that no tracked record establishes authorising an "
        "action; prevents a name invented at the point of use"
    ),
    "RA_REFUSED_ROLE_UNKNOWN": (
        "a role outside the seven-role vocabulary authorising an action; prevents "
        "a made-up role label"
    ),
    "RA_REFUSED_ROLE_NOT_ASSIGNED": (
        "an identity signing in a role it was never assigned; prevents a signer "
        "choosing its own role"
    ),
    "RA_REFUSED_EXPIRED": (
        "an assignment beyond its validity authorising a later action; prevents a "
        "stale grant from outliving the scope it was given"
    ),
    "RA_REFUSED_REVOKED": (
        "an assignment revoked before the action authorising it; prevents a "
        "withdrawn authority from being used"
    ),
    "RA_REFUSED_SCOPE_EXCEEDED": (
        "a signature or assignment narrower than the action authorising the "
        "action; prevents a narrow grant from covering a wider action"
    ),
    "RA_REFUSED_WRONG_ROLE": (
        "a valid signature by an identity that does not hold the role the action "
        "requires; prevents the right key from being treated as the right role"
    ),
    "RA_REFUSED_SELF_AUTHORISATION": (
        "the producer of the evidence authorising its own promotion; prevents the "
        "author from accepting its own run"
    ),
    "RA_REFUSED_SEPARATION": (
        "one identity occupying both sides of a required separation; prevents two "
        "signatures that are one party"
    ),
    "RA_REFUSED_DUPLICATE_SIGNER": (
        "one identity signing twice and being counted as two signers; prevents a "
        "quorum from being met by repetition"
    ),
    "RA_REFUSED_INSUFFICIENT_SIGNERS": (
        "fewer distinct signers (or an unheld required role) than the action "
        "requires; prevents an under-signed action"
    ),
    "RA_REFUSED_ACTION_UNKNOWN": (
        "an action with no policy being authorised by default; prevents an "
        "unlisted action from inheriting permission"
    ),
}


class ToolError(Exception):
    """An unreadable input or usage error (exit status 2)."""


# ---------------------------------------------------------------------------
# Time, scope and party helpers
# ---------------------------------------------------------------------------
def _as_date(value: Any, field: str) -> date:
    if isinstance(value, date):
        return value
    if not isinstance(value, str) or not value:
        raise ToolError(f"{field} must be a non-empty ISO date")
    try:
        return date.fromisoformat(value[:10])
    except ValueError as exc:
        raise ToolError(f"{field} is not an ISO date: {value!r}") from exc


def _at(value: Any) -> date:
    return date.today() if value is None else _as_date(value, "at")


def _scopes(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return list(value)
    raise ToolError("scope must be a string or a list of strings")


def _covers(granted: Any, required: Any) -> bool:
    """Whether ``granted`` covers every item in ``required``.

    Exact match, the ``*`` wildcard, and a suffix wildcard (``release:*`` covers
    ``release:openssh-b85c``).  Nothing else is inferred.
    """
    granted_items = _scopes(granted)
    required_items = _scopes(required)
    for need in required_items:
        hit = False
        for have in granted_items:
            if have == "*" or have == need:
                hit = True
                break
            if have.endswith("*") and need.startswith(have[:-1]):
                hit = True
                break
        if not hit:
            return False
    return True


def _normalise_assignments(assignments: Any) -> list[dict[str, Any]]:
    if isinstance(assignments, dict):
        assignments = assignments.get("assignments", [])
    if not isinstance(assignments, list):
        raise ToolError("assignments must be a list or a record with 'assignments'")
    return [item for item in assignments if isinstance(item, dict)]


def _recorded_assignments(assignments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Only assignments that name a tracked record establish an identity."""
    return [item for item in assignments if item.get("evidence")]


def _party_map(assignments: list[dict[str, Any]]) -> dict[str, str]:
    parties: dict[str, str] = {}
    for item in _recorded_assignments(assignments):
        identity = item.get("identity")
        if not isinstance(identity, str) or not identity:
            continue
        party = item.get("party") or identity
        if identity in parties and parties[identity] != party:
            # A conflicting party mapping is not resolvable; keep both aliases in
            # one conservative class so separation cannot be escaped by a second
            # spelling.
            parties[identity] = f"AMBIGUOUS:{identity}"
        else:
            parties[identity] = party
    return parties


def _party_of(identity: Any, parties: dict[str, str]) -> str:
    return parties.get(identity, str(identity))


def _same_party(left: Any, right: Any, parties: dict[str, str]) -> bool:
    return _party_of(left, parties) == _party_of(right, parties)


def _assignment_state(assignment: dict[str, Any], at: date) -> str:
    """VALID, REVOKED, EXPIRED or NOT_YET for one assignment at ``at``."""
    granted_at = _as_date(assignment.get("grantedAt"), "grantedAt")
    revoked_at = assignment.get("revokedAt")
    expires_at = assignment.get("expiresAt")
    if revoked_at is not None and at >= _as_date(revoked_at, "revokedAt"):
        return "REVOKED"
    if expires_at is not None and at > _as_date(expires_at, "expiresAt"):
        return "EXPIRED"
    if at < granted_at:
        return "NOT_YET"
    return "VALID"


def _order_codes(codes: list[str]) -> list[str]:
    seen: list[str] = []
    for code in REFUSAL_CODES:
        if code in codes and code not in seen:
            seen.append(code)
    for code in codes:  # any code a caller's policy adds outside the registry
        if code not in seen:
            seen.append(code)
    return seen


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------
def _outcome(
    action: str,
    at: date,
    outcome: str,
    codes: list[str],
    detail: list[str],
    *,
    signers: int = 0,
    required_roles: list[str] | None = None,
    min_distinct: int = 0,
    valid_signers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "action": action,
        "at": at.isoformat(),
        "outcome": outcome,
        "codes": _order_codes(codes),
        "detail": detail,
        "signers": signers,
        "requiredRoles": required_roles or [],
        "minDistinctSigners": min_distinct,
        "validSigners": [
            {"identity": item.get("identity"), "role": item.get("role"),
             "scope": _scopes(item.get("scope"))}
            for item in (valid_signers or [])
        ],
    }


def authorise(
    action: str,
    signatures: Any,
    assignments: Any,
    policy: dict[str, dict[str, Any]] | None = None,
    at: Any = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Decide one action.  Returns the outcome, every code and the detail."""
    policy = ACTIONS if policy is None else policy
    moment = _at(at)
    context = context or {}
    assignments_list = _normalise_assignments(assignments)

    rule = policy.get(action)
    if rule is None:
        return _outcome(
            action, moment, "REFUSED", ["RA_REFUSED_ACTION_UNKNOWN"],
            [f"no policy exists for action {action!r}; an unlisted action is not authorised by default"],
        )
    if rule.get("status") == "NOT_RUN":
        return _outcome(
            action, moment, "NOT_RUN", [],
            [str(rule.get("notRunReason") or "the action policy declares NOT_RUN")],
        )
    if signatures is None:
        return _outcome(
            action, moment, "NOT_RUN", [],
            ["no signature set was supplied; the action was not attempted, which is not a pass"],
        )
    if not isinstance(signatures, list):
        raise ToolError("signatures must be a list")

    required_roles = list(rule.get("requiredRoles") or [])
    min_distinct = int(rule.get("minDistinctSigners", 1))
    action_scope = _scopes(context.get("scope") or ["*"])
    recorded = _recorded_assignments(assignments_list)
    recorded_ids = {item.get("identity") for item in recorded}
    parties = _party_map(assignments_list)

    codes: list[str] = []
    detail: list[str] = []
    valid: list[dict[str, Any]] = []

    for index, signature in enumerate(signatures):
        if not isinstance(signature, dict):
            raise ToolError(f"signature[{index}] must be an object")
        identity = signature.get("identity")
        role = signature.get("role")
        label = f"signature[{index}] identity={identity!r} role={role!r}"

        # 1. A signature that was not verified is refused before its role is read.
        if signature.get("verified") is not True:
            codes.append("RA_REFUSED_SIGNATURE_UNVERIFIED")
            detail.append(f"{label} is unverified; its role is not considered")
            continue
        # 2. The identity must be established by a tracked record.
        if identity not in recorded_ids:
            codes.append("RA_REFUSED_IDENTITY_UNRECORDED")
            detail.append(f"{label}: no tracked record establishes identity {identity!r}")
            continue
        # 3. The role must be known and assigned, and the assignment valid now.
        if role not in ROLES:
            codes.append("RA_REFUSED_ROLE_UNKNOWN")
            detail.append(f"{label}: {role!r} is not one of the seven roles {list(ROLES)}")
            continue
        candidates = [
            item for item in recorded
            if item.get("identity") == identity and item.get("role") == role
        ]
        if not candidates:
            codes.append("RA_REFUSED_ROLE_NOT_ASSIGNED")
            detail.append(f"{label}: identity {identity!r} has no recorded assignment of {role!r}")
            continue
        states = [(item, _assignment_state(item, moment)) for item in candidates]
        usable = [item for item, state in states if state == "VALID"]
        if not usable:
            for item, state in states:
                if state == "REVOKED":
                    codes.append("RA_REFUSED_REVOKED")
                    detail.append(f"{label}: the {role!r} assignment was revoked at {item.get('revokedAt')}")
                    break
                if state == "EXPIRED":
                    codes.append("RA_REFUSED_EXPIRED")
                    detail.append(f"{label}: the {role!r} assignment expired at {item.get('expiresAt')}")
                    break
                if state == "NOT_YET":
                    codes.append("RA_REFUSED_ROLE_NOT_ASSIGNED")
                    detail.append(f"{label}: the {role!r} assignment begins at {item.get('grantedAt')}, after the action")
                    break
            continue
        # 4. Both the signature and the assignment must cover the action scope.
        if not _covers(signature.get("scope"), action_scope):
            codes.append("RA_REFUSED_SCOPE_EXCEEDED")
            detail.append(
                f"{label}: signature scope {_scopes(signature.get('scope'))} does not cover "
                f"action scope {action_scope}"
            )
            continue
        if not any(_covers(item.get("scope"), action_scope) for item in usable):
            codes.append("RA_REFUSED_SCOPE_EXCEEDED")
            detail.append(
                f"{label}: the {role!r} assignment scope {[item.get('scope') for item in usable]} "
                f"does not cover action scope {action_scope}"
            )
            continue
        # 5. The role must be one the action requires.
        if role not in required_roles:
            codes.append("RA_REFUSED_WRONG_ROLE")
            detail.append(
                f"{label}: the action requires {required_roles}, so a valid {role!r} "
                f"signature is the wrong role"
            )
            continue
        valid.append(signature)

    # 6a. The producer of the evidence may not be the signer whose authorisation
    # is required.  The context names the producer; aliases of its party count.
    producer = context.get("evidenceProducer")
    if producer is None:
        producer = (context.get("roleIdentities") or {}).get("producer")
    if rule.get("selfAuthorisation") and producer is not None:
        for signature in valid:
            if _same_party(signature.get("identity"), producer, parties):
                codes.append("RA_REFUSED_SELF_AUTHORISATION")
                detail.append(
                    f"separation failed: {signature.get('identity')!r} is the producer of "
                    f"the evidence ({producer!r}) and signs its own authorisation"
                )
                break

    # 6b. No identity (or alias party) may occupy both sides of a separation.
    role_parties: dict[str, set[str]] = {}
    for signature in valid:
        role = signature.get("role")
        role_parties.setdefault(role, set()).add(_party_of(signature.get("identity"), parties))
    for role, identity in (context.get("roleIdentities") or {}).items():
        if identity is not None:
            role_parties.setdefault(role, set()).add(_party_of(identity, parties))
    for constraint in rule.get("separation") or []:
        left, right = constraint["roles"]
        overlap = role_parties.get(left, set()) & role_parties.get(right, set())
        if overlap:
            codes.append("RA_REFUSED_SEPARATION")
            detail.append(
                f"separation failed: {left} and {right} are the same party "
                f"{sorted(overlap)}; {constraint['why']}"
            )

    # 7. Signers must be distinct parties and meet the minimum.  A required role
    # with no valid signer is also an insufficient signer set.
    identities = [signature.get("identity") for signature in valid]
    if len(identities) != len(set(identities)):
        codes.append("RA_REFUSED_DUPLICATE_SIGNER")
        detail.append(
            "one identity signs more than once; a repeated signature is not a "
            "second signer"
        )
    signer_parties = {_party_of(identity, parties) for identity in identities}
    present_roles = {signature.get("role") for signature in valid}
    missing = [role for role in required_roles if role not in present_roles]
    if missing:
        codes.append("RA_REFUSED_INSUFFICIENT_SIGNERS")
        detail.append(f"required role(s) {missing} have no valid signature")
    if len(signer_parties) < min_distinct:
        codes.append("RA_REFUSED_INSUFFICIENT_SIGNERS")
        detail.append(
            f"{len(signer_parties)} distinct signer party(ies); the action requires "
            f"{min_distinct}"
        )

    codes = _order_codes(codes)
    return _outcome(
        action, moment, "REFUSED" if codes else "AUTHORISED", codes, detail,
        signers=len(signer_parties), required_roles=required_roles,
        min_distinct=min_distinct, valid_signers=valid,
    )


def separation_failures(
    action: str,
    assignments: Any,
    policy: dict[str, dict[str, Any]] | None = None,
    at: Any = None,
    context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Assess the recorded role fills against an action's separations.

    This is a structural reading of the assignments, independent of whether a
    signature exists.  It is what lets a record say *which* separation failed
    when the recorded attempt is refused earlier at an unverified signature.
    """
    policy = ACTIONS if policy is None else policy
    moment = _at(at)
    context = context or {}
    rule = policy.get(action)
    if rule is None:
        return []
    assignments_list = _normalise_assignments(assignments)
    parties = _party_map(assignments_list)
    action_scope = _scopes(context.get("scope") or ["*"])
    role_parties: dict[str, set[str]] = {}
    for role, identity in (context.get("roleIdentities") or {}).items():
        if identity is not None:
            role_parties.setdefault(role, set()).add(_party_of(identity, parties))
    for role in rule.get("requiredRoles") or []:
        if role in role_parties:
            continue
        for item in _recorded_assignments(assignments_list):
            if item.get("role") != role:
                continue
            if _assignment_state(item, moment) != "VALID":
                continue
            if not _covers(item.get("scope"), action_scope):
                continue
            role_parties.setdefault(role, set()).add(_party_of(item.get("identity"), parties))
    failures: list[dict[str, Any]] = []
    for constraint in rule.get("separation") or []:
        left, right = constraint["roles"]
        missing = [role for role in (left, right) if role not in role_parties]
        if missing:
            failures.append({
                "constraint": f"{left} != {right}",
                "why": constraint["why"],
                "party": [],
                "evaluated": False,
                "note": f"role(s) {missing} have no recorded identity for this scope",
            })
            continue
        overlap = role_parties.get(left, set()) & role_parties.get(right, set())
        if overlap:
            failures.append({
                "constraint": f"{left} != {right}",
                "why": constraint["why"],
                "party": sorted(overlap),
                "evaluated": True,
            })
    return failures


def roles_of(
    identity: str,
    at: Any = None,
    assignments: Any = None,
) -> list[dict[str, Any]]:
    """The roles an identity holds at ``at``, from recorded assignments."""
    moment = _at(at)
    if assignments is None:
        assignments = load_assignments(ROLES_RECORD)
    result: list[dict[str, Any]] = []
    for item in _recorded_assignments(_normalise_assignments(assignments)):
        if item.get("identity") != identity:
            continue
        if _assignment_state(item, moment) != "VALID":
            continue
        result.append({
            "role": item.get("role"),
            "scope": _scopes(item.get("scope")),
            "party": item.get("party") or identity,
            "grantedAt": item.get("grantedAt"),
            "expiresAt": item.get("expiresAt"),
            "revokedAt": item.get("revokedAt"),
            "evidence": item.get("evidence"),
        })
    return result


def explain(
    action: str,
    policy: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """The policy a consumer needs to see why an action can be refused."""
    policy = ACTIONS if policy is None else policy
    rule = policy.get(action)
    if rule is None:
        return None
    return {
        "action": action,
        "description": rule.get("description", ""),
        "requiredRoles": list(rule.get("requiredRoles") or []),
        "minDistinctSigners": int(rule.get("minDistinctSigners", 1)),
        "separation": [dict(item) for item in (rule.get("separation") or [])],
        "selfAuthorisation": bool(rule.get("selfAuthorisation", False)),
        "status": rule.get("status", "ACTIVE"),
        "refusalCodes": list(REFUSAL_CODES),
    }


# ---------------------------------------------------------------------------
# Loading and the command line
# ---------------------------------------------------------------------------
def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ToolError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ToolError(f"cannot parse {path}: {exc}") from exc


def load_assignments(path: Path | None = None) -> list[dict[str, Any]]:
    document = _load_json(path or ROLES_RECORD)
    if isinstance(document, dict):
        document = document.get("assignments", [])
    if not isinstance(document, list):
        raise ToolError(f"{path or ROLES_RECORD} names no assignment list")
    return _normalise_assignments(document)


def _signatures_from(document: Any, action: str, face_value: bool) -> list[Any] | None:
    if isinstance(document, list):
        return document
    if not isinstance(document, dict):
        raise ToolError("signatures document must be a list or an object")
    if "signatures" in document:
        return document["signatures"]
    actions = document.get("actions")
    if isinstance(actions, dict) and action in actions:
        entry = actions[action]
        key = "faceValue" if face_value else "recorded"
        if isinstance(entry, dict) and isinstance(entry.get(key), dict):
            return entry[key].get("signatures")
        if isinstance(entry, dict) and key == "recorded" and "signatures" in entry:
            return entry["signatures"]
    return None


def _print_authorise(result: dict[str, Any], face_value_assessment: dict[str, Any] | None,
                     separation: list[dict[str, Any]] | None) -> None:
    codes = ",".join(result["codes"]) if result["codes"] else "NONE"
    print(
        f"authorisation: action={result['action']} at={result['at']} "
        f"outcome={result['outcome']} codes={codes} signers={result['signers']} "
        f"required={','.join(result['requiredRoles']) or 'NONE'}"
    )
    for line in result["detail"]:
        print(f"  detail: {line}")
    if face_value_assessment is not None:
        face_codes = ",".join(face_value_assessment["codes"]) or "NONE"
        print(
            f"  face-value: outcome={face_value_assessment['outcome']} codes={face_codes} "
            f"(counterfactual role assessment; not an authorisation)"
        )
    for failure in separation or []:
        if failure.get("evaluated"):
            print(
                f"  separation: {failure['constraint']} same party "
                f"{','.join(failure.get('party') or [])} -- {failure['why']}"
            )
        else:
            print(f"  separation: {failure['constraint']} not evaluable -- {failure.get('note')}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    roles_parser = sub.add_parser("roles", help="print the roles an identity holds")
    roles_parser.add_argument("identity")
    roles_parser.add_argument("--at", default=None, help="ISO date (default today)")
    roles_parser.add_argument("--assignments", default=None)
    roles_parser.add_argument("--json", action="store_true")

    authorise_parser = sub.add_parser("authorise", help="decide one action")
    authorise_parser.add_argument("action")
    authorise_parser.add_argument("signatures", nargs="?", default=None)
    authorise_parser.add_argument("--assignments", default=None)
    authorise_parser.add_argument("--authorisations", default=None)
    authorise_parser.add_argument("--at", default=None, help="ISO date (default today)")
    authorise_parser.add_argument("--face-value", action="store_true",
                                  help="use the record's counterfactual verified signatures")
    authorise_parser.add_argument("--json", action="store_true")

    explain_parser = sub.add_parser("explain", help="print an action policy")
    explain_parser.add_argument("action")
    explain_parser.add_argument("--json", action="store_true")

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code != 0 else 0

    try:
        if args.command == "roles":
            assignments = load_assignments(
                Path(args.assignments).resolve() if args.assignments else None
            )
            found = roles_of(args.identity, at=args.at, assignments=assignments)
            if args.json:
                print(json.dumps({"identity": args.identity, "at": args.at,
                                  "roles": found}, indent=2, sort_keys=True))
            elif found:
                for item in found:
                    print(
                        f"identity={args.identity} role={item['role']} "
                        f"scope={','.join(item['scope']) or 'NONE'} party={item['party']} "
                        f"grantedAt={item['grantedAt']}"
                    )
            else:
                print(f"identity={args.identity} roles=NONE")
            return 0 if found else 1

        if args.command == "authorise":
            assignments = load_assignments(
                Path(args.assignments).resolve() if args.assignments else None
            )
            record_path = (
                Path(args.authorisations).resolve() if args.authorisations
                else Path(args.signatures).resolve() if args.signatures
                else AUTHORISATION_RECORD
            )
            document = _load_json(record_path)
            signatures = _signatures_from(document, args.action, args.face_value)
            context = None
            face_value_assessment = None
            separation = None
            if isinstance(document, dict) and isinstance(document.get("actions"), dict):
                entry = document["actions"].get(args.action) or {}
                context = entry.get("context")
                separation = separation_failures(
                    args.action, assignments, at=args.at, context=context
                )
                other = "recorded" if args.face_value else "faceValue"
                if isinstance(entry.get(other), dict):
                    other_signatures = entry[other].get("signatures")
                    face_value_assessment = authorise(
                        args.action, other_signatures, assignments,
                        at=args.at, context=context,
                    )
            result = authorise(
                args.action, signatures, assignments, at=args.at, context=context
            )
            if args.json:
                payload = dict(result)
                payload["faceValue"] = face_value_assessment
                payload["separationFailed"] = separation
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                _print_authorise(result, face_value_assessment, separation)
            return 0 if result["outcome"] == "AUTHORISED" else 1

        if args.command == "explain":
            policy = explain(args.action)
            if policy is None:
                print(f"explain: action={args.action} outcome=REFUSED codes=RA_REFUSED_ACTION_UNKNOWN")
                return 1
            if args.json:
                print(json.dumps(policy, indent=2, sort_keys=True))
            else:
                print(
                    f"action={policy['action']} status={policy['status']} "
                    f"required={','.join(policy['requiredRoles']) or 'NONE'} "
                    f"minDistinctSigners={policy['minDistinctSigners']} "
                    f"selfAuthorisation={str(policy['selfAuthorisation']).lower()}"
                )
                for constraint in policy["separation"]:
                    print(
                        f"  separation: {constraint['roles'][0]} != {constraint['roles'][1]} "
                        f"-- {constraint['why']}"
                    )
            return 0
    except ToolError as exc:
        print(f"authorisation: error: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
