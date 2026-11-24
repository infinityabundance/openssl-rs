#!/usr/bin/env python3
"""thresholds.py -- a k-of-n threshold counts distinct trust domains, not labels.

Why this tool exists
--------------------
A quorum is a claim about *distinct trust domains*.  Two approvals that name two
different domain labels but resolve to the same domain are one approval.  A
domain label asserted by the approval itself is not evidence of a domain.  A
threshold lowered after its approvals were collected is not the threshold that
was met.  A k-of-n threshold is unreachable when fewer than k distinct domains
exist at all.

The rule
--------
An approval contributes to a threshold only when every one of the following
holds, in this order:

  1. its ``domainId`` resolves to a recorded domain
     (``TH_REFUSED_DOMAIN_UNRECORDED``);
  2. that domain is established by a record, not by the approval's own field
     (``TH_REFUSED_SELF_ASSERTED_DOMAIN``);
  3. that domain is not the candidate's own or a same-party domain
     (``TH_REFUSED_CANDIDATE_DOMAIN``);
  4. its signature is verified (``TH_REFUSED_UNVERIFIED``);
  5. its role is one the threshold requires and is held by the identity at the
     approval time under A14's assignment records (``TH_REFUSED_WRONG_ROLE``);
  6. its artefact digest matches the threshold's and it has not expired
     (``TH_REFUSED_STALE_APPROVAL``).

The count is over distinct *established* domains after the substitutions below
have been refused.  Two labels that share an establishment record are one domain
(``TH_REFUSED_ALIASED``); one domain approving twice is one domain
(``TH_REFUSED_DOMAIN_DUPLICATE``); one identity approving under two labels is one
identity and contributes at most one domain (``TH_REFUSED_DUPLICATE_IDENTITY``).
A reachable threshold with fewer qualifying domains than k is
``TH_REFUSED_INSUFFICIENT_DOMAINS``.  A threshold with fewer than k established
domains in existence is ``TH_REFUSED_THRESHOLD_UNREACHABLE``.

The threshold declaration must pre-exist the approvals.  A declaration made
after the earliest approval, or amended after approvals exist, is
``TH_REFUSED_THRESHOLD_LOWERED``: the k that was met is not the k recorded.  A
missing or invalid declaration is ``TH_REFUSED_THRESHOLD_UNRECORDED``.

What this tool does not establish
---------------------------------
It does not verify a cryptographic signature (``verified`` is supplied by the
caller), decide role authorisation (the role check is delegated to A14's
``authorisation.authorise`` over its assignment records), establish that a
domain record is truthful, or decide that a domain is an independent
organisation.  A ``MET`` threshold is not an authorisation, not truth and not
independence; it is a count over the domains the records establish.

Usage
-----
    python3 forensics/tools/thresholds.py domains [--domains PATH]
    python3 forensics/tools/thresholds.py count ID APPROVALS [--domains PATH]
    python3 forensics/tools/thresholds.py evaluate ID [--json]

Exit status: 0 when a threshold is ``MET`` (or a query succeeds), 1 when it is
``UNMET``/``UNREACHABLE``/``NOT_RUN`` or a refusal fires, 2 for a usage or
unreadable-input error.  The code and the outcome are always printed.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import authorisation  # noqa: E402

TOOL_PATH = "forensics/tools/thresholds.py"
MODEL_ID = "a15/v1"
DOMAINS_SCHEMA = "openssl-rs/a15/domains/1"
THRESHOLDS_SCHEMA = "openssl-rs/a15/thresholds/1"
APPROVALS_SCHEMA = "openssl-rs/a15/approvals/1"
EVALUATION_SCHEMA = "openssl-rs/a15/threshold-evaluation/1"
CONTROLS_SCHEMA = "openssl-rs/a15/controls/1"

DEFAULT_DOMAINS = REPO_ROOT / "evidence/a15/DOMAINS.json"
DEFAULT_THRESHOLDS = REPO_ROOT / "evidence/a15/THRESHOLDS.json"
DEFAULT_APPROVALS = REPO_ROOT / "evidence/a15/APPROVALS.json"
DEFAULT_ROLES = REPO_ROOT / "evidence/a14/ROLES.json"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
CODE_OK = "TH_OK"
CODE_USAGE = "TH_USAGE"

OUTCOME_MET = "MET"
OUTCOME_UNMET = "UNMET"
OUTCOME_UNREACHABLE = "UNREACHABLE"
OUTCOME_NOT_RUN = "NOT_RUN"
OUTCOMES = (OUTCOME_MET, OUTCOME_UNMET, OUTCOME_UNREACHABLE, OUTCOME_NOT_RUN)

# ---------------------------------------------------------------------------
# Refusal codes. Each is stable and names the wrong conclusion it prevents.
# ---------------------------------------------------------------------------

TH_REFUSED_THRESHOLD_UNRECORDED = "TH_REFUSED_THRESHOLD_UNRECORDED"
TH_REFUSED_THRESHOLD_LOWERED = "TH_REFUSED_THRESHOLD_LOWERED"
TH_REFUSED_THRESHOLD_UNREACHABLE = "TH_REFUSED_THRESHOLD_UNREACHABLE"
TH_REFUSED_SELF_ASSERTED_DOMAIN = "TH_REFUSED_SELF_ASSERTED_DOMAIN"
TH_REFUSED_DOMAIN_UNRECORDED = "TH_REFUSED_DOMAIN_UNRECORDED"
TH_REFUSED_CANDIDATE_DOMAIN = "TH_REFUSED_CANDIDATE_DOMAIN"
TH_REFUSED_ALIASED = "TH_REFUSED_ALIASED"
TH_REFUSED_DOMAIN_DUPLICATE = "TH_REFUSED_DOMAIN_DUPLICATE"
TH_REFUSED_UNVERIFIED = "TH_REFUSED_UNVERIFIED"
TH_REFUSED_WRONG_ROLE = "TH_REFUSED_WRONG_ROLE"
TH_REFUSED_STALE_APPROVAL = "TH_REFUSED_STALE_APPROVAL"
TH_REFUSED_INSUFFICIENT_DOMAINS = "TH_REFUSED_INSUFFICIENT_DOMAINS"
TH_REFUSED_DUPLICATE_IDENTITY = "TH_REFUSED_DUPLICATE_IDENTITY"

# The order a reader should apply them in; ``evaluate`` reports codes in it.
CODE_ORDER: tuple[str, ...] = (
    TH_REFUSED_THRESHOLD_UNRECORDED,
    TH_REFUSED_THRESHOLD_LOWERED,
    TH_REFUSED_THRESHOLD_UNREACHABLE,
    TH_REFUSED_SELF_ASSERTED_DOMAIN,
    TH_REFUSED_DOMAIN_UNRECORDED,
    TH_REFUSED_CANDIDATE_DOMAIN,
    TH_REFUSED_ALIASED,
    TH_REFUSED_DOMAIN_DUPLICATE,
    TH_REFUSED_UNVERIFIED,
    TH_REFUSED_WRONG_ROLE,
    TH_REFUSED_STALE_APPROVAL,
    TH_REFUSED_INSUFFICIENT_DOMAINS,
    TH_REFUSED_DUPLICATE_IDENTITY,
)

REFUSALS: dict[str, dict[str, str]] = {
    TH_REFUSED_THRESHOLD_UNRECORDED: {
        "condition": (
            "no threshold declaration exists, or the declaration lacks id, action, "
            "k, n, requiredRoles, distinctDomains: true, declaredAt or declaredBy"
        ),
        "prevents": (
            "that an undeclared or malformed threshold is evaluated as if it were a "
            "recorded k-of-n claim"
        ),
    },
    TH_REFUSED_THRESHOLD_LOWERED: {
        "condition": (
            "the declaration's declaredAt is after the earliest approval, or an "
            "amendment exists at or after the earliest approval"
        ),
        "prevents": (
            "that a threshold lowered after the approvals were collected is read as "
            "the threshold that was met"
        ),
    },
    TH_REFUSED_THRESHOLD_UNREACHABLE: {
        "condition": (
            "fewer established external domains exist in the inventory than k"
        ),
        "prevents": (
            "that a threshold is reported as merely unmet when no set of approvals "
            "could ever meet it"
        ),
    },
    TH_REFUSED_SELF_ASSERTED_DOMAIN: {
        "condition": (
            "the domain record has no establishment record (no path and sha256), so "
            "the only thing asserting the domain is an approval's own field"
        ),
        "prevents": (
            "that a domain label invented at the point of approval is counted as a "
            "distinct trust domain"
        ),
    },
    TH_REFUSED_DOMAIN_UNRECORDED: {
        "condition": "the approval's domainId names no recorded domain",
        "prevents": (
            "that a label with no domain record is counted because it appears in an "
            "approval"
        ),
    },
    TH_REFUSED_CANDIDATE_DOMAIN: {
        "condition": (
            "the resolved domain is the candidate's own domain, a same-party domain, "
            "or a domain whose record does not declare independence of the candidate"
        ),
        "prevents": (
            "that the candidate or the producing party is counted as an independent "
            "approval of itself"
        ),
    },
    TH_REFUSED_ALIASED: {
        "condition": (
            "two approvals use different domain labels whose domain records share one "
            "establishment record"
        ),
        "prevents": (
            "that one domain is counted twice by spelling its label twice"
        ),
    },
    TH_REFUSED_DOMAIN_DUPLICATE: {
        "condition": (
            "the same domainId approves in more than one counted approval, or the "
            "inventory records the same domainId twice"
        ),
        "prevents": (
            "that a repeated approval from one domain is counted as a second domain"
        ),
    },
    TH_REFUSED_UNVERIFIED: {
        "condition": (
            "the approval's signature is not verified, or the approval is not a "
            "readable object"
        ),
        "prevents": (
            "that an unchecked approval borrows a domain and a role"
        ),
    },
    TH_REFUSED_WRONG_ROLE: {
        "condition": (
            "the approval's role is not one the threshold requires, or A14's "
            "assignment records do not establish that role for the identity at the "
            "approval time at the threshold's scope"
        ),
        "prevents": (
            "that a verified approval in the wrong role is counted; the role policy "
            "is read from A14's records, not restated here"
        ),
    },
    TH_REFUSED_STALE_APPROVAL: {
        "condition": (
            "the approval's artefactDigest differs from the threshold's, the "
            "approval has expired, its approvedAt is after the evaluation date, or "
            "a date/digest is absent or malformed"
        ),
        "prevents": (
            "that an approval for different bytes or an expired approval is counted"
        ),
    },
    TH_REFUSED_INSUFFICIENT_DOMAINS: {
        "condition": (
            "at least k established external domains exist, but fewer than k "
            "distinct domains have a qualifying approval"
        ),
        "prevents": (
            "that fewer approvals than k are reported as meeting a reachable "
            "threshold"
        ),
    },
    TH_REFUSED_DUPLICATE_IDENTITY: {
        "condition": (
            "one identity approves under two different established domains"
        ),
        "prevents": (
            "that one approver is counted as two domains; the first approval is kept "
            "and later approvals by the same identity do not add a domain"
        ),
    },
}

# A14 codes that establish the approval's role is invalid for this action.  The
# action-level codes (insufficient signers, separation, self-authorisation,
# duplicate signer) are A14's whole-action policy and are not re-applied here.
ROLE_INVALID_CODES = frozenset(
    {
        "RA_REFUSED_SIGNATURE_UNVERIFIED",
        "RA_REFUSED_IDENTITY_UNRECORDED",
        "RA_REFUSED_ROLE_UNKNOWN",
        "RA_REFUSED_ROLE_NOT_ASSIGNED",
        "RA_REFUSED_EXPIRED",
        "RA_REFUSED_REVOKED",
        "RA_REFUSED_SCOPE_EXCEEDED",
        "RA_REFUSED_WRONG_ROLE",
        "RA_REFUSED_ACTION_UNKNOWN",
    }
)

# A domain whose kind is one of these is the candidate's own or a same-party
# domain no matter what ``independentOfCandidate`` claims.
CANDIDATE_KINDS = frozenset({"candidate", "producer", "same-party", "project", "self"})

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ToolError(Exception):
    """An unreadable input or usage error (exit status 2)."""


class Refusal(Exception):
    """A stable refusal code and the conclusion it prevents."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Normalisation, dates and domains
# ---------------------------------------------------------------------------
def _parse_date(value: Any) -> date | None:
    if isinstance(value, date):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _domains_document(domains: Any) -> dict[str, Any]:
    if isinstance(domains, Mapping):
        document = dict(domains)
    elif isinstance(domains, list):
        document = {"domains": list(domains)}
    elif domains is None:
        document = {"domains": []}
    else:
        raise ToolError("domains must be a document, a list or None")
    records = document.get("domains")
    if records is None:
        document["domains"] = []
    elif not isinstance(records, list):
        raise ToolError("the domains document's 'domains' member is not a list")
    return document


def _domain_records(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    records = document.get("domains") or []
    return [item for item in records if isinstance(item, Mapping)]


def _domain_index(document: Mapping[str, Any]) -> tuple[dict[str, Mapping[str, Any]], list[str]]:
    index: dict[str, Mapping[str, Any]] = {}
    duplicates: list[str] = []
    for record in _domain_records(document):
        domain_id = record.get("domainId")
        if not isinstance(domain_id, str) or not domain_id:
            continue
        if domain_id in index:
            duplicates.append(domain_id)
        index[domain_id] = record
    return index, duplicates


def established_by(domain: Mapping[str, Any]) -> dict[str, str] | None:
    """The establishment record, or None when the domain asserts itself.

    A domain is established by ``{path, sha256}``.  An absent, empty or
    malformed record is not an establishment: the label would be the only thing
    asserting the domain.
    """
    record = domain.get("establishedBy")
    if not isinstance(record, Mapping):
        return None
    path = record.get("path")
    digest = record.get("sha256")
    if not isinstance(path, str) or not path.strip():
        return None
    if not isinstance(digest, str) or not _SHA256.match(digest):
        return None
    return {"path": path, "sha256": digest}


def is_candidate_domain(domain: Mapping[str, Any], document: Mapping[str, Any]) -> bool:
    """Whether a domain is the candidate's own, a same-party domain, or undeclared.

    ``independentOfCandidate`` must be exactly ``true`` and the kind must not be
    a candidate/same-party kind.  A missing or false declaration is refused, so
    a domain cannot become independent by omission.
    """
    if domain.get("independentOfCandidate") is not True:
        return True
    if domain.get("kind") in CANDIDATE_KINDS:
        return True
    candidate = document.get("candidateDomain")
    return isinstance(candidate, str) and domain.get("domainId") == candidate


def is_external_domain(domain: Mapping[str, Any], document: Mapping[str, Any]) -> bool:
    return established_by(domain) is not None and not is_candidate_domain(domain, document)


def external_domains(domains: Any) -> list[Mapping[str, Any]]:
    """The established, candidate-independent domains in an inventory."""
    document = _domains_document(domains)
    return [record for record in _domain_records(document)
            if is_external_domain(record, document)]


def available_domain_count(domains: Any) -> int:
    """The number of distinct *establishments* that could count toward k.

    Two labels sharing one establishment record are one domain, so the
    reachability test must not be met by an alias pair.
    """
    document = _domains_document(domains)
    keys = set()
    for record in _domain_records(document):
        if not is_external_domain(record, document):
            continue
        establishment = established_by(record)
        if establishment is not None:
            keys.add((establishment["path"], establishment["sha256"]))
    return len(keys)


def _approval_list(approvals: Any) -> list[Any]:
    if approvals is None:
        return []
    if isinstance(approvals, Mapping):
        approvals = approvals.get("approvals")
    if approvals is None:
        return []
    if not isinstance(approvals, list):
        raise ToolError("approvals must be a list or a document with an 'approvals' array")
    return list(approvals)


def _threshold_scope(threshold: Mapping[str, Any]) -> list[str]:
    scope = threshold.get("scope")
    if scope is None:
        return ["*"]
    if isinstance(scope, str):
        return [scope]
    if isinstance(scope, list) and all(isinstance(item, str) for item in scope):
        return list(scope)
    return ["*"]


def _threshold_digest(threshold: Mapping[str, Any]) -> str | None:
    digest = threshold.get("artefactDigest")
    if isinstance(digest, str) and digest:
        return digest
    subject = threshold.get("subject")
    if isinstance(subject, Mapping):
        digest = subject.get("sha256")
        if isinstance(digest, str) and digest:
            return digest
    return None


def _threshold_valid(threshold: Any) -> bool:
    if not isinstance(threshold, Mapping):
        return False
    if not isinstance(threshold.get("id"), str) or not threshold["id"]:
        return False
    if not isinstance(threshold.get("action"), str) or not threshold["action"]:
        return False
    k = threshold.get("k")
    n = threshold.get("n")
    if isinstance(k, bool) or not isinstance(k, int) or k < 1:
        return False
    if isinstance(n, bool) or not isinstance(n, int) or n < k:
        return False
    roles = threshold.get("requiredRoles")
    if not isinstance(roles, list) or not roles:
        return False
    if not all(isinstance(role, str) and role for role in roles):
        return False
    if threshold.get("distinctDomains") is not True:
        return False
    if _parse_date(threshold.get("declaredAt")) is None:
        return False
    if not threshold.get("declaredBy"):
        return False
    amendments = threshold.get("amendments", [])
    if amendments is None:
        amendments = []
    if not isinstance(amendments, list):
        return False
    for amendment in amendments:
        if not isinstance(amendment, Mapping) or _parse_date(amendment.get("at")) is None:
            return False
    return True


def _amendment_dates(threshold: Mapping[str, Any]) -> list[date]:
    amendments = threshold.get("amendments") or []
    dates: list[date] = []
    for amendment in amendments:
        if isinstance(amendment, Mapping):
            parsed = _parse_date(amendment.get("at"))
            if parsed is not None:
                dates.append(parsed)
    return dates


# ---------------------------------------------------------------------------
# The count over distinct domains
# ---------------------------------------------------------------------------
def distinct_domains(approvals: Any, domains: Any) -> dict[str, Any]:
    """Group approvals by their *domain's establishment record*.

    The approval's ``domainId`` is a lookup key only.  Two labels whose domain
    records share ``establishedBy`` are one domain; the returned ``aliases``
    name the labels that collapsed so a reader can see the substitution.  The
    count is over established, candidate-independent domains; unresolved,
    self-asserted and candidate domains are reported separately and are not
    counted.
    """
    document = _domains_document(domains)
    index, duplicate_records = _domain_index(document)
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    unresolved: list[dict[str, Any]] = []
    self_asserted: list[dict[str, Any]] = []
    not_independent: list[dict[str, Any]] = []
    label_counts: dict[str, int] = {}
    identity_groups: dict[str, set[tuple[str, str]]] = {}

    for approval in _approval_list(approvals):
        if not isinstance(approval, Mapping):
            unresolved.append({"domainId": None, "reason": "the approval is not an object"})
            continue
        label = approval.get("domainId")
        if not isinstance(label, str) or not label:
            unresolved.append({"domainId": label, "reason": "the approval names no domainId"})
            continue
        domain = index.get(label)
        if domain is None:
            unresolved.append({"domainId": label, "reason": "no domain record"})
            continue
        record = established_by(domain)
        if record is None:
            self_asserted.append({"domainId": label, "reason": "no establishment record"})
            continue
        if is_candidate_domain(domain, document):
            not_independent.append({
                "domainId": label,
                "reason": "the candidate's own or a same-party domain",
            })
            continue
        key = (record["path"], record["sha256"])
        group = groups.setdefault(key, {
            "establishedBy": record,
            "domainIds": [],
            "identities": [],
            "approvals": [],
        })
        if label not in group["domainIds"]:
            group["domainIds"].append(label)
        identity = approval.get("identity")
        group["identities"].append(identity)
        group["approvals"].append(
            {"identity": identity, "domainId": label, "role": approval.get("role")}
        )
        label_counts[label] = label_counts.get(label, 0) + 1
        if isinstance(identity, str) and identity:
            identity_groups.setdefault(identity, set()).add(key)

    group_list: list[dict[str, Any]] = []
    for key, group in groups.items():
        group_list.append({
            "establishedBy": group["establishedBy"],
            "domainIds": group["domainIds"],
            "identities": group["identities"],
            "approvals": group["approvals"],
            "aliased": len(group["domainIds"]) > 1,
        })
    aliases = [group for group in group_list if group["aliased"]]
    duplicate_labels = sorted(label for label, count in label_counts.items() if count > 1)
    duplicate_identities = sorted(
        identity for identity, keys in identity_groups.items() if len(keys) > 1
    )
    return {
        "count": len(group_list),
        "groups": group_list,
        "aliases": aliases,
        "duplicateLabels": duplicate_labels,
        "duplicateIdentities": duplicate_identities,
        "duplicateRecords": sorted(set(duplicate_records)),
        "unresolved": unresolved,
        "selfAsserted": self_asserted,
        "notIndependent": not_independent,
        "approvals": len(_approval_list(approvals)),
    }


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------
def _order_codes(codes: list[str]) -> list[str]:
    seen: list[str] = []
    for code in CODE_ORDER:
        if code in codes and code not in seen:
            seen.append(code)
    for code in codes:
        if code not in seen:
            seen.append(code)
    return seen


def _approval_verified(approval: Mapping[str, Any]) -> bool:
    if approval.get("verified") is True:
        return True
    signature = approval.get("signature")
    return isinstance(signature, Mapping) and signature.get("verified") is True


def _role_verdict(
    approval: Mapping[str, Any],
    threshold: Mapping[str, Any],
    role_assignments: Any,
) -> tuple[bool, list[str], str]:
    """Delegate the role check to A14's assignment records.

    A single synthetic signature is handed to ``authorisation.authorise``.  The
    action-level codes (insufficient signers, separation, self-authorisation)
    are A14's whole-action policy and are ignored here; only the codes that say
    this identity does not hold this role for this action are considered.
    """
    identity = approval.get("identity")
    role = approval.get("role")
    required = threshold.get("requiredRoles") or []
    if not isinstance(role, str) or role not in required:
        return False, [TH_REFUSED_WRONG_ROLE], (
            f"role {role!r} is not one the threshold requires {list(required)}"
        )
    if not isinstance(identity, str) or not identity:
        return False, [TH_REFUSED_WRONG_ROLE], "the approval names no identity"
    try:
        decision = authorisation.authorise(
            threshold.get("action"),
            [{
                "identity": identity,
                "role": role,
                "scope": ["*"],
                "verified": True,
            }],
            role_assignments,
            at=approval.get("approvedAt"),
            context={"scope": _threshold_scope(threshold)},
        )
    except authorisation.ToolError as error:
        return False, [TH_REFUSED_WRONG_ROLE], f"the role records are unreadable: {error}"
    invalid = sorted(set(decision.get("codes") or []) & ROLE_INVALID_CODES)
    if invalid:
        return False, [TH_REFUSED_WRONG_ROLE], (
            f"A14 refuses identity {identity!r} in role {role!r}: {', '.join(invalid)}"
        )
    return True, [], ""


def _check_approval(
    approval: Any,
    threshold: Mapping[str, Any],
    domains_document: Mapping[str, Any],
    index: Mapping[str, Mapping[str, Any]],
    role_assignments: Any,
    moment: date,
    expected_digest: str | None,
) -> dict[str, Any]:
    codes: list[str] = []
    detail: list[str] = []
    identity = approval.get("identity") if isinstance(approval, Mapping) else None
    label = approval.get("domainId") if isinstance(approval, Mapping) else None
    role = approval.get("role") if isinstance(approval, Mapping) else None
    verdict: dict[str, Any] = {
        "identity": identity,
        "domainId": label,
        "role": role,
        "qualified": False,
        "codes": codes,
        "detail": detail,
    }

    if not isinstance(approval, Mapping):
        codes.append(TH_REFUSED_UNVERIFIED)
        detail.append("the approval is not an object; an unreadable approval is not verified")
        return verdict

    # 1. The domain label must resolve to a record.
    if not isinstance(label, str) or not label:
        codes.append(TH_REFUSED_DOMAIN_UNRECORDED)
        detail.append("the approval names no domainId")
        return verdict
    domain = index.get(label)
    if domain is None:
        codes.append(TH_REFUSED_DOMAIN_UNRECORDED)
        detail.append(f"domainId {label!r} names no recorded domain")
        return verdict

    # 2. A domain record must be established by a record, not by this field.
    record = established_by(domain)
    if record is None:
        codes.append(TH_REFUSED_SELF_ASSERTED_DOMAIN)
        detail.append(
            f"domain {label!r} has no establishment record; the approval's field is "
            "the only thing asserting it"
        )
        return verdict

    # 3. The domain must not be the candidate's own or a same-party domain.
    if is_candidate_domain(domain, domains_document):
        codes.append(TH_REFUSED_CANDIDATE_DOMAIN)
        detail.append(
            f"domain {label!r} is the candidate's own or a same-party domain "
            f"(kind={domain.get('kind')!r}, independentOfCandidate="
            f"{domain.get('independentOfCandidate')!r})"
        )
        return verdict

    verdict["establishedBy"] = record
    verdict["domainKey"] = [record["path"], record["sha256"]]

    # 4. The approval's signature must be verified.
    if not _approval_verified(approval):
        codes.append(TH_REFUSED_UNVERIFIED)
        detail.append("the approval's signature is not verified")
        return verdict

    # An unreadable approval date is stale before it is anything else: the role
    # check needs the approval time, and a missing time cannot be borrowed.
    approved = _parse_date(approval.get("approvedAt"))
    expires = _parse_date(approval.get("expiresAt"))
    if approved is None:
        codes.append(TH_REFUSED_STALE_APPROVAL)
        detail.append("the approval's approvedAt is absent or not an ISO date")
        return verdict
    if expires is None:
        codes.append(TH_REFUSED_STALE_APPROVAL)
        detail.append("the approval's expiresAt is absent or not an ISO date")
        return verdict

    # 5. The role must be required and held at the approval time.
    ok, role_codes, reason = _role_verdict(approval, threshold, role_assignments)
    if not ok:
        codes.extend(role_codes)
        detail.append(reason)
        return verdict

    # 6. The approval must be for this artefact and not expired.
    expected = expected_digest if expected_digest is not None else _threshold_digest(threshold)
    got = approval.get("artefactDigest")
    if not isinstance(expected, str) or not expected:
        codes.append(TH_REFUSED_STALE_APPROVAL)
        detail.append("the threshold declares no artefact digest, so no approval is fresh")
        return verdict
    if not isinstance(got, str) or got != expected:
        codes.append(TH_REFUSED_STALE_APPROVAL)
        detail.append(
            f"the approval's artefactDigest {got!r} is not the threshold's {expected!r}"
        )
        return verdict
    if approved > moment:
        codes.append(TH_REFUSED_STALE_APPROVAL)
        detail.append(f"the approval begins at {approved} after the evaluation date {moment}")
        return verdict
    if expires < moment:
        codes.append(TH_REFUSED_STALE_APPROVAL)
        detail.append(f"the approval expired at {expires} before the evaluation date {moment}")
        return verdict

    verdict["qualified"] = True
    return verdict


def _result(
    threshold_id: str,
    outcome: str,
    codes: list[str],
    detail: list[str],
    *,
    threshold: Mapping[str, Any] | None = None,
    distinct: int = 0,
    available: int = 0,
    groups: list[dict[str, Any]] | None = None,
    aliases: list[dict[str, Any]] | None = None,
    approvals: list[dict[str, Any]] | None = None,
    moment: date | None = None,
) -> dict[str, Any]:
    return {
        "schema": EVALUATION_SCHEMA,
        "thresholdId": threshold_id,
        "threshold": {
            "id": threshold.get("id") if isinstance(threshold, Mapping) else None,
            "action": threshold.get("action") if isinstance(threshold, Mapping) else None,
            "k": threshold.get("k") if isinstance(threshold, Mapping) else None,
            "n": threshold.get("n") if isinstance(threshold, Mapping) else None,
            "requiredRoles": (
                list(threshold.get("requiredRoles") or [])
                if isinstance(threshold, Mapping) else []
            ),
            "distinctDomains": (
                threshold.get("distinctDomains") if isinstance(threshold, Mapping) else None
            ),
            "declaredAt": (
                threshold.get("declaredAt") if isinstance(threshold, Mapping) else None
            ),
            "declaredBy": (
                threshold.get("declaredBy") if isinstance(threshold, Mapping) else None
            ),
            "artefactDigest": (
                _threshold_digest(threshold) if isinstance(threshold, Mapping) else None
            ),
        },
        "at": moment.isoformat() if moment is not None else None,
        "outcome": outcome,
        "codes": _order_codes(codes),
        "detail": detail,
        "distinctDomains": distinct,
        "availableDomains": available,
        "groups": groups or [],
        "aliases": aliases or [],
        "approvals": approvals or [],
    }


def evaluate(
    threshold: Mapping[str, Any] | None,
    approvals: Any,
    domains: Any,
    role_assignments: Any,
    *,
    at: Any = None,
    artefact_digest: str | None = None,
) -> dict[str, Any]:
    """Evaluate one k-of-n threshold over distinct established trust domains.

    ``threshold`` is the declaration; ``approvals`` is the list (or document) of
    approvals; ``domains`` is the domain inventory; ``role_assignments`` are
    A14's assignment records.  ``at`` is the evaluation date; when omitted the
    declaration's ``asOf`` or ``declaredAt`` is used, never a live clock.
    ``artefact_digest`` overrides the declaration's recorded digest.
    """
    threshold_id = (
        threshold.get("id") if isinstance(threshold, Mapping) and threshold.get("id")
        else "UNRECORDED"
    )
    document = _domains_document(domains)
    index, _duplicate_records = _domain_index(document)
    available = available_domain_count(document)
    approvals_list = _approval_list(approvals)

    if at is None:
        at = None
        if isinstance(threshold, Mapping):
            at = threshold.get("asOf") or threshold.get("declaredAt")
    moment = _parse_date(at)
    if moment is None:
        moment = _parse_date("1970-01-01")

    # 1. The declaration must exist and be well-formed.
    if not _threshold_valid(threshold):
        return _result(
            threshold_id,
            OUTCOME_NOT_RUN,
            [TH_REFUSED_THRESHOLD_UNRECORDED],
            [
                "no valid threshold declaration: a declaration needs id, action, k, n, "
                "requiredRoles, distinctDomains: true, declaredAt and declaredBy; "
                "nothing was evaluated and NOT_RUN is not a pass"
            ],
            threshold=threshold,
            available=available,
            moment=moment,
        )

    assert isinstance(threshold, Mapping)

    # 2. The declaration must pre-exist the approvals and must not be amended
    #    after they exist.  A threshold that did not pre-exist is not the
    #    threshold that was met.
    approval_dates = [
        _parse_date(item.get("approvedAt"))
        for item in approvals_list
        if isinstance(item, Mapping)
    ]
    approval_dates = [value for value in approval_dates if value is not None]
    if approval_dates:
        earliest = min(approval_dates)
        declared = _parse_date(threshold.get("declaredAt"))
        if declared is not None and declared > earliest:
            return _result(
                threshold_id,
                OUTCOME_UNMET,
                [TH_REFUSED_THRESHOLD_LOWERED],
                [
                    f"the declaration is dated {declared}, after the earliest approval "
                    f"{earliest}; the k that was met is not the k recorded"
                ],
                threshold=threshold,
                available=available,
                moment=moment,
            )
        for amended in _amendment_dates(threshold):
            if amended >= earliest:
                return _result(
                    threshold_id,
                    OUTCOME_UNMET,
                    [TH_REFUSED_THRESHOLD_LOWERED],
                    [
                        f"the declaration was amended at {amended}, at or after the "
                        f"earliest approval {earliest}; a threshold changed after the "
                        "approvals were collected is not the threshold that was met"
                    ],
                    threshold=threshold,
                    available=available,
                    moment=moment,
                )

    # 3. A threshold of k is unreachable when fewer than k established domains
    #    exist at all.
    k = int(threshold.get("k"))
    if available < k:
        return _result(
            threshold_id,
            OUTCOME_UNREACHABLE,
            [TH_REFUSED_THRESHOLD_UNREACHABLE],
            [
                f"{available} established external domain(s) exist and the threshold "
                f"is k={k}; no set of approvals could meet it"
            ],
            threshold=threshold,
            distinct=0,
            available=available,
            moment=moment,
        )

    # 4. Qualify each approval, then collapse one identity to one domain.
    codes: list[str] = []
    detail: list[str] = []
    qualified: list[Mapping[str, Any]] = []
    verdicts: list[dict[str, Any]] = []
    seen_identity: dict[str, tuple[str, str]] = {}
    for approval in approvals_list:
        verdict = _check_approval(
            approval, threshold, document, index, role_assignments, moment,
            artefact_digest,
        )
        verdicts.append(verdict)
        if not verdict["qualified"]:
            codes.extend(verdict["codes"])
            detail.extend(verdict["detail"])
            continue
        identity = verdict.get("identity")
        key = tuple(verdict.get("domainKey") or ())
        previous = seen_identity.get(identity) if isinstance(identity, str) else None
        if previous is not None and previous != key:
            verdict["qualified"] = False
            verdict["codes"] = [TH_REFUSED_DUPLICATE_IDENTITY]
            verdict["detail"] = [
                f"identity {identity!r} already approved in another domain; one identity "
                "contributes at most one domain"
            ]
            codes.append(TH_REFUSED_DUPLICATE_IDENTITY)
            detail.extend(verdict["detail"])
            continue
        if isinstance(identity, str):
            seen_identity.setdefault(identity, key)
        qualified.append(approval)

    structural = distinct_domains(qualified, document)
    count = int(structural["count"])
    if structural["aliases"]:
        codes.append(TH_REFUSED_ALIASED)
        for group in structural["aliases"]:
            detail.append(
                "two labels resolve to one domain: "
                + ", ".join(sorted(group["domainIds"]))
            )
    if structural["duplicateLabels"] or structural["duplicateRecords"]:
        codes.append(TH_REFUSED_DOMAIN_DUPLICATE)
        for label in structural["duplicateLabels"]:
            detail.append(f"domain {label!r} approves in more than one counted approval")
        for label in structural["duplicateRecords"]:
            detail.append(f"the domain inventory records domainId {label!r} twice")
    if structural["duplicateIdentities"]:
        codes.append(TH_REFUSED_DUPLICATE_IDENTITY)
        for identity in structural["duplicateIdentities"]:
            detail.append(f"identity {identity!r} appears in more than one domain")

    # 5. The outcome is the conservative count against k.  A per-approval code
    #    explains why an approval did not contribute; it does not invalidate a
    #    threshold met by other, legitimate domains.
    if count >= k:
        outcome = OUTCOME_MET
    else:
        outcome = OUTCOME_UNMET
        codes.append(TH_REFUSED_INSUFFICIENT_DOMAINS)
        detail.append(
            f"{count} distinct domain(s) approved and the threshold is k={k}"
        )

    return _result(
        threshold_id,
        outcome,
        codes,
        detail,
        threshold=threshold,
        distinct=count,
        available=available,
        groups=structural["groups"],
        aliases=structural["aliases"],
        approvals=verdicts,
        moment=moment,
    )


# ---------------------------------------------------------------------------
# Loading and the command line
# ---------------------------------------------------------------------------
def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ToolError(f"cannot read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ToolError(f"cannot parse {path}: {error}") from error


def load_domains(path: Path | None = None) -> dict[str, Any]:
    document = _load_json(path or DEFAULT_DOMAINS)
    return _domains_document(document)


def load_thresholds(path: Path | None = None) -> dict[str, Any]:
    document = _load_json(path or DEFAULT_THRESHOLDS)
    if not isinstance(document, dict):
        raise ToolError(f"{path or DEFAULT_THRESHOLDS} is not an object")
    return document


def load_approvals(path: Path | None = None) -> list[Any]:
    return _approval_list(_load_json(path or DEFAULT_APPROVALS))


def load_roles(path: Path | None = None) -> list[dict[str, Any]]:
    document = _load_json(path or DEFAULT_ROLES)
    if isinstance(document, Mapping):
        document = document.get("assignments", [])
    if not isinstance(document, list):
        raise ToolError(f"{path or DEFAULT_ROLES} names no assignment list")
    return [item for item in document if isinstance(item, Mapping)]


def find_threshold(document: Mapping[str, Any], threshold_id: str) -> Mapping[str, Any] | None:
    records = document.get("thresholds")
    if not isinstance(records, list):
        return None
    for record in records:
        if isinstance(record, Mapping) and record.get("id") == threshold_id:
            return record
    return None


def _codes_text(codes: list[str]) -> str:
    return ",".join(codes) if codes else "NONE"


def _print_domains(document: Mapping[str, Any]) -> None:
    records = _domain_records(document)
    external = external_domains(document)
    candidate = document.get("candidateDomain") or "UNRECORDED"
    print(
        f"domains: recorded={len(records)} external={len(external)} "
        f"candidateDomain={candidate} code={CODE_OK} outcome={OUTCOME_NOT_RUN}"
    )
    for record in records:
        print(
            f"  domain: id={record.get('domainId')!r} kind={record.get('kind')!r} "
            f"independentOfCandidate={record.get('independentOfCandidate')!r} "
            f"establishedBy={established_by(record)}"
        )


def _print_evaluation(result: Mapping[str, Any]) -> None:
    threshold = result.get("threshold") or {}
    print(
        f"threshold: id={result.get('thresholdId')} action={threshold.get('action')} "
        f"k={threshold.get('k')} n={threshold.get('n')} "
        f"availableDomains={result.get('availableDomains')} "
        f"distinctDomains={result.get('distinctDomains')} "
        f"outcome={result.get('outcome')} codes={_codes_text(result.get('codes') or [])}"
    )
    for line in result.get("detail") or []:
        print(f"  detail: {line}")
    for group in result.get("groups") or []:
        print(
            f"  group: labels={','.join(group.get('domainIds') or [])} "
            f"identities={','.join(str(i) for i in group.get('identities') or [])} "
            f"aliased={group.get('aliased')}"
        )
    for approval in result.get("approvals") or []:
        print(
            f"  approval: identity={approval.get('identity')!r} "
            f"domainId={approval.get('domainId')!r} role={approval.get('role')!r} "
            f"qualified={approval.get('qualified')} "
            f"codes={_codes_text(approval.get('codes') or [])}"
        )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    domains_parser = sub.add_parser("domains", help="print the domain inventory")
    domains_parser.add_argument("--domains", default=None)

    count_parser = sub.add_parser("count", help="count distinct domains for one threshold")
    count_parser.add_argument("threshold")
    count_parser.add_argument("approvals")
    count_parser.add_argument("--thresholds", default=None)
    count_parser.add_argument("--domains", default=None)
    count_parser.add_argument("--roles", default=None)
    count_parser.add_argument("--at", default=None)

    evaluate_parser = sub.add_parser("evaluate", help="evaluate one recorded threshold")
    evaluate_parser.add_argument("threshold")
    evaluate_parser.add_argument("--thresholds", default=None)
    evaluate_parser.add_argument("--approvals", default=None)
    evaluate_parser.add_argument("--domains", default=None)
    evaluate_parser.add_argument("--roles", default=None)
    evaluate_parser.add_argument("--at", default=None)
    evaluate_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)

    try:
        if args.command == "domains":
            document = load_domains(Path(args.domains) if args.domains else None)
            _print_domains(document)
            return EXIT_OK

        threshold_document = load_thresholds(
            Path(args.thresholds) if args.thresholds else None
        )
        threshold = find_threshold(threshold_document, args.threshold)
        if threshold is None:
            result = _result(
                args.threshold,
                OUTCOME_NOT_RUN,
                [TH_REFUSED_THRESHOLD_UNRECORDED],
                [f"no threshold with id {args.threshold!r} is recorded"],
            )
            if getattr(args, "json", False):
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                _print_evaluation(result)
            return EXIT_REFUSED

        domains_document = load_domains(Path(args.domains) if args.domains else None)
        roles = load_roles(Path(args.roles) if args.roles else None)
        if args.command == "count":
            approvals = load_approvals(Path(args.approvals))
        else:
            approvals = load_approvals(
                Path(args.approvals) if args.approvals else None
            )
        result = evaluate(
            threshold, approvals, domains_document, roles, at=args.at
        )
        if getattr(args, "json", False):
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.command == "count":
            print(
                f"count: threshold={args.threshold} "
                f"count={result['distinctDomains']} "
                f"availableDomains={result['availableDomains']} "
                f"outcome={result['outcome']} "
                f"codes={_codes_text(result['codes'])}"
            )
            for group in result.get("groups") or []:
                print(
                    f"  group: labels={','.join(group.get('domainIds') or [])} "
                    f"identities={','.join(str(i) for i in group.get('identities') or [])} "
                    f"aliased={group.get('aliased')}"
                )
            for line in result.get("detail") or []:
                print(f"  detail: {line}")
        else:
            _print_evaluation(result)
        return EXIT_OK if result["outcome"] == OUTCOME_MET else EXIT_REFUSED
    except ToolError as error:
        print(f"{CODE_USAGE}: {error}")
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
