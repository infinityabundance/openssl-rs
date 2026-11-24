#!/usr/bin/env python3
"""suppression_governance.py -- a suppressed finding remains a finding.

The normative document is `docs/SUPPRESSION-GOVERNANCE.md`. This module implements
the rule it states: a suppression is a **disposition of a finding that is still in
the population**, never an absence. A suppression that cannot name the identity it
targets, the members it disposes of, its justification, its reviewer, the time it
was made, its expiry and its policy basis is not a governed suppression -- it is a
finding made to disappear without a record, and it is refused.

What this module does
---------------------
* `Suppression` carries one recorded suppression verbatim: the target identity and
  the kind of identity it is (rule, logical or exact), the scope the suppression is
  authorised at, the justification, the reviewer token and where that token is
  recorded, the time it was made, the expiry (or an explicit unbounded claim), the
  policy basis, the members it disposes of, and the disposition it declares.
* `admit(record)` derives the disposition the recorded fields support and returns
  the stable refusal codes for every required field the record does not establish.
  A record with any refusal code is `NON_ACTIONABLE`: it suppresses nothing.
* `invalidate(record, trigger)` returns the new disposition and a reason that cites
  the identity which changed. It never deletes the finding or the record.
* `reconcile(population, records)` returns `(population, suppressed, unsuppressed,
  dispositions)` and refuses `SG_REFUSED_SUPPRESSION_AS_ABSENCE` when a finding the
  register claims to suppress is not still in the population, and
  `SG_REFUSED_COUNT_UNBALANCED` when the totals do not reconcile.
* `build_register(repo_root)` reads every real suppression-shaped record in a
  tracked record and returns the register, with fields preserved verbatim.
* `build_controls(...)` builds one in-memory control per refusal code and per
  invalidation trigger. A control proves the refusal fires; it is not a source
  change and not a defect report.

What this module does not do
----------------------------
It does not decide whether a suppressed finding is true, severe or reachable. An
`ACTIVE` suppression does not make a finding false, and an `INVALIDATED` one does
not make it not exist (Article 1). It does not decide whether a reviewer is
independent; it checks that the token is recorded, and Article 5 remains a separate
obligation. It does not read the scanner or regenerate any suppression member: a
member population that the record does not carry is absent, not reconstructed.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

MODEL_ID = "a6/v1"
SUPPRESSIONS_SCHEMA = "openssl-rs/a6/suppressions/1"
INVALIDATION_SCHEMA = "openssl-rs/a6/invalidation/1"
CONTROLS_SCHEMA = "openssl-rs/a6/controls/1"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTER = Path("evidence/a6/SUPPRESSIONS.json")
DEFAULT_POPULATION = Path("evidence/a1/SARIF.json")

# --------------------------------------------------------------------------
# Dispositions. Every disposition keeps its finding in the population.
# --------------------------------------------------------------------------

D_ACTIVE = "ACTIVE"
D_EXPIRED = "EXPIRED"
D_INVALIDATED = "INVALIDATED"
D_NON_ACTIONABLE = "NON_ACTIONABLE"
D_PENDING_REVIEW = "PENDING_REVIEW"

DISPOSITIONS = (D_ACTIVE, D_EXPIRED, D_INVALIDATED, D_NON_ACTIONABLE, D_PENDING_REVIEW)

# disposition -> (what it licenses, what it does not license)
DISPOSITION_MEANINGS = {
    D_ACTIVE: (
        "the suppression's recorded fields are all established and it disposes of "
        "its member findings, which remain in the population",
        "that the finding is false, fixed, unreachable or safe; an ACTIVE "
        "suppression is an accepted disposition, not a result",
    ),
    D_EXPIRED: (
        "the suppression was valid until its recorded expiry and no longer "
        "authorises a disposition; the finding is still in the population",
        "that the suppression never existed; the record and its history remain",
    ),
    D_INVALIDATED: (
        "a recorded trigger changed the identity the suppression was bound to; the "
        "finding is still in the population and the record states why it no longer "
        "authorises a disposition",
        "that the finding entered or left the population; invalidation is a "
        "disposition of the suppression, not of the finding",
    ),
    D_NON_ACTIONABLE: (
        "the record cannot be read as a governed suppression because a required "
        "field is missing or contradicted; the findings it names remain in the "
        "population and are unsuppressed",
        "that the record is absent, or that its findings are absent; the record is "
        "present and refused",
    ),
    D_PENDING_REVIEW: (
        "the record was submitted and no review has established it; the finding "
        "remains in the population and is not suppressed",
        "a provisional acceptance; a pending suppression authorises nothing",
    ),
}

# --------------------------------------------------------------------------
# Target kinds and authorised scopes.
# --------------------------------------------------------------------------

T_RULE = "rule"
T_LOGICAL = "logical"
T_EXACT = "exact"
T_NONE = "none"
TARGET_KINDS = (T_RULE, T_LOGICAL, T_EXACT, T_NONE)

SCOPE_EXACT = "exact"
SCOPE_LOGICAL = "logical"
SCOPE_RULE = "rule"
SCOPES = (SCOPE_EXACT, SCOPE_LOGICAL, SCOPE_RULE)

SCOPE_RANK = {SCOPE_EXACT: 0, SCOPE_LOGICAL: 1, SCOPE_RULE: 2}
TARGET_RANK = {T_EXACT: 0, T_LOGICAL: 1, T_RULE: 2, T_NONE: -1}

C_SUPPRESSION = "suppression"
C_NOT_A_SUPPRESSION = "not-a-suppression"
C_CONTROL_FIXTURE = "control-fixture"
CLASSIFICATIONS = (C_SUPPRESSION, C_NOT_A_SUPPRESSION, C_CONTROL_FIXTURE)

# --------------------------------------------------------------------------
# Refusal codes. A code is stable: a document, receipt and test cite it verbatim.
# --------------------------------------------------------------------------

R_AS_ABSENCE = "SG_REFUSED_SUPPRESSION_AS_ABSENCE"
R_NO_MEMBERS = "SG_REFUSED_NO_MEMBER_IDENTITIES"
R_NO_JUSTIFICATION = "SG_REFUSED_NO_JUSTIFICATION"
R_NO_REVIEWER = "SG_REFUSED_NO_REVIEWER"
R_UNRECORDED_REVIEWER = "SG_REFUSED_UNRECORDED_REVIEWER"
R_NO_EXPIRY = "SG_REFUSED_NO_EXPIRY"
R_EXPIRED = "SG_REFUSED_EXPIRED"
R_UNBOUNDED_SCOPE = "SG_REFUSED_UNBOUNDED_SCOPE"
R_LOGICAL_AS_EXACT = "SG_REFUSED_LOGICAL_AS_EXACT"
R_CROSS_ARTEFACT = "SG_REFUSED_CROSS_ARTEFACT_INHERITANCE"
R_STALE_CANDIDATE = "SG_REFUSED_STALE_CANDIDATE"
R_TARGET_ABSENT = "SG_REFUSED_TARGET_NOT_IN_POPULATION"
R_INVALIDATED = "SG_REFUSED_INVALIDATED"
R_COUNT_UNBALANCED = "SG_REFUSED_COUNT_UNBALANCED"

# code -> (the condition it refuses, the wrong conclusion it prevents)
REFUSALS = {
    R_AS_ABSENCE: (
        "a suppressed finding is dropped from the finding population, or counted as "
        "absent because it is suppressed",
        "that suppressing a finding removes it; a suppression is a disposition of a "
        "finding that is still there, so removing it makes the population and the "
        "register disagree while the total appears to fall",
    ),
    R_NO_MEMBERS: (
        "the record states a suppression total but records no member identity, or "
        "records member locators that are not the findings it disposes of",
        "that an aggregate is a census: a number with no member row cannot be "
        "reviewed, re-read, deduplicated or checked, and the suppressed findings "
        "cannot be named",
    ),
    R_NO_JUSTIFICATION: (
        "the record states no reason the suppression is acceptable",
        "that a suppression is justified because it exists, and that a remediation "
        "plan (`would_close`) is a reason the present state is acceptable",
    ),
    R_NO_REVIEWER: (
        "the record names nobody who reviewed the suppression",
        "that a suppression was reviewed because it was written down; an author's "
        "own record is not a review",
    ),
    R_UNRECORDED_REVIEWER: (
        "the reviewer token is not established by any tracked record as a reviewer",
        "that a role description (`decision-maker`, `the principal`) is a reviewer "
        "identity; a token no record establishes cannot be checked, and an invented "
        "reviewer is a false independence claim",
    ),
    R_NO_EXPIRY: (
        "the record states no expiry, or explicitly declares the suppression "
        "unbounded",
        "that a permanent suppression is a governed one; without an expiry the "
        "suppression never re-enters review and a stale acceptance is read as current",
    ),
    R_EXPIRED: (
        "the suppression's recorded expiry is at or before the evaluation date but "
        "it is presented as active",
        "that a lapsed suppression still authorises a disposition; an expired "
        "acceptance is history, not current state",
    ),
    R_UNBOUNDED_SCOPE: (
        "the authorised scope is broader than the identity the record targets",
        "that a suppression of one occurrence, or of one logical finding, authorises "
        "a rule, an artefact or a tree; the suppression then covers findings it never "
        "named",
    ),
    R_LOGICAL_AS_EXACT: (
        "a suppression whose target is a logical identity is used to authorise an "
        "exact occurrence",
        "that one occurrence's disposition transfers to a different occurrence of "
        "the same logical finding, including a new occurrence after code motion",
    ),
    R_CROSS_ARTEFACT: (
        "a suppression is applied to a member bound to a different artefact than the "
        "one it records",
        "that a suppression of a finding in one artefact disposes of a finding in "
        "another; an exact identity names one binding",
    ),
    R_STALE_CANDIDATE: (
        "the suppression's candidate identity is not recorded, or differs from the "
        "candidate under evaluation",
        "that an acceptance made at one candidate governs another; a candidate change "
        "invalidates the suppression before any member is considered",
    ),
    R_TARGET_ABSENT: (
        "the record names no target identity, or the target is not present in the "
        "finding population",
        "that a suppression targets a finding that exists; a target no population "
        "contains cannot be disposed of, and a suppression of the whole tree targets "
        "everything",
    ),
    R_INVALIDATED: (
        "the record's recorded disposition is INVALIDATED, or a recorded invalidation "
        "trigger fired",
        "that an invalidated suppression remains in force, or that invalidation "
        "deleted the finding or the suppression record",
    ),
    R_COUNT_UNBALANCED: (
        "the disposition totals do not reconcile with the finding population: a "
        "member is counted twice, a stated member count disagrees with the member "
        "list, or suppressed plus unsuppressed does not equal the population",
        "that the register accounts for the population when its parts do not add up",
    ),
}

# --------------------------------------------------------------------------
# Invalidation triggers.
# --------------------------------------------------------------------------

TR_CANDIDATE = "candidate-identity-change"
TR_SOURCE_TREE = "source-tree-digest-change"
TR_TOOL = "tool-identity-change"
TR_EXPIRY = "expiry"
TR_TARGET_ABSENT = "target-absent-from-population"
TR_NEW_OCCURRENCE = "new-occurrence-at-logical-identity"
TR_POLICY = "policy-basis-change"
TRIGGERS = (
    TR_CANDIDATE,
    TR_SOURCE_TREE,
    TR_TOOL,
    TR_EXPIRY,
    TR_TARGET_ABSENT,
    TR_NEW_OCCURRENCE,
    TR_POLICY,
)

# trigger -> (the identity that changes, the disposition it produces, what it prevents)
TRIGGER_MEANINGS = {
    TR_CANDIDATE: (
        "the candidate identity the suppression was recorded against",
        D_INVALIDATED,
        "an acceptance at one candidate governing another",
    ),
    TR_SOURCE_TREE: (
        "the digest of the source tree the finding was observed in",
        D_INVALIDATED,
        "a disposition surviving an edit to the tree it was made about",
    ),
    TR_TOOL: (
        "the identity of the tool or instrument that produced the finding",
        D_INVALIDATED,
        "a disposition surviving a change to the analyser that justified it",
    ),
    TR_EXPIRY: (
        "the suppression's recorded expiry date",
        D_EXPIRED,
        "a lapsed acceptance being read as current",
    ),
    TR_TARGET_ABSENT: (
        "the target identity's presence in the current finding population",
        D_INVALIDATED,
        "a suppression of a finding that is no longer in the population",
    ),
    TR_NEW_OCCURRENCE: (
        "a new exact occurrence at the suppression's logical identity",
        D_INVALIDATED,
        "one occurrence's acceptance transferring to a new occurrence of the same "
        "logical finding",
    ),
    TR_POLICY: (
        "the policy basis the suppression was authorised under",
        D_INVALIDATED,
        "an acceptance surviving the policy that permitted it",
    ),
}

STATUS_FIRED = "FIRED"
STATUS_NOT_FIRED = "NOT_FIRED"
STATUS_NOT_RUN = "NOT_RUN"

DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class Refusal(Exception):
    """A stable, citable refusal. `str(refusal)` is `CODE: detail`."""

    def __init__(self, code: str, detail: str) -> None:
        if code not in REFUSALS:
            raise ValueError(f"unknown refusal code {code!r}")
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(Path(path).read_bytes())


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", str(repo), *args],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise Refusal(
            R_STALE_CANDIDATE,
            f"git {' '.join(args)} failed, so the candidate under evaluation is "
            f"unknown: {result.stderr.decode('utf-8', 'replace').strip()}",
        )
    return result.stdout.decode("utf-8").strip()


def candidate_identity(repo: Path) -> "CurrentIdentity":
    """The candidate under evaluation, read from Git rather than assumed."""
    head = _git(repo, "rev-parse", "HEAD")
    as_of = _git(repo, "show", "-s", "--format=%cs", "HEAD")
    tool = Path(repo) / "forensics" / "tools" / "unsafe_obligations.py"
    token = f"forensics/tools/unsafe_obligations.py@{digest_file(tool)}"
    return CurrentIdentity(candidate=head, tool=token, as_of=as_of,
                           detail="the candidate whose suppressions are evaluated in "
                                  "this document")


# --------------------------------------------------------------------------
# The suppression record
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Suppression:
    """One recorded suppression, with the fields the record actually states."""

    id: str
    record: str
    locator: str
    record_sha256: str
    classification: str = C_SUPPRESSION
    reason: str = ""
    target_scope: str = T_NONE
    target_identity: str | None = None
    target_rule: str | None = None
    scope: str = SCOPE_RULE
    justification: str = ""
    reviewer: str | None = None
    reviewer_recorded_in: str | None = None
    recorded_at: str = ""
    expires_at: str | None = None
    unbounded: bool = False
    policy_basis: str = ""
    policy_token: str | None = None
    member_ids: tuple[str, ...] = ()
    members_recorded: bool = False
    member_count: int | None = None
    member_count_basis: str = ""
    candidate: str | None = None
    source_tree: str | None = None
    tool: str | None = None
    artefact: dict | None = None
    logical_identity: str | None = None
    claimed_absent: bool = False
    disposition: str = D_ACTIVE
    invalidation: tuple[dict, ...] = ()
    recorded_fields: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("a suppression has no id")
        if self.classification not in CLASSIFICATIONS:
            raise ValueError(
                f"{self.id}: classification {self.classification!r} is not one of "
                f"{CLASSIFICATIONS}"
            )
        if self.classification != C_SUPPRESSION and not self.reason.strip():
            raise ValueError(
                f"{self.id}: a record that is not a suppression must state why"
            )
        if self.target_scope not in TARGET_KINDS:
            raise ValueError(
                f"{self.id}: target scope {self.target_scope!r} is not one of "
                f"{TARGET_KINDS}"
            )
        if self.scope not in SCOPES:
            raise ValueError(f"{self.id}: scope {self.scope!r} is not one of {SCOPES}")
        if self.disposition not in DISPOSITIONS:
            raise ValueError(
                f"{self.id}: disposition {self.disposition!r} is not one of "
                f"{DISPOSITIONS}"
            )
        if self.expires_at is not None and not DATE_PATTERN.match(self.expires_at):
            raise ValueError(
                f"{self.id}: expiresAt {self.expires_at!r} is not an ISO date"
            )
        if self.member_count is not None and (
            not isinstance(self.member_count, int) or self.member_count < 0
        ):
            raise ValueError(f"{self.id}: memberCount is not a non-negative count")
        if self.artefact is not None:
            if not isinstance(self.artefact, dict) or not self.artefact.get("uri"):
                raise ValueError(f"{self.id}: artefact names no uri")

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "classification": self.classification,
            "reason": self.reason,
            "record": self.record,
            "locator": self.locator,
            "recordSha256": self.record_sha256,
            "target": {
                "scope": self.target_scope,
                "identity": self.target_identity,
                "ruleId": self.target_rule,
            },
            "authorisedScope": self.scope,
            "justification": self.justification,
            "reviewer": self.reviewer,
            "reviewerRecordedIn": self.reviewer_recorded_in,
            "recordedAt": self.recorded_at,
            "expiresAt": self.expires_at,
            "unbounded": self.unbounded,
            "policyBasis": self.policy_basis,
            "policyToken": self.policy_token,
            "memberIds": list(self.member_ids),
            "membersRecorded": self.members_recorded,
            "memberCount": self.member_count,
            "memberCountBasis": self.member_count_basis,
            "candidate": self.candidate,
            "sourceTree": self.source_tree,
            "tool": self.tool,
            "artefact": self.artefact,
            "logicalIdentity": self.logical_identity,
            "claimedAbsent": self.claimed_absent,
            "declaredDisposition": self.disposition,
            "invalidation": list(self.invalidation),
            "recordedFields": self.recorded_fields,
        }

    @classmethod
    def from_dict(cls, item: dict) -> "Suppression":
        required = (
            "id", "classification", "reason", "record", "locator", "recordSha256",
            "target", "authorisedScope", "justification", "reviewer",
            "reviewerRecordedIn", "recordedAt", "expiresAt", "unbounded",
            "policyBasis", "memberIds", "membersRecorded", "declaredDisposition",
        )
        missing = [key for key in required if key not in item]
        if missing:
            raise Refusal(
                R_NO_MEMBERS if "memberIds" in missing else R_TARGET_ABSENT,
                f"the suppression record is missing required field(s) {missing}",
            )
        target = item["target"]
        if not isinstance(target, dict) or "scope" not in target:
            raise Refusal(R_TARGET_ABSENT, "the target is not an object with a scope")
        return cls(
            id=item["id"],
            record=item["record"],
            locator=item["locator"],
            record_sha256=item["recordSha256"],
            classification=item["classification"],
            reason=item["reason"],
            target_scope=target["scope"],
            target_identity=target.get("identity"),
            target_rule=target.get("ruleId"),
            scope=item["authorisedScope"],
            justification=item["justification"],
            reviewer=item["reviewer"],
            reviewer_recorded_in=item["reviewerRecordedIn"],
            recorded_at=item["recordedAt"],
            expires_at=item["expiresAt"],
            unbounded=item["unbounded"],
            policy_basis=item["policyBasis"],
            policy_token=item.get("policyToken"),
            member_ids=tuple(item["memberIds"]),
            members_recorded=item["membersRecorded"],
            member_count=item.get("memberCount"),
            member_count_basis=item.get("memberCountBasis", ""),
            candidate=item.get("candidate"),
            source_tree=item.get("sourceTree"),
            tool=item.get("tool"),
            artefact=item.get("artefact"),
            logical_identity=item.get("logicalIdentity"),
            claimed_absent=item.get("claimedAbsent", False),
            disposition=item["declaredDisposition"],
            invalidation=tuple(item.get("invalidation", ())),
            recorded_fields=item.get("recordedFields", {}),
        )


# --------------------------------------------------------------------------
# The finding population and the candidate under evaluation
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingPopulation:
    """The findings that exist at the candidate under evaluation.

    `exact`, `logical` and `rule` are the three identity sets from
    `finding_identity.py`. A suppressed finding is a member of `exact`; being
    suppressed never removes it.
    """

    id: str
    record: str
    record_sha256: str
    exact: tuple[str, ...]
    logical: tuple[str, ...]
    rule: tuple[str, ...]
    bindings: Mapping[str, dict] = field(default_factory=dict)
    expected: int | None = None

    def __post_init__(self) -> None:
        if self.expected is not None and self.expected != len(self.exact):
            raise Refusal(
                R_COUNT_UNBALANCED,
                f"{self.id}: the record states {self.expected} findings but "
                f"{len(self.exact)} exact identities were enumerated",
            )
        if len(set(self.exact)) != len(self.exact):
            raise Refusal(
                R_COUNT_UNBALANCED,
                f"{self.id}: the exact identity list contains a duplicate",
            )

    def contains(self, kind: str, identity: str | None) -> bool:
        if not identity:
            return False
        if kind == T_EXACT:
            return identity in self.exact
        if kind == T_LOGICAL:
            return identity in self.logical
        if kind == T_RULE:
            return identity in self.rule
        return False

    def summary(self) -> dict:
        stream = "\n".join(sorted(self.exact)).encode("utf-8")
        return {
            "id": self.id,
            "record": self.record,
            "recordSha256": self.record_sha256,
            "expected": self.expected,
            "results": len(self.exact),
            "distinctExact": len(set(self.exact)),
            "distinctLogical": len(set(self.logical)),
            "distinctRule": len(set(self.rule)),
            "exactStreamSha256": digest_bytes(stream),
        }


@dataclass(frozen=True)
class CurrentIdentity:
    """The identity the suppression is evaluated against, read from records."""

    candidate: str | None = None
    source_tree: str | None = None
    tool: str | None = None
    policy_basis: str | None = None
    new_occurrence_logical: str | None = None
    new_occurrence_exact: str | None = None
    as_of: str | None = None
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "candidate": self.candidate,
            "sourceTree": self.source_tree,
            "tool": self.tool,
            "policyBasis": self.policy_basis,
            "newOccurrenceLogical": self.new_occurrence_logical,
            "newOccurrenceExact": self.new_occurrence_exact,
            "asOf": self.as_of,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------
# Admission: the disposition the recorded fields support
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Admission:
    suppression_id: str
    classification: str
    declared_disposition: str
    disposition: str
    codes: tuple[str, ...]
    detail: str
    member_count: int

    @property
    def actionable(self) -> bool:
        return self.disposition == D_ACTIVE and not self.codes

    def as_dict(self) -> dict:
        return {
            "id": self.suppression_id,
            "classification": self.classification,
            "declaredDisposition": self.declared_disposition,
            "disposition": self.disposition,
            "codes": list(self.codes),
            "memberCount": self.member_count,
            "actionable": self.actionable,
            "detail": self.detail,
        }


def _tool_name(token: str | None) -> str | None:
    if not token:
        return None
    return token.split("@", 1)[0]


def admit(
    record: Suppression,
    *,
    population: FindingPopulation | None = None,
    reviewers: Mapping[str, Iterable[str]] | None = None,
    as_of: str | None = None,
    current: CurrentIdentity | None = None,
) -> Admission:
    """Derive the disposition the record supports and the refusal codes.

    A record with any code is `NON_ACTIONABLE`: it authorises nothing. The order of
    the codes is fixed so the recorded bytes are deterministic.
    """
    if record.classification != C_SUPPRESSION:
        return Admission(
            suppression_id=record.id,
            classification=record.classification,
            declared_disposition=record.disposition,
            disposition=D_NON_ACTIONABLE,
            codes=(),
            detail=f"not a suppression in this model: {record.reason}",
            member_count=record.member_count or 0,
        )

    codes: list[str] = []
    factors: list[str] = []

    if record.claimed_absent:
        codes.append(R_AS_ABSENCE)
        factors.append("the record counts its suppressed findings as absent")

    target_present = True
    if record.target_scope == T_NONE or not record.target_identity:
        target_present = False
    elif population is not None:
        target_present = population.contains(record.target_scope, record.target_identity)
    if not target_present:
        codes.append(R_TARGET_ABSENT)
        factors.append(
            "no target identity is recorded"
            if record.target_scope == T_NONE or not record.target_identity
            else "the target is not in the finding population"
        )

    if not record.members_recorded or not record.member_ids:
        codes.append(R_NO_MEMBERS)
        factors.append("the record states no member identity")

    if not record.justification.strip():
        codes.append(R_NO_JUSTIFICATION)
        factors.append("no justification is recorded")

    if not record.reviewer:
        codes.append(R_NO_REVIEWER)
        factors.append("no reviewer is recorded")
    elif reviewers is not None and record.reviewer not in reviewers:
        codes.append(R_UNRECORDED_REVIEWER)
        factors.append(
            f"the reviewer token {record.reviewer!r} is not established by a tracked "
            "record as a reviewer"
        )

    if record.expires_at is None or record.unbounded:
        codes.append(R_NO_EXPIRY)
        factors.append(
            "the suppression declares itself unbounded"
            if record.unbounded
            else "no expiry is recorded"
        )
    elif as_of is not None and record.expires_at <= as_of:
        codes.append(R_EXPIRED)
        factors.append(
            f"expiresAt {record.expires_at} is at or before the evaluation date {as_of}"
        )

    if SCOPE_RANK[record.scope] > TARGET_RANK[record.target_scope]:
        codes.append(R_UNBOUNDED_SCOPE)
        factors.append(
            f"the authorised scope {record.scope!r} is broader than the target "
            f"{record.target_scope!r}"
        )

    if record.scope == SCOPE_EXACT and record.target_scope == T_LOGICAL:
        codes.append(R_LOGICAL_AS_EXACT)
        factors.append(
            "an exact occurrence is authorised by a logical target, so a second "
            "exact occurrence at the same logical identity would inherit it"
        )

    if record.artefact is not None and record.member_ids and population is not None:
        for member in record.member_ids:
            binding = population.bindings.get(member)
            if binding is None:
                continue
            if (
                binding.get("uri") != record.artefact.get("uri")
                or binding.get("digest") != record.artefact.get("digest")
                or binding.get("digestScope") != record.artefact.get("digestScope")
            ):
                codes.append(R_CROSS_ARTEFACT)
                factors.append(
                    f"member {member[:12]} is bound to {binding.get('uri')!r} but the "
                    f"suppression records {record.artefact.get('uri')!r}"
                )
                break

    if record.candidate is None:
        codes.append(R_STALE_CANDIDATE)
        factors.append("no candidate identity is recorded, so the suppression is unbound")
    elif current is not None and current.candidate and record.candidate != current.candidate:
        codes.append(R_STALE_CANDIDATE)
        factors.append(
            f"candidate {record.candidate} is not the candidate under evaluation "
            f"{current.candidate}"
        )

    if record.disposition == D_INVALIDATED or record.invalidation:
        codes.append(R_INVALIDATED)
        factors.append("the record states an invalidation")

    if record.disposition == D_INVALIDATED:
        disposition = D_INVALIDATED
    elif R_INVALIDATED in codes:
        disposition = D_INVALIDATED
    elif R_EXPIRED in codes:
        disposition = D_EXPIRED
    elif record.disposition == D_PENDING_REVIEW and not codes:
        disposition = D_PENDING_REVIEW
    elif codes:
        disposition = D_NON_ACTIONABLE
    else:
        disposition = D_ACTIVE

    detail = (
        f"{record.id}: {disposition} at {record.target_scope} scope"
        if not factors
        else f"{record.id}: {disposition}; " + "; ".join(factors)
    )
    return Admission(
        suppression_id=record.id,
        classification=record.classification,
        declared_disposition=record.disposition,
        disposition=disposition,
        codes=tuple(codes),
        detail=detail,
        member_count=len(record.member_ids) if record.member_ids else (record.member_count or 0),
    )


# --------------------------------------------------------------------------
# Invalidation
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Invalidation:
    trigger: str
    status: str
    disposition: str
    reason: str
    changed_identity: str | None

    @property
    def fired(self) -> bool:
        return self.status == STATUS_FIRED

    def as_dict(self) -> dict:
        return {
            "trigger": self.trigger,
            "status": self.status,
            "disposition": self.disposition,
            "reason": self.reason,
            "changedIdentity": self.changed_identity,
        }


def _fired(record: Suppression, trigger: str, reason: str, changed: str,
           disposition: str) -> Invalidation:
    return Invalidation(trigger, STATUS_FIRED, disposition, reason, changed)


def _not_fired(record: Suppression, trigger: str, reason: str) -> Invalidation:
    return Invalidation(trigger, STATUS_NOT_FIRED, record.disposition, reason, None)


def _not_run(record: Suppression, trigger: str, reason: str) -> Invalidation:
    return Invalidation(trigger, STATUS_NOT_RUN, record.disposition, reason, None)


def invalidate(
    record: Suppression,
    trigger: str,
    *,
    current: CurrentIdentity | None = None,
    population: FindingPopulation | None = None,
    as_of: str | None = None,
) -> Invalidation:
    """Record what a trigger does to the suppression. Never deletes anything."""
    if trigger not in TRIGGERS:
        raise ValueError(f"{trigger!r} is not an invalidation trigger")
    if record.classification != C_SUPPRESSION:
        return _not_run(record, trigger, "the record is not a suppression in this model")
    current = current or CurrentIdentity()

    if trigger == TR_CANDIDATE:
        now = current.candidate
        if now is None:
            return _not_run(record, trigger,
                            "the current candidate identity is not available")
        if record.candidate is None:
            return _fired(
                record, trigger,
                f"candidate identity changed: recorded none (unbound) != current {now}",
                now, D_INVALIDATED,
            )
        if record.candidate != now:
            return _fired(
                record, trigger,
                f"candidate identity changed: recorded {record.candidate} != "
                f"current {now}",
                now, D_INVALIDATED,
            )
        return _not_fired(record, trigger,
                          f"the candidate is unchanged: {now}")

    if trigger == TR_SOURCE_TREE:
        now = current.source_tree
        if now is None:
            return _not_run(record, trigger,
                            "the current source-tree digest was not recomputed")
        if record.source_tree is None:
            return _fired(
                record, trigger,
                f"source-tree digest changed: recorded none != current {now}",
                now, D_INVALIDATED,
            )
        if record.source_tree != now:
            return _fired(
                record, trigger,
                f"source-tree digest changed: recorded {record.source_tree} != "
                f"current {now}",
                now, D_INVALIDATED,
            )
        return _not_fired(record, trigger,
                          f"the source-tree digest is unchanged: {now}")

    if trigger == TR_TOOL:
        now = current.tool
        if now is None:
            return _not_run(record, trigger,
                            "the current instrument identity is not available")
        if record.tool is None:
            return _not_run(
                record, trigger,
                "no instrument identity is recorded, and the current identity names a "
                "different instrument; a comparison would be invalid",
            )
        if _tool_name(record.tool) != _tool_name(now):
            return _not_run(
                record, trigger,
                f"the record names {_tool_name(record.tool)!r} and the current "
                f"identity is {_tool_name(now)!r}; the two are not the same "
                "instrument and a comparison would be invalid",
            )
        if record.tool != now:
            return _fired(
                record, trigger,
                f"instrument identity changed: recorded {record.tool} != "
                f"current {now}",
                now, D_INVALIDATED,
            )
        return _not_fired(record, trigger,
                          f"the instrument identity is unchanged: {now}")

    if trigger == TR_EXPIRY:
        date = as_of or current.as_of
        if record.expires_at is None:
            return _not_run(
                record, trigger,
                "no expiry is recorded, so the expiry trigger cannot fire; "
                f"{R_NO_EXPIRY} applies instead",
            )
        if date is None:
            return _not_run(record, trigger, "no evaluation date is available")
        if record.expires_at <= date:
            return _fired(
                record, trigger,
                f"expiry passed: recorded expiresAt {record.expires_at} <= "
                f"as-of {date}",
                record.expires_at, D_EXPIRED,
            )
        return _not_fired(
            record, trigger,
            f"not expired: recorded expiresAt {record.expires_at} > as-of {date}",
        )

    if trigger == TR_TARGET_ABSENT:
        if population is None:
            return _not_run(record, trigger, "no finding population is supplied")
        present = (
            record.target_scope != T_NONE
            and bool(record.target_identity)
            and population.contains(record.target_scope, record.target_identity)
        )
        if not present:
            if record.target_scope == T_NONE or not record.target_identity:
                reason = (
                    f"target identity absent from {population.id}: the record names no "
                    "target identity"
                )
                changed = "none"
            else:
                reason = (
                    f"target identity absent from {population.id}: recorded "
                    f"{record.target_scope} {record.target_identity}"
                )
                changed = record.target_identity
            return _fired(record, trigger, reason, changed, D_INVALIDATED)
        return _not_fired(
            record, trigger,
            f"the target {record.target_identity} is present in {population.id}",
        )

    if trigger == TR_NEW_OCCURRENCE:
        if record.logical_identity is None:
            return _not_run(
                record, trigger,
                "no logical identity is recorded, so a new occurrence at it cannot "
                "be detected",
            )
        now = current.new_occurrence_logical
        if now is None:
            return _not_run(record, trigger, "no new occurrence is supplied")
        if now != record.logical_identity:
            return _not_fired(
                record, trigger,
                f"the supplied occurrence is at {now}, not the recorded logical "
                f"identity {record.logical_identity}",
            )
        if (
            record.target_scope == T_EXACT
            and current.new_occurrence_exact
            and current.new_occurrence_exact == record.target_identity
        ):
            return _not_fired(
                record, trigger,
                "the supplied exact occurrence is the one the suppression targets",
            )
        return _fired(
            record, trigger,
            f"a new exact occurrence {current.new_occurrence_exact or 'not stated'} "
            f"appeared at logical identity {record.logical_identity}; the suppression "
            f"targets {record.target_scope} {record.target_identity}",
            current.new_occurrence_exact, D_INVALIDATED,
        )

    # policy
    if record.policy_token is None:
        return _not_run(record, trigger,
                        "no policy-basis identity is recorded for the suppression")
    now = current.policy_basis
    if now is None:
        return _not_run(record, trigger,
                        "the current policy-basis identity is not supplied")
    if record.policy_token != now:
        return _fired(
            record, trigger,
            f"policy basis changed: recorded {record.policy_token} != current {now}",
            now, D_INVALIDATED,
        )
    return _not_fired(record, trigger,
                      f"the policy basis is unchanged: {now}")


def apply_invalidation(record: Suppression, invalidation: Invalidation) -> Suppression:
    """The record after a fired trigger, with the reason preserved.

    The finding is untouched and the prior record is recoverable: the invalidation
    is appended, not substituted (Article 10).
    """
    if not invalidation.fired:
        return record
    return dataclasses.replace(
        record,
        disposition=invalidation.disposition,
        invalidation=tuple(record.invalidation) + (invalidation.as_dict(),),
    )


# --------------------------------------------------------------------------
# Reconciliation
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Reconciliation:
    population_id: str
    expected: int | None
    enumerated: int
    suppressed: tuple[str, ...]
    unsuppressed: tuple[str, ...]
    dispositions: Mapping[str, str]
    codes: tuple[str, ...]

    @property
    def by_disposition(self) -> dict[str, int]:
        counts = {disposition: 0 for disposition in DISPOSITIONS}
        for disposition in self.dispositions.values():
            counts[disposition] += 1
        return counts

    @property
    def balanced(self) -> bool:
        return len(self.suppressed) + len(self.unsuppressed) == self.enumerated

    def summary(self) -> dict:
        return {
            "population": self.population_id,
            "expected": self.expected,
            "enumerated": self.enumerated,
            "suppressed": len(self.suppressed),
            "unsuppressed": len(self.unsuppressed),
            "suppressedStreamSha256": digest_bytes(
                "\n".join(sorted(self.suppressed)).encode("utf-8")
            ),
            "dispositions": dict(sorted(self.dispositions.items())),
            "byDisposition": self.by_disposition,
            "codes": list(self.codes),
            "balanced": self.balanced,
        }


def reconcile(
    population: FindingPopulation,
    records: Iterable[Suppression],
    *,
    reviewers: Mapping[str, Iterable[str]] | None = None,
    as_of: str | None = None,
    current: CurrentIdentity | None = None,
) -> Reconciliation:
    """Return `(population, suppressed, unsuppressed, dispositions)` and refuse an
    unbalanced or absence-shaped reconciliation.

    A suppression of a finding that is not in the population is refused with
    `SG_REFUSED_SUPPRESSION_AS_ABSENCE`: the register cannot dispose of a finding
    that is not still there, and a population that omits it is not the population
    the register describes.
    """
    records = list(records)

    # The absence check is made against the population as supplied and against the
    # record's **declared** disposition: a record that claims to suppress a finding
    # must not be reconciled with a population that omits it. A deliberate
    # `invalidate(target-absent-from-population)` sets the declared disposition to
    # INVALIDATED and is the recorded path for a finding that really left.
    for record in records:
        if record.disposition != D_ACTIVE:
            continue
        for member in record.member_ids:
            if member not in population.exact:
                raise Refusal(
                    R_AS_ABSENCE,
                    f"{record.id} disposes of {member}, which is not in "
                    f"{population.id}; a suppressed finding is still a finding, so a "
                    "population that omits it cannot be reconciled with the register",
                )

    admissions = [
        admit(record, population=population, reviewers=reviewers, as_of=as_of,
              current=current)
        for record in records
    ]
    dispositions = {
        admission.suppression_id: admission.disposition for admission in admissions
    }

    suppressed: set[str] = set()
    for record, admission in zip(records, admissions):
        if admission.disposition != D_ACTIVE:
            continue
        for member in record.member_ids:
            suppressed.add(member)

    unsuppressed = set(population.exact) - suppressed
    if len(suppressed) + len(unsuppressed) != len(population.exact):
        raise Refusal(
            R_COUNT_UNBALANCED,
            f"suppressed {len(suppressed)} + unsuppressed {len(unsuppressed)} != "
            f"population {len(population.exact)}",
        )
    if suppressed & unsuppressed:
        raise Refusal(
            R_COUNT_UNBALANCED,
            "a member is counted as both suppressed and unsuppressed",
        )
    for record in records:
        if (
            record.member_ids
            and record.member_count is not None
            and record.member_count != len(record.member_ids)
        ):
            raise Refusal(
                R_COUNT_UNBALANCED,
                f"{record.id}: the record states {record.member_count} members but "
                f"lists {len(record.member_ids)}",
            )
    counted = sum(1 for disposition in dispositions.values() if disposition in DISPOSITIONS)
    if counted != len(records):
        raise Refusal(
            R_COUNT_UNBALANCED,
            f"{len(records)} suppression records but {counted} disposition entries",
        )

    codes = tuple(sorted({code for admission in admissions for code in admission.codes}))
    return Reconciliation(
        population_id=population.id,
        expected=population.expected,
        enumerated=len(population.exact),
        suppressed=tuple(sorted(suppressed)),
        unsuppressed=tuple(sorted(unsuppressed)),
        dispositions=dispositions,
        codes=codes,
    )


# --------------------------------------------------------------------------
# The reviewer register
# --------------------------------------------------------------------------

#: A guard control fixture establishes a control, not a reviewer of a real
#: suppression. The fixtures are named by the guard's own registry.
def _excluded_fixtures(repo_root: Path) -> set[str]:
    path = repo_root / "evidence" / "etp-t3" / "SPECIFICATIONS.json"
    if not path.is_file():
        return set()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    return {
        entry["path"]
        for entry in document.get("excluded", [])
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }


def reviewer_register(repo_root: Path, skip: Iterable[str] = ("evidence/a6/",)) -> dict:
    """`token -> [record#locator]` for every reviewer a tracked record establishes.

    The scan is bounded to `evidence/**/*.json`, skips files above 40,000,000 bytes,
    skips this item's own records (so the register cannot be established by citing
    itself), and skips the guard's control fixtures (a fixture proves the guard
    works; it is not a reviewer of a real suppression). A role description recorded
    in a `decided_by` field is not a reviewer: the accepting party is not the
    reviewing party (Article 5).
    """
    root = Path(repo_root) / "evidence"
    fixtures = _excluded_fixtures(Path(repo_root))
    skip = tuple(skip)
    collected: dict[str, list[str]] = {}

    def walk(value: Any, locator: str, record: str) -> None:
        if isinstance(value, dict):
            reviewer = value.get("reviewer")
            if isinstance(reviewer, str) and reviewer.strip():
                collected.setdefault(reviewer, []).append(f"{record}#{locator}/reviewer")
            for key in sorted(value):
                walk(value[key], f"{locator}/{key}", record)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{locator}/{index}", record)

    for path in sorted(root.rglob("*.json")):
        relative = path.relative_to(Path(repo_root)).as_posix()
        if any(relative.startswith(prefix) for prefix in skip):
            continue
        if relative in fixtures:
            continue
        try:
            if path.stat().st_size > 40_000_000:
                continue
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        walk(document, "", relative)

    # A guard control fixture is not a reviewer of a real suppression: a token whose
    # only occurrences are fixture entries is not established by a tracked record.
    register: dict[str, list[str]] = {}
    for token, locators in sorted(collected.items()):
        real = sorted(locator for locator in locators if "/controls/" not in locator)
        if real:
            register[token] = real
    return register


# --------------------------------------------------------------------------
# Readers for the real suppression-shaped records
# --------------------------------------------------------------------------


def _load(repo_root: Path, relative: str) -> tuple[dict, str]:
    path = Path(repo_root) / relative
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise Refusal(
            R_TARGET_ABSENT, f"{relative}: the record cannot be read ({exc})"
        ) from exc
    try:
        return json.loads(data.decode("utf-8")), digest_bytes(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal(
            R_TARGET_ABSENT, f"{relative}: the record is not valid JSON ({exc})"
        ) from exc


def _require(document: Any, path: Iterable[str], record: str) -> Any:
    value = document
    for key in path:
        if isinstance(value, dict) and key in value:
            value = value[key]
        elif isinstance(value, list) and isinstance(key, int) and key < len(value):
            value = value[key]
        else:
            raise Refusal(
                R_TARGET_ABSENT,
                f"{record}: the record does not state /{'/'.join(str(k) for k in path)}",
            )
    return value


def _rule_fingerprint(rule_id: str) -> str:
    payload = "\x00".join(("a1-rule/v1", rule_id)).encode("utf-8")
    return digest_bytes(payload)


def _t4_records(repo_root: Path) -> list[Suppression]:
    relative = "evidence/etp-t4/SAFETY-SITES.json"
    document, digest = _load(repo_root, relative)
    block = _require(document, ("suppressions",), relative)
    total = _require(block, ("total",), f"{relative}#/suppressions")
    by_lint = _require(block, ("by_lint",), f"{relative}#/suppressions")
    modules = _require(block, ("test_modules",), f"{relative}#/suppressions")
    if sum(by_lint.values()) != total:
        raise Refusal(
            R_COUNT_UNBALANCED,
            f"{relative}#/suppressions: by_lint sums to {sum(by_lint.values())}, "
            f"not the stated total {total}",
        )
    summary_count = _require(document, ("summary", "suppressions"), relative)
    summary_modules = _require(document, ("summary", "test_modules"), relative)
    if summary_count != total or summary_modules != len(modules):
        raise Refusal(
            R_COUNT_UNBALANCED,
            f"{relative}: summary.suppressions/test_modules disagree with the block",
        )
    identity = _require(document, ("identity",), relative)
    candidate = _require(identity, ("commit",), f"{relative}#/identity")
    source_tree = _require(identity, ("source_tree_sha256",), f"{relative}#/identity")
    scanner = _require(identity, ("scanner_sha256",), f"{relative}#/identity")
    axioms, axioms_digest = _load(repo_root, "evidence/etp-t4/AXIOMS.json")
    axiom_status = {
        axiom["id"]: axiom["status"]
        for axiom in axioms.get("axioms", [])
        if isinstance(axiom, dict) and "id" in axiom
    }
    artefact = {"uri": "src", "digest": source_tree, "digestScope": "source-tree"}

    return [
        Suppression(
            id="t4-suppressions",
            record=relative,
            locator="/suppressions",
            record_sha256=digest,
            target_scope=T_NONE,
            scope=SCOPE_RULE,
            justification="",
            reviewer=None,
            recorded_at="",
            expires_at=None,
            policy_basis=(
                "AX-SUPPRESSION-SCOPE in evidence/etp-t4/AXIOMS.json "
                f"(status {axiom_status.get('AX-SUPPRESSION-SCOPE', 'unknown')}); "
                f"the axioms record's sha256 is {axioms_digest}"
            ),
            member_ids=(),
            members_recorded=False,
            member_count=total,
            member_count_basis=(
                "the record states a total and a per-lint partition and no member "
                "row, so the count is an aggregate, not a census"
            ),
            candidate=candidate,
            source_tree=source_tree,
            tool=f"forensics/tools/unsafe_obligations.py@{scanner}",
            artefact=artefact,
            recorded_fields={
                "total": total,
                "byLint": by_lint,
                "summary": {"suppressions": summary_count, "testModules": summary_modules},
                "identity": {
                    "commit": candidate,
                    "sourceTreeSha256": source_tree,
                    "scannerSha256": scanner,
                },
            },
        ),
        Suppression(
            id="t4-test-modules",
            record=relative,
            locator="/suppressions/test_modules",
            record_sha256=digest,
            target_scope=T_NONE,
            scope=SCOPE_RULE,
            justification="",
            reviewer=None,
            recorded_at="",
            expires_at=None,
            policy_basis=(
                "AX-TEST-ONLY in evidence/etp-t4/AXIOMS.json "
                f"(status {axiom_status.get('AX-TEST-ONLY', 'unknown')}); "
                f"the axioms record's sha256 is {axioms_digest}"
            ),
            member_ids=(),
            members_recorded=False,
            member_count=len(modules),
            member_count_basis=(
                f"{len(modules)} module rows, each a region (path, line, module); the "
                "rows identify the scope, not the findings it keeps out of the census"
            ),
            candidate=candidate,
            source_tree=source_tree,
            tool=f"forensics/tools/unsafe_obligations.py@{scanner}",
            artefact=artefact,
            recorded_fields={
                "testModules": summary_modules,
                "firstModule": modules[0] if modules else None,
                "lastModule": modules[-1] if modules else None,
            },
        ),
    ]


def _t3_records(repo_root: Path) -> list[Suppression]:
    relative = "evidence/etp-t3/SPECIFICATIONS.json"
    document, digest = _load(repo_root, relative)
    failures = _require(document, ("known_failures",), relative)
    specifications = _require(document, ("specifications",), relative)
    exemptions = sum(len(entry.get("exemptions", [])) for entry in specifications)
    if exemptions != 0:
        raise Refusal(
            R_NO_REVIEWER,
            f"{relative}: {exemptions} recorded exemption(s) exist, but this reader "
            "was written for a register with none; refusing rather than dropping one",
        )
    records: list[Suppression] = []
    rule_fingerprint = _rule_fingerprint("SP_INTERNAL_IDENTIFIER")
    for index, failure in enumerate(failures):
        path = _require(failure, ("path",), f"{relative}#/known_failures/{index}")
        tokens = _require(failure, ("tokens",), f"{relative}#/known_failures/{index}")
        level = _require(failure, ("level",), f"{relative}#/known_failures/{index}")
        would_close = _require(
            failure, ("would_close",), f"{relative}#/known_failures/{index}"
        )
        status = _require(failure, ("status",), f"{relative}#/known_failures/{index}")
        slug = re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-")
        records.append(
            Suppression(
                id=f"t3-known-nonconformance-{slug}",
                record=relative,
                locator=f"/known_failures/{index}",
                record_sha256=digest,
                target_scope=T_RULE,
                target_identity=rule_fingerprint,
                target_rule="SP_INTERNAL_IDENTIFIER",
                scope=SCOPE_RULE,
                justification="",
                reviewer=None,
                recorded_at="",
                expires_at=None,
                policy_basis=(
                    "the spec_guard known-nonconformance register: a token listed here "
                    f"is not refused as SP_INTERNAL_IDENTIFIER; status {status}, level "
                    f"{level}"
                ),
                member_ids=(),
                members_recorded=False,
                member_count=len(tokens),
                member_count_basis=(
                    f"{len(tokens)} identifier tokens; a token is a key for the rule, "
                    "not a finding identity, and it may cover many occurrences"
                ),
                artefact={"uri": path, "digest": "", "digestScope": "artifact"},
                recorded_fields={
                    "path": path,
                    "level": level,
                    "status": status,
                    "tokens": tokens,
                    "wouldClose": would_close,
                },
            )
        )
    return records


def _openssh_record(repo_root: Path) -> list[Suppression]:
    relative = "evidence/SAFE-COMPATIBLE-openssh-b85c.json"
    document, digest = _load(repo_root, relative)
    obligations = _require(document, ("accepted_obligations",), relative)
    classification = _require(document, ("classification",), relative)
    identity = _require(document, ("identity",), relative)
    decided_by = _require(classification, ("decided_by",), relative)
    authority = _require(classification, ("authority",), relative)
    basis = _require(classification, ("basis",), relative)
    scope = _require(classification, ("scope",), relative)
    date = _require(document, ("date",), relative)
    candidate_tag = _require(identity, ("candidate_tag",), relative)
    source_head = _require(identity, ("source_head",), relative)
    tool_sha = _require(identity, ("tool_sha256",), relative)
    obligation_ids = [
        item.get("id") for item in obligations if isinstance(item, dict) and item.get("id")
    ]
    if len(obligation_ids) != len(obligations):
        raise Refusal(
            R_NO_MEMBERS,
            f"{relative}#/accepted_obligations: an obligation has no id, so the "
            "acceptance cannot name every member",
        )
    return [
        Suppression(
            id="openssh-risk-acceptance-b85c",
            record=relative,
            locator="/accepted_obligations",
            record_sha256=digest,
            target_scope=T_NONE,
            scope=SCOPE_RULE,
            justification=basis,
            reviewer=decided_by,
            reviewer_recorded_in=f"{relative}#/classification/decided_by",
            recorded_at=date,
            expires_at=None,
            policy_basis=authority,
            member_ids=(),
            members_recorded=False,
            member_count=len(obligations),
            member_count_basis=(
                f"{len(obligations)} obligation identifiers ({', '.join(obligation_ids[:3])}"
                f"{'...' if len(obligation_ids) > 3 else ''}); an obligation is not a "
                "finding identity in the finding-identity model"
            ),
            candidate=candidate_tag,
            source_tree=None,
            tool=None,
            recorded_fields={
                "classification": classification,
                "date": date,
                "candidateTag": candidate_tag,
                "sourceHead": source_head,
                "toolSha256": tool_sha,
                "scope": scope,
                "acceptedObligationIds": obligation_ids,
            },
        )
    ]


def _not_suppression_records(repo_root: Path) -> list[Suppression]:
    records: list[Suppression] = []

    exclusions_relative = "evidence/etp-t10/EXCLUSIONS.json"
    exclusions, exclusions_digest = _load(repo_root, exclusions_relative)
    rows = _require(exclusions, ("rows",), exclusions_relative)
    totals = _require(exclusions, ("exclusion_rows",), exclusions_relative)
    if totals != len(rows):
        raise Refusal(
            R_COUNT_UNBALANCED,
            f"{exclusions_relative}: exclusion_rows {totals} != {len(rows)} rows",
        )
    records.append(
        Suppression(
            id="t10-closure-exclusions",
            record=exclusions_relative,
            locator="/rows",
            record_sha256=exclusions_digest,
            classification=C_NOT_A_SUPPRESSION,
            reason=(
                "an exclusion row argues that an edge is outside the closure's "
                "conservative upper bound; it removes no finding from a population, "
                f"all {len(rows)} rows are present, and A5 admits the population as "
                "COMPLETE"
            ),
            target_scope=T_NONE,
            scope=SCOPE_RULE,
            justification="",
            reviewer=None,
            recorded_at="",
            member_ids=(),
            members_recorded=False,
            member_count=len(rows),
            member_count_basis=(
                f"{len(rows)} closure-exclusion rows, each with its own id and edge "
                "identity; they are not finding identities"
            ),
            recorded_fields={
                "exclusionRows": totals,
                "exclusionsPassing": exclusions.get("exclusions_passing"),
                "exclusionsFailing": exclusions.get("exclusions_failing"),
            },
        )
    )

    sarif_relative = "evidence/a1/SARIF.json"
    sarif, sarif_digest = _load(repo_root, sarif_relative)
    superseded: tuple[int, int, dict] | None = None
    for run_index, run in enumerate(sarif.get("runs", [])):
        for result_index, result in enumerate(run.get("results", [])):
            properties = result.get("properties", {}).get("a1", {})
            if properties.get("superseded") is True:
                superseded = (run_index, result_index, result)
                break
        if superseded is not None:
            break
    if superseded is None:
        raise Refusal(
            R_TARGET_ABSENT,
            f"{sarif_relative}: the superseded result named by the record is absent",
        )
    run_index, result_index, result = superseded
    fingerprints = _require(result, ("partialFingerprints",), sarif_relative)
    exact = _require(fingerprints, ("a1Exact/v1",), sarif_relative)
    records.append(
        Suppression(
            id="a1-superseded-disposition",
            record=sarif_relative,
            locator=f"/runs/{run_index}/results/{result_index}",
            record_sha256=sarif_digest,
            classification=C_NOT_A_SUPPRESSION,
            reason=(
                "a superseded disposition is emitted verbatim and remains a finding; "
                "it is a disposition, not a suppression, and A1 emits no "
                "result.suppressions"
            ),
            target_scope=T_EXACT,
            target_identity=exact,
            scope=SCOPE_EXACT,
            justification=(
                "the native record marks this disposition superseded and A1 emits it "
                "with `superseded: true`"
            ),
            reviewer=None,
            recorded_at="",
            member_ids=(exact,),
            members_recorded=True,
            member_count=1,
            member_count_basis="one exact finding identity, emitted and marked",
            candidate=(result.get("properties", {}).get("a1", {}).get("candidate") or {}).get(
                "repository_head"
            ),
            artefact={
                "uri": (result.get("properties", {}).get("a1", {}).get("artifact") or {}).get(
                    "uri"
                ),
                "digest": (
                    result.get("properties", {}).get("a1", {}).get("artifact") or {}
                ).get("digest"),
                "digestScope": (
                    result.get("properties", {}).get("a1", {}).get("artifact") or {}
                ).get("digestScope"),
            },
            recorded_fields={
                "ruleId": result.get("ruleId"),
                "superseded": True,
                "supersededDisposition": (
                    result.get("properties", {}).get("a1", {}).get("supersededDisposition")
                ),
                "exactFingerprint": exact,
            },
        )
    )

    control_relative = "evidence/etp-t3/SPECIFICATIONS.json"
    control_document, control_digest = _load(repo_root, control_relative)
    fixture = next(
        (
            entry
            for entry in control_document.get("controls", [])
            if entry.get("exemptions")
        ),
        None,
    )
    if fixture is not None:
        exemption = fixture["exemptions"][0]
        records.append(
            Suppression(
                id="t3-spec-guard-control-fixture",
                record=control_relative,
                locator=f"/controls/{control_document['controls'].index(fixture)}/exemptions/0",
                record_sha256=control_digest,
                classification=C_CONTROL_FIXTURE,
                reason=(
                    "a guard control fixture: it proves the exemption mechanism "
                    "accepts a justified exemption and disposes of no real finding"
                ),
                target_scope=T_NONE,
                scope=SCOPE_RULE,
                justification=exemption.get("justification", ""),
                reviewer=exemption.get("reviewer"),
                reviewer_recorded_in=(
                    f"{control_relative}#/controls/*/exemptions/0/reviewer"
                ),
                recorded_at=str(exemption.get("reviewed", "")),
                expires_at=None,
                member_ids=(),
                members_recorded=False,
                member_count=1,
                member_count_basis="one fixture token, not a finding identity",
                recorded_fields={"exemption": exemption, "expect": fixture.get("expect")},
            )
        )
    return records


def build_register(repo_root: Path) -> list[Suppression]:
    """Every real suppression-shaped record, with its fields read verbatim."""
    return [
        *_t4_records(repo_root),
        *_t3_records(repo_root),
        *_openssh_record(repo_root),
        *_not_suppression_records(repo_root),
    ]


def register_document(
    records: list[Suppression],
    *,
    population: FindingPopulation | None = None,
    reviewers: Mapping[str, Iterable[str]] | None = None,
    as_of: str | None = None,
    current: CurrentIdentity | None = None,
) -> dict:
    admissions = [
        admit(record, population=population, reviewers=reviewers, as_of=as_of,
              current=current)
        for record in records
    ]
    return {
        "schema": SUPPRESSIONS_SCHEMA,
        "model": MODEL_ID,
        "purpose": (
            "every real suppression-shaped record, the fields it actually states, the "
            "disposition it is admitted at and the refusal codes that fire"
        ),
        "rule": (
            "a suppression is a disposition of a finding that is still in the "
            "population, never an absence"
        ),
        "dispositions": list(DISPOSITIONS),
        "dispositionMeanings": {
            disposition: {"licenses": licenses, "doesNotLicense": does_not}
            for disposition, (licenses, does_not) in DISPOSITION_MEANINGS.items()
        },
        "refusals": {
            code: {"condition": condition, "prevents": prevents}
            for code, (condition, prevents) in REFUSALS.items()
        },
        "records": [record.as_dict() for record in records],
        "admissions": [admission.as_dict() for admission in admissions],
        "totals": _totals(records, admissions),
    }


def _totals(records: list[Suppression], admissions: list[Admission]) -> dict:
    by_disposition = {disposition: 0 for disposition in DISPOSITIONS}
    by_code: dict[str, int] = {}
    for admission in admissions:
        by_disposition[admission.disposition] += 1
        for code in admission.codes:
            by_code[code] = by_code.get(code, 0) + 1
    return {
        "records": len(records),
        "suppressions": sum(1 for r in records if r.classification == C_SUPPRESSION),
        "notSuppressions": sum(
            1 for r in records if r.classification != C_SUPPRESSION
        ),
        "actionable": sum(
            1 for ad in admissions
            if ad.classification == C_SUPPRESSION and ad.actionable
        ),
        "byDisposition": by_disposition,
        "byCode": dict(sorted(by_code.items())),
        "membersDisposed": sum(
            len(record.member_ids)
            for record, admission in zip(records, admissions)
            if admission.disposition == D_ACTIVE
        ),
    }


# --------------------------------------------------------------------------
# Invalidation document
# --------------------------------------------------------------------------


def _synthetic_active(
    *,
    member: str,
    rule: str,
    logical: str,
    binding: dict,
    reviewer: str,
) -> Suppression:
    """A well-formed synthetic suppression used only by the controls."""
    return Suppression(
        id="synthetic-active",
        record="in-memory control",
        locator="/control",
        record_sha256=digest_bytes(b"synthetic-active"),
        target_scope=T_EXACT,
        target_identity=member,
        scope=SCOPE_EXACT,
        justification="a synthetic justification used only to exercise the model",
        reviewer=reviewer,
        reviewer_recorded_in="in-memory control reviewer register",
        recorded_at="2026-01-01",
        expires_at="2027-01-01",
        policy_basis="the synthetic control policy",
        policy_token="control-policy@aa",
        member_ids=(member,),
        members_recorded=True,
        member_count=1,
        member_count_basis="one exact member, supplied by the control",
        candidate="candidate-a",
        source_tree="aa" * 32,
        tool="forensics/tools/suppression_governance.py@bb",
        artefact=binding,
        logical_identity=logical,
        recorded_fields={"ruleId": rule},
    )


def invalidation_document(
    records: list[Suppression],
    *,
    population: FindingPopulation,
    current: CurrentIdentity,
    reviewers: Mapping[str, Iterable[str]],
    as_of: str,
) -> dict:
    entries = []
    for record in records:
        results = [
            invalidate(record, trigger, current=current, population=population,
                       as_of=as_of)
            for trigger in TRIGGERS
        ]
        entries.append(
            {
                "id": record.id,
                "classification": record.classification,
                "record": record.record,
                "locator": record.locator,
                "candidate": record.candidate,
                "expiresAt": record.expires_at,
                "triggers": [result.as_dict() for result in results],
                "disposition": next(
                    (result.disposition for result in results if result.fired),
                    record.disposition,
                ),
            }
        )

    controls = _invalidation_controls(population)
    return {
        "schema": INVALIDATION_SCHEMA,
        "model": MODEL_ID,
        "purpose": (
            "which invalidation triggers fire at the candidate under evaluation, what "
            "each suppression's disposition becomes, and a synthetic control for each "
            "trigger"
        ),
        "currentIdentity": current.as_dict(),
        "evaluation": {
            "asOf": as_of,
            "population": population.summary(),
            "reviewerTokens": len(reviewers),
        },
        "triggers": {
            trigger: {
                "changes": changes,
                "disposition": disposition,
                "prevents": prevents,
            }
            for trigger, (changes, disposition, prevents) in TRIGGER_MEANINGS.items()
        },
        "records": entries,
        "controls": controls,
        "summary": _invalidation_summary(entries, controls),
    }


def _invalidation_summary(entries: list[dict], controls: list[dict]) -> dict:
    by_trigger = {trigger: {"FIRED": 0, "NOT_FIRED": 0, "NOT_RUN": 0} for trigger in TRIGGERS}
    for entry in entries:
        for result in entry["triggers"]:
            by_trigger[result["trigger"]][result["status"]] += 1
    return {
        "records": len(entries),
        "recordsInvalidated": sum(
            1 for entry in entries
            if entry["classification"] == C_SUPPRESSION and entry["disposition"] == D_INVALIDATED
        ),
        "recordsExpired": sum(
            1 for entry in entries
            if entry["classification"] == C_SUPPRESSION and entry["disposition"] == D_EXPIRED
        ),
        "byTrigger": by_trigger,
        "controls": len(controls),
        "controlsFired": sum(1 for control in controls if control["status"] == STATUS_FIRED),
    }


def _invalidation_controls(population: FindingPopulation) -> list[dict]:
    if not population.exact:
        raise Refusal(R_COUNT_UNBALANCED, "the population is empty; no control base")
    member = sorted(population.exact)[0]
    logical = sorted(population.logical)[0]
    rule = sorted(population.rule)[0]
    binding = population.bindings.get(member) or {
        "uri": population.record,
        "digest": "cc" * 32,
        "digestScope": "record",
    }
    reviewers = {"synthetic control reviewer": ["in-memory control register"]}
    base = _synthetic_active(
        member=member, rule=rule, logical=logical, binding=binding,
        reviewer="synthetic control reviewer",
    )

    def run(control_id: str, trigger: str, current: CurrentIdentity,
            record: Suppression = base, pop: FindingPopulation = population,
            as_of: str = "2026-11-24") -> dict:
        result = invalidate(record, trigger, current=current, population=pop, as_of=as_of)
        if result.status != STATUS_FIRED:
            raise AssertionError(f"{control_id}: expected FIRED, observed {result.status}")
        return {
            "id": control_id,
            "trigger": trigger,
            "expectedStatus": STATUS_FIRED,
            "status": result.status,
            "disposition": result.disposition,
            "reason": result.reason,
            "changedIdentity": result.changed_identity,
        }

    return [
        run("candidate-identity-change",
            TR_CANDIDATE, CurrentIdentity(candidate="candidate-b", as_of="2026-11-24")),
        run("source-tree-digest-change",
            TR_SOURCE_TREE, CurrentIdentity(source_tree="dd" * 32, as_of="2026-11-24")),
        run("tool-identity-change",
            TR_TOOL,
            CurrentIdentity(tool="forensics/tools/suppression_governance.py@ee",
                            as_of="2026-11-24")),
        run("expiry",
            TR_EXPIRY, CurrentIdentity(as_of="2027-06-01"), as_of="2027-06-01"),
        run("target-absent-from-population",
            TR_TARGET_ABSENT, CurrentIdentity(as_of="2026-11-24"),
            pop=FindingPopulation(
                id="population-without-the-target",
                record=population.record,
                record_sha256=population.record_sha256,
                exact=tuple(sorted(set(population.exact) - {member})),
                logical=population.logical,
                rule=population.rule,
                bindings=population.bindings,
            )),
        run("new-occurrence-at-logical-identity",
            TR_NEW_OCCURRENCE,
            CurrentIdentity(new_occurrence_logical=logical,
                            new_occurrence_exact="ff" * 32, as_of="2026-11-24")),
        run("policy-basis-change",
            TR_POLICY, CurrentIdentity(policy_basis="control-policy@ff",
                                       as_of="2026-11-24")),
    ]


# --------------------------------------------------------------------------
# Controls: one in-memory control per refusal code
# --------------------------------------------------------------------------


def build_controls(
    population: FindingPopulation,
    *,
    reviewers: Mapping[str, Iterable[str]] | None = None,
    as_of: str = "2026-11-24",
) -> list[dict]:
    """One control per refusal code, each built in memory from a real population."""
    if not population.exact:
        raise Refusal(R_COUNT_UNBALANCED, "the population is empty; no control base")
    if not population.bindings:
        raise Refusal(
            R_CROSS_ARTEFACT,
            "the population carries no artefact bindings, so the cross-artefact "
            "control cannot be built",
        )
    reviewer = "synthetic control reviewer"
    control_reviewers = {reviewer: ["in-memory control reviewer register"]}
    if reviewers:
        control_reviewers.update(reviewers)
    members = sorted(population.exact)
    if len(members) < 2:
        raise Refusal(
            R_CROSS_ARTEFACT,
            "the population has fewer than two members, so the cross-artefact "
            "control cannot be built",
        )
    member = members[0]
    binding = population.bindings[member]
    second = next(
        (candidate for candidate in members[1:]
         if population.bindings.get(candidate) != binding),
        None,
    )
    if second is None:
        raise Refusal(
            R_CROSS_ARTEFACT,
            "every member of the population shares one artefact binding, so the "
            "cross-artefact control cannot be built",
        )
    other_binding = population.bindings[second]
    logical = sorted(population.logical)[0]
    rule = sorted(population.rule)[0]
    base = _synthetic_active(
        member=member, rule=rule, logical=logical, binding=binding, reviewer=reviewer
    )
    current = CurrentIdentity(candidate=base.candidate, as_of=as_of)

    controls: list[dict] = []

    def add(control_id: str, kind: str, mutation: str, expected: str, observed: str,
            detail: str) -> None:
        if observed != expected:
            raise AssertionError(
                f"{control_id}: expected {expected}, observed {observed}"
            )
        controls.append(
            {
                "id": control_id,
                "kind": kind,
                "mutation": mutation,
                "expectedCode": expected,
                "observedCode": observed,
                "detail": detail,
            }
        )

    def admit_codes(record: Suppression, **kwargs: Any) -> list[str]:
        return list(
            admit(record, population=kwargs.pop("population", population),
                  reviewers=kwargs.pop("reviewers", control_reviewers),
                  as_of=kwargs.pop("as_of", as_of),
                  current=kwargs.pop("current", current), **kwargs).codes
        )

    def first_code(record: Suppression, **kwargs: Any) -> str:
        codes = admit_codes(record, **kwargs)
        if not codes:
            raise AssertionError(f"{record.id}: expected a refusal, observed none")
        return codes[0]

    # SG_REFUSED_SUPPRESSION_AS_ABSENCE -- a suppressed finding dropped.
    try:
        reconcile(
            FindingPopulation(
                id="population-with-the-suppressed-finding-dropped",
                record=population.record,
                record_sha256=population.record_sha256,
                exact=tuple(m for m in population.exact if m != member),
                logical=population.logical,
                rule=population.rule,
                bindings=population.bindings,
            ),
            [base],
            reviewers=control_reviewers,
            as_of=as_of,
            current=current,
        )
    except Refusal as refusal:
        add_observed = refusal.code
    else:
        add_observed = "none"
    add(
        "suppression-as-absence",
        "reconciliation",
        "the population is rebuilt without the member an active suppression disposes of",
        R_AS_ABSENCE,
        add_observed,
        "a suppressed finding is still a finding, so a population that omits it cannot "
        "be reconciled with the register",
    )

    # SG_REFUSED_NO_MEMBER_IDENTITIES -- an aggregate read as a census.
    add(
        "aggregate-read-as-census",
        "admission",
        "members_recorded is cleared and the member list emptied while member_count is kept",
        R_NO_MEMBERS,
        first_code(dataclasses.replace(
            base, members_recorded=False, member_ids=(), member_count=9,
            member_count_basis="an aggregate total with no member row",
        )),
        "a total with no member row is not a census",
    )

    # SG_REFUSED_NO_JUSTIFICATION
    add(
        "no-justification",
        "admission",
        "the justification is cleared",
        R_NO_JUSTIFICATION,
        first_code(dataclasses.replace(base, justification="")),
        "a suppression is not justified because it exists",
    )

    # SG_REFUSED_NO_REVIEWER
    add(
        "no-reviewer",
        "admission",
        "the reviewer is cleared",
        R_NO_REVIEWER,
        first_code(dataclasses.replace(base, reviewer=None, reviewer_recorded_in=None)),
        "an author's own record is not a review",
    )

    # SG_REFUSED_UNRECORDED_REVIEWER
    add(
        "unrecorded-reviewer",
        "admission",
        "the reviewer token is replaced by one no tracked record establishes",
        R_UNRECORDED_REVIEWER,
        first_code(dataclasses.replace(
            base, reviewer="control-token-not-in-any-record",
            reviewer_recorded_in="not recorded",
        )),
        "a token no record establishes cannot be checked",
    )

    # SG_REFUSED_NO_EXPIRY
    add(
        "no-expiry",
        "admission",
        "the expiry is cleared and the suppression declares itself unbounded",
        R_NO_EXPIRY,
        first_code(dataclasses.replace(base, expires_at=None, unbounded=True)),
        "a permanent suppression is not a governed one",
    )

    # SG_REFUSED_EXPIRED
    add(
        "expired-read-as-active",
        "admission",
        "the expiry is moved before the evaluation date while the record still "
        "declares ACTIVE",
        R_EXPIRED,
        first_code(dataclasses.replace(
            base, expires_at="2020-01-01", disposition=D_ACTIVE
        )),
        "a lapsed acceptance is history, not current state",
    )

    # SG_REFUSED_UNBOUNDED_SCOPE
    add(
        "unbounded-scope",
        "admission",
        "the authorised scope is widened to rule while the target stays an exact "
        "occurrence",
        R_UNBOUNDED_SCOPE,
        first_code(dataclasses.replace(base, scope=SCOPE_RULE)),
        "a suppression covers findings it never named",
    )

    # SG_REFUSED_LOGICAL_AS_EXACT -- a logical target authorising an exact occurrence.
    logical_record = dataclasses.replace(
        base, target_scope=T_LOGICAL, target_identity=logical, scope=SCOPE_EXACT,
        logical_identity=logical,
    )
    add(
        "logical-as-exact",
        "admission",
        "the target is a logical identity and the authorised scope is exact, so a "
        "second exact occurrence at the same logical identity would inherit it",
        R_LOGICAL_AS_EXACT,
        first_code(logical_record),
        "one occurrence's disposition does not transfer to another occurrence",
    )

    # SG_REFUSED_CROSS_ARTEFACT_INHERITANCE
    cross = dataclasses.replace(
        base,
        member_ids=(second,),
        member_count=1,
        target_identity=second,
        artefact=binding,
        logical_identity=population.bindings.get(second, {}).get("logical", logical),
    )
    observed_cross = first_code(cross)
    add(
        "cross-artefact-inheritance",
        "admission",
        f"the suppression records the binding of {binding.get('uri')!r} and its "
        f"member is bound to {other_binding.get('uri')!r}",
        R_CROSS_ARTEFACT,
        observed_cross,
        "an exact identity names one artefact binding",
    )

    # SG_REFUSED_STALE_CANDIDATE
    add(
        "stale-candidate",
        "admission",
        "the candidate under evaluation is moved and the suppression keeps its "
        "recorded candidate",
        R_STALE_CANDIDATE,
        first_code(base, current=CurrentIdentity(candidate="candidate-b", as_of=as_of)),
        "an acceptance at one candidate does not govern another",
    )

    # SG_REFUSED_TARGET_NOT_IN_POPULATION
    add(
        "target-absent-from-population",
        "admission",
        "the target exact identity is replaced by one the population does not contain",
        R_TARGET_ABSENT,
        first_code(dataclasses.replace(
            base, target_identity="00" * 32, member_ids=("00" * 32,), member_count=1
        )),
        "a target no population contains cannot be disposed of",
    )

    # SG_REFUSED_INVALIDATED
    add(
        "invalidated-read-as-active",
        "admission",
        "the record's disposition is INVALIDATED while its other fields still look "
        "active",
        R_INVALIDATED,
        first_code(dataclasses.replace(base, disposition=D_INVALIDATED)),
        "an invalidated suppression is not in force",
    )

    # SG_REFUSED_COUNT_UNBALANCED
    try:
        reconcile(
            population,
            [dataclasses.replace(base, member_count=2)],
            reviewers=control_reviewers,
            as_of=as_of,
            current=current,
        )
    except Refusal as refusal:
        unbalanced = refusal.code
    else:
        unbalanced = "none"
    add(
        "count-unbalanced",
        "reconciliation",
        "the record states two members while listing one",
        R_COUNT_UNBALANCED,
        unbalanced,
        "the register does not account for the population when its parts do not add up",
    )

    # A policy change is an invalidation trigger, not a field check. It produces
    # SG_REFUSED_INVALIDATED and keeps the finding and the record.
    policy = invalidate(
        base, TR_POLICY,
        current=CurrentIdentity(policy_basis="control-policy@ff", as_of=as_of),
        population=population, as_of=as_of,
    )
    add(
        "policy-change",
        "invalidation",
        "the policy basis the suppression was authorised under changes, and the "
        "trigger is applied",
        R_INVALIDATED,
        R_INVALIDATED if policy.fired else "not-fired",
        "an acceptance does not survive the policy that permitted it, and invalidation "
        "deletes neither the finding nor the record",
    )

    return controls


def controls_document(controls: list[dict]) -> dict:
    by_code: dict[str, int] = {}
    for control in controls:
        by_code[control["expectedCode"]] = by_code.get(control["expectedCode"], 0) + 1
    return {
        "schema": CONTROLS_SCHEMA,
        "model": MODEL_ID,
        "purpose": (
            "one in-memory control per refusal code, each built from a real finding "
            "population; a control proves the refusal fires and is not a source change"
        ),
        "controls": controls,
        "totals": {"controls": len(controls), "byCode": dict(sorted(by_code.items()))},
    }


# --------------------------------------------------------------------------
# Documents and the command line
# --------------------------------------------------------------------------


def dump_document(document: dict) -> str:
    """Canonical JSON bytes for a recorded document: sorted keys, indent 1."""
    return json.dumps(document, indent=1, sort_keys=True) + "\n"


def sarif_population(
    path: Path, expected: int | None = None, display: str | None = None
) -> FindingPopulation:
    """Read the finding population from a SARIF emission, through A3's identities."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise Refusal(R_TARGET_ABSENT, f"{path}: the population cannot be read ({exc})")
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal(R_TARGET_ABSENT, f"{path}: the population is not valid JSON ({exc})")
    exact: list[str] = []
    logical: set[str] = set()
    rule: set[str] = set()
    bindings: dict[str, dict] = {}
    for run in document.get("runs", []):
        for result in run.get("results", []):
            fingerprints = result.get("partialFingerprints")
            if not isinstance(fingerprints, dict):
                raise Refusal(
                    R_NO_MEMBERS,
                    f"{path}: a result carries no fingerprints, so no member identity "
                    "can be established",
                )
            try:
                exact_id = fingerprints["a1Exact/v1"]
                logical_id = fingerprints["a1Logical/v1"]
                rule_id = fingerprints["a1Rule/v1"]
            except KeyError as exc:
                raise Refusal(
                    R_NO_MEMBERS,
                    f"{path}: a result is missing {exc.args[0]}, so the population "
                    "cannot be enumerated",
                ) from exc
            exact.append(exact_id)
            logical.add(logical_id)
            rule.add(rule_id)
            artifact = result.get("properties", {}).get("a1", {}).get("artifact", {})
            bindings[exact_id] = {
                "uri": artifact.get("uri"),
                "digest": artifact.get("digest"),
                "digestScope": artifact.get("digestScope"),
            }
    if expected is not None and expected != len(exact):
        raise Refusal(
            R_COUNT_UNBALANCED,
            f"{path}: the second statement says {expected} results but "
            f"{len(exact)} were enumerated",
        )
    return FindingPopulation(
        id="a1-sarif-results",
        record=display or str(path),
        record_sha256=digest_bytes(data),
        exact=tuple(exact),
        logical=tuple(sorted(logical)),
        rule=tuple(sorted(rule)),
        bindings=bindings,
        expected=expected if expected is not None else len(exact),
    )


def _display(repo_root: Path, path: Path) -> str:
    """A record path as written in the evidence: relative where it is in the tree."""
    try:
        return path.resolve().relative_to(Path(repo_root).resolve()).as_posix()
    except ValueError:
        return str(path)


def _load_register(path: Path) -> list[Suppression]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise Refusal(R_TARGET_ABSENT, f"{path}: the register cannot be read ({exc})")
    except json.JSONDecodeError as exc:
        raise Refusal(R_TARGET_ABSENT, f"{path}: the register is not valid JSON ({exc})")
    if document.get("schema") != SUPPRESSIONS_SCHEMA:
        raise Refusal(
            R_TARGET_ABSENT,
            f"{path}: schema is {document.get('schema')!r}, not {SUPPRESSIONS_SCHEMA!r}",
        )
    return [Suppression.from_dict(item) for item in document.get("records", [])]


def _second_statement(repo_root: Path, population_id: str) -> int | None:
    """A second record's examined count for the population, or None."""
    path = Path(repo_root) / "evidence" / "a5" / "ADMISSION.json"
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    for item in document.get("populations", []):
        if item.get("id") == population_id and isinstance(item.get("examined"), int):
            return item["examined"]
    return None


def _print_register(records: list[Suppression], admissions: list[Admission]) -> None:
    for record, admission in zip(records, admissions):
        print(
            f"{record.id}\tclassification={record.classification}\t"
            f"declared={admission.declared_disposition}\t"
            f"disposition={admission.disposition}\t"
            f"target={record.target_scope}\tscope={record.scope}\t"
            f"members={admission.member_count}\t"
            f"codes={','.join(admission.codes) if admission.codes else 'none'}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_parser = subparsers.add_parser(
        "register", help="admit every record in the suppression register"
    )
    register_parser.add_argument("--register", type=Path, default=None)
    register_parser.add_argument("--as-of", default=None)
    register_parser.add_argument("--no-population", action="store_true")

    admit_parser = subparsers.add_parser(
        "admit", help="admit one suppression id or register file"
    )
    admit_parser.add_argument("target", help="a suppression id, or a register file")
    admit_parser.add_argument("--register", type=Path, default=None)
    admit_parser.add_argument("--as-of", default=None)

    invalidate_parser = subparsers.add_parser(
        "invalidate", help="apply one invalidation trigger to one suppression"
    )
    invalidate_parser.add_argument("target", help="a suppression id")
    invalidate_parser.add_argument("--trigger", required=True, choices=TRIGGERS)
    invalidate_parser.add_argument("--register", type=Path, default=None)
    invalidate_parser.add_argument("--as-of", default=None)

    reconcile_parser = subparsers.add_parser(
        "reconcile", help="reconcile the register with the finding population"
    )
    reconcile_parser.add_argument("--register", type=Path, default=None)
    reconcile_parser.add_argument("--population", type=Path, default=None)
    reconcile_parser.add_argument("--as-of", default=None)

    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root)

    try:
        register_path = (
            Path(args.register)
            if getattr(args, "register", None) is not None
            else repo_root / DEFAULT_REGISTER
        )
        if register_path.is_file():
            records = _load_register(register_path)
        else:
            records = build_register(repo_root)

        current = candidate_identity(repo_root)
        as_of = getattr(args, "as_of", None) or current.as_of
        reviewers = reviewer_register(repo_root)
        population: FindingPopulation | None = None
        if args.command == "reconcile":
            population_path = (
                Path(args.population)
                if args.population is not None
                else repo_root / DEFAULT_POPULATION
            )
            population = sarif_population(
                population_path, expected=_second_statement(repo_root, "a1-sarif-results"),
                display=_display(repo_root, population_path),
            )
        elif args.command in ("register", "admit") and not getattr(
            args, "no_population", False
        ):
            population = sarif_population(
                repo_root / DEFAULT_POPULATION,
                expected=_second_statement(repo_root, "a1-sarif-results"),
                display=DEFAULT_POPULATION.as_posix(),
            )

        if args.command == "register":
            admissions = [
                admit(record, population=population, reviewers=reviewers, as_of=as_of,
                      current=current)
                for record in records
            ]
            _print_register(records, admissions)
            totals = _totals(records, admissions)
            print(
                f"records={totals['records']} suppressions={totals['suppressions']} "
                f"notSuppressions={totals['notSuppressions']} "
                f"actionable={totals['actionable']} "
                + " ".join(
                    f"{disposition}={count}"
                    for disposition, count in totals["byDisposition"].items()
                )
                + " codes="
                + (",".join(totals["byCode"]) if totals["byCode"] else "none")
            )
            return EXIT_REFUSED if totals["actionable"] != totals["suppressions"] else EXIT_OK

        if args.command == "admit":
            target_path = Path(args.target)
            candidates = (
                _load_register(target_path) if target_path.is_file() else
                [record for record in records if record.id == args.target]
            )
            if not candidates:
                print(
                    f"{R_TARGET_ABSENT}: no suppression {args.target!r} in "
                    f"{register_path}",
                    file=sys.stderr,
                )
                return EXIT_USAGE
            admissions = [
                admit(record, population=population, reviewers=reviewers, as_of=as_of,
                      current=current)
                for record in candidates
            ]
            _print_register(candidates, admissions)
            for admission in admissions:
                print(f"{admission.suppression_id}\t{admission.detail}")
            return EXIT_OK if all(not a.codes for a in admissions) else EXIT_REFUSED

        if args.command == "invalidate":
            matches = [record for record in records if record.id == args.target]
            if not matches:
                print(
                    f"{R_TARGET_ABSENT}: no suppression {args.target!r} in "
                    f"{register_path}",
                    file=sys.stderr,
                )
                return EXIT_USAGE
            record = matches[0]
            if population is None:
                population = sarif_population(
                    repo_root / DEFAULT_POPULATION,
                    expected=_second_statement(repo_root, "a1-sarif-results"),
                    display=DEFAULT_POPULATION.as_posix(),
                )
            result = invalidate(record, args.trigger, current=current,
                                population=population, as_of=as_of)
            print(
                f"{record.id}\ttrigger={args.trigger}\tstatus={result.status}\t"
                f"disposition={result.disposition}\tchanged={result.changed_identity or 'none'}\t"
                f"reason={result.reason}"
            )
            print(
                f"{record.id}\tcodes="
                + (R_INVALIDATED if result.fired else "none")
            )
            return EXIT_OK if result.fired else EXIT_REFUSED

        if args.command == "reconcile":
            assert population is not None
            reconciliation = reconcile(
                population, records, reviewers=reviewers, as_of=as_of, current=current
            )
            for record in records:
                admission = admit(record, population=population, reviewers=reviewers,
                                  as_of=as_of, current=current)
                print(
                    f"{record.id}\tclassification={record.classification}\t"
                    f"disposition={admission.disposition}\t"
                    f"members={admission.member_count}\t"
                    f"codes={','.join(admission.codes) if admission.codes else 'none'}"
                )
            summary = reconciliation.summary()
            print(
                f"population={summary['population']} expected={summary['expected']} "
                f"enumerated={summary['enumerated']} suppressed={summary['suppressed']} "
                f"unsuppressed={summary['unsuppressed']} balance="
                + ("ok" if summary["balanced"] else "unbalanced")
                + " dispositions="
                + " ".join(
                    f"{disposition}={count}"
                    for disposition, count in summary["byDisposition"].items()
                )
                + " codes="
                + (",".join(summary["codes"]) if summary["codes"] else "none")
            )
            return EXIT_OK if not summary["codes"] else EXIT_REFUSED
    except Refusal as refusal:
        print(str(refusal), file=sys.stderr)
        return EXIT_REFUSED if refusal.code != R_TARGET_ABSENT else EXIT_USAGE

    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
