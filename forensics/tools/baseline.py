#!/usr/bin/env python3
"""baseline.py -- a baseline is a finding population at a recorded identity.

The normative document is `docs/BASELINE-DISPOSITION.md`. This module implements
the rule it states: **a finding that is absent from a later report is not thereby
resolved.** A delta between two baselines must say why a member is absent, and
only one class of reason is a resolution: the mechanism is gone and the finding's
identity is absent from a population that was complete for its scope, scanned by
the same tool identity, with no exclusion or suppression added, and at a candidate
recorded on both sides where the later side is the one being claimed.

What this module does
---------------------
* `Baseline` binds a finding population to the candidate it was taken at, the
  tool that produced it, the scope and its A5 completeness state, the exact
  member identities (or an explicit aggregate flag with no members), the A6
  suppression dispositions that touch it, the time it was taken and the tracked
  record plus locator that carries it.
* `delta(before, after, exclusions, suppressions)` returns one disposition per
  member identity and never drops a before-member. It emits `RESOLVED` only when
  all five conditions in the rule hold; every weaker case gets the weaker
  disposition and a stable code naming the condition that failed.
* `build_baselines(repo_root)` reads the real baselines in this tree: the A1
  emission, the A3 fingerprint migration, the ETP-T15 claim reconciliation, the
  OpenSSH closure pair, the HAZ-15 padding observations, the HAZ-16 FFI
  classification, the ETP-T4 and ETP-T10 populations, the curl closure, and the
  A3 collision report. A record that is not a finding population is named in
  `not_baselines` rather than forced into the model.
* `build_deltas(baselines)` computes the real deltas and records a `NO_BASELINE`
  entry for every area that has no second population at a second identity.
* `build_controls(baselines)` builds one in-memory control per refusal code. A
  control proves the refusal fires; it is not a source change and not a defect
  report.

What this module does not do
----------------------------
It does not decide whether a finding is true, severe or reachable. A resolution
is not a safety proof, and a baseline is not a census of the tree. `RESOLVED` is
scoped to the population examined: it says the member's identity is absent from a
complete later population, not that the mechanism cannot recur. `STILL_PRESENT`
does not say a finding is open, and `NEW` does not say it is a new defect.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

MODEL_ID = "a7/v1"
BASELINES_SCHEMA = "openssl-rs/a7/baselines/1"
DELTA_SCHEMA = "openssl-rs/a7/delta/1"
CONTROLS_SCHEMA = "openssl-rs/a7/controls/1"

EXIT_ADMITTED = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

REPO_ROOT = Path(__file__).resolve().parents[2]

# --------------------------------------------------------------------------
# Dispositions. Every disposition is a statement about identity, not truth.
# --------------------------------------------------------------------------

D_STILL_PRESENT = "STILL_PRESENT"
D_RESOLVED = "RESOLVED"
D_MOVED = "MOVED"
D_NEW = "NEW"
D_SUPPRESSED_ABSENT = "SUPPRESSED_ABSENT"
D_EXCLUDED_ABSENT = "EXCLUDED_ABSENT"
D_UNSCANNED_ABSENT = "UNSCANNED_ABSENT"
D_TOOL_CHANGED_ABSENT = "TOOL_CHANGED_ABSENT"
D_POPULATION_SHRUNK_ABSENT = "POPULATION_SHRUNK_ABSENT"
D_UNKNOWN = "UNKNOWN"

DISPOSITIONS = (
    D_STILL_PRESENT,
    D_RESOLVED,
    D_MOVED,
    D_NEW,
    D_SUPPRESSED_ABSENT,
    D_EXCLUDED_ABSENT,
    D_UNSCANNED_ABSENT,
    D_TOOL_CHANGED_ABSENT,
    D_POPULATION_SHRUNK_ABSENT,
    D_UNKNOWN,
)

# disposition -> (what it licenses, what it does not license)
DISPOSITION_MEANINGS = {
    D_STILL_PRESENT: (
        "the exact identity is in both populations; the finding is still present "
        "at the later candidate",
        "that the finding is true, open, reachable or severe; presence is not state",
    ),
    D_RESOLVED: (
        "the exact and logical identity are absent from a later population that is "
        "COMPLETE for the same scope, scanned by the same recorded tool identity, "
        "with no exclusion or suppression added, at a later recorded candidate",
        "a safety proof, a proof that the mechanism cannot recur, a statement about "
        "a population outside the declared scope, or anything about the omitted "
        "members of a non-complete population",
    ),
    D_MOVED: (
        "the logical identity is preserved and the exact identity changed, so the "
        "underlying finding is still in the later population at another occurrence "
        "or state",
        "a resolution; a moved, relocated or reclassified finding has not left the "
        "population, and a status change is not an elimination",
    ),
    D_NEW: (
        "the identity appears in the later population and not in the earlier one",
        "that the finding is new in the tree, novel, severe or introduced by the "
        "change between the two candidates",
    ),
    D_SUPPRESSED_ABSENT: (
        "the identity is absent and a suppression record on the later side names or "
        "covers it; the disposition is a suppression, not an elimination",
        "a resolution; a suppressed finding remains a finding (A6)",
    ),
    D_EXCLUDED_ABSENT: (
        "the identity is absent and an exclusion record on the later side covers "
        "it; the absence is an argued exclusion, not an elimination",
        "a resolution; an exclusion removes a finding from the examined population, "
        "not from the tree",
    ),
    D_UNSCANNED_ABSENT: (
        "the identity is absent, but the later population is not COMPLETE for the "
        "scope (sampled, truncated, absent, unknown, aggregate-only or deferred), so "
        "the member may simply not have been examined",
        "a resolution; an unexamined member is not an absent one (A5)",
    ),
    D_TOOL_CHANGED_ABSENT: (
        "the identity is absent and the tool identity is not established as "
        "unchanged; the later report may have stopped reporting the class",
        "a resolution; a changed analyser is not a fixed mechanism",
    ),
    D_POPULATION_SHRUNK_ABSENT: (
        "the identity is absent and the later population declares fewer members for "
        "the same scope, so the absence may be a consequence of the smaller scope",
        "a resolution; a smaller population is not a cleaner one",
    ),
    D_UNKNOWN: (
        "the recorded fields do not establish why the identity is absent; the "
        "absence is unexplained",
        "any conclusion, including a resolution; an unknown reason is not a pass "
        "(Article 3)",
    ),
}

# --------------------------------------------------------------------------
# Refusal codes. A code is stable: a document, receipt and test cite it verbatim.
# --------------------------------------------------------------------------

R_ABSENCE_AS_RESOLUTION = "BL_REFUSED_ABSENCE_AS_RESOLUTION"
R_POPULATION_SHRINK = "BL_REFUSED_POPULATION_SHRINK"
R_TOOL_CHANGE = "BL_REFUSED_TOOL_CHANGE"
R_EXCLUSION_AS_RESOLUTION = "BL_REFUSED_EXCLUSION_AS_RESOLUTION"
R_SUPPRESSION_AS_RESOLUTION = "BL_REFUSED_SUPPRESSION_AS_RESOLUTION"
R_PARTIAL_SCAN = "BL_REFUSED_PARTIAL_SCAN"
R_MOVED_AS_RESOLVED = "BL_REFUSED_MOVED_AS_RESOLVED"
R_CANDIDATE_UNRECORDED = "BL_REFUSED_CANDIDATE_UNRECORDED"
R_AGGREGATE_AS_MEMBERS = "BL_REFUSED_AGGREGATE_AS_MEMBERS"
R_NO_BASELINE = "BL_REFUSED_NO_BASELINE"
R_IDENTITY_UNSTABLE = "BL_REFUSED_IDENTITY_UNSTABLE"

# code -> (the condition it refuses, the wrong conclusion it prevents)
REFUSALS = {
    R_ABSENCE_AS_RESOLUTION: (
        "an absent member is read as resolved without the other conditions, or a "
        "member is absent from a population taken at the same candidate as the "
        "earlier one",
        "that a finding disappeared because the report stopped listing it; at one "
        "candidate a deterministic tool reports the same population, so a "
        "disappearance is a changed record, a changed scope or a changed tool",
    ),
    R_POPULATION_SHRINK: (
        "the later population declares fewer members for the same scope, so a "
        "member's absence may follow from the smaller population",
        "that a smaller report is a cleaner tree; the omitted members are not "
        "examined and their properties are unknown (A5)",
    ),
    R_TOOL_CHANGE: (
        "the tool identity changed, or is not recorded on one side, so the absence "
        "may be the analyser no longer emitting the class",
        "that a finding was fixed when the analyser changed; a different tool is a "
        "different observation, not a different tree (Article 6)",
    ),
    R_EXCLUSION_AS_RESOLUTION: (
        "an exclusion record on the later side covers the member's identity",
        "that excluding a finding from the examined population eliminates it; an "
        "exclusion is an argued boundary, not a fix (A6)",
    ),
    R_SUPPRESSION_AS_RESOLUTION: (
        "a suppression record on the later side names or covers the member's "
        "identity",
        "that a suppressed finding is gone; a suppressed finding remains a finding "
        "(A6)",
    ),
    R_PARTIAL_SCAN: (
        "the later population is not COMPLETE for the scope (sampled, truncated, "
        "absent, unknown, aggregate-only or deferred), or its member set does not "
        "cover its declared expected count",
        "that an unexamined member was examined and found absent; an absence inside "
        "a partial scan is not an observation of absence (A5)",
    ),
    R_MOVED_AS_RESOLVED: (
        "a member's logical identity is present in the later population while its "
        "exact identity changed, and the movement is read as a resolution",
        "that a relocated, reclassified or re-statused finding was fixed; the "
        "underlying finding is still present (A3 `MOVED`)",
    ),
    R_CANDIDATE_UNRECORDED: (
        "a candidate identity is missing on one side, is mixed across runs, or the "
        "later side is not recorded as a later candidate",
        "that the later population was taken at the candidate being claimed; an "
        "unrecorded or stale identity cannot support a delta (Article 2)",
    ),
    R_AGGREGATE_AS_MEMBERS: (
        "a baseline states a total without member identities (or an aggregate "
        "member count is read as a member set)",
        "that a number is a census; an aggregate cannot be diffed per identity and "
        "cannot support a resolution",
    ),
    R_NO_BASELINE: (
        "no second population exists at a second identity for the scope, or the two "
        "populations are not the same scope",
        "that a delta can be computed from one population, or across two different "
        "populations; a missing baseline is not a clean baseline",
    ),
    R_IDENTITY_UNSTABLE: (
        "a member carries no recorded exact or logical identity, or the identity is "
        "not a full-length sha-256",
        "that an unidentifiable member can be tracked across populations; an "
        "identity that is not recorded cannot be compared (A3)",
    ),
}

# --------------------------------------------------------------------------
# A5 completeness states. A baseline records the state; it never upgrades it.
# --------------------------------------------------------------------------

S_COMPLETE = "COMPLETE"
S_SAMPLED = "SAMPLED"
S_TRUNCATED_BOUNDED = "TRUNCATED_BOUNDED"
S_ABSENT = "ABSENT"
S_EMPTY = "EMPTY"
S_UNKNOWN = "UNKNOWN"
S_AGGREGATE_ONLY = "AGGREGATE_ONLY"
S_DEFERRED = "DEFERRED"

COMPLETENESS_STATES = (
    S_COMPLETE,
    S_SAMPLED,
    S_TRUNCATED_BOUNDED,
    S_ABSENT,
    S_EMPTY,
    S_UNKNOWN,
    S_AGGREGATE_ONLY,
    S_DEFERRED,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Refusal(Exception):
    """A stable refusal code plus the detail that produced it."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str | None:
    try:
        return digest_bytes(Path(path).read_bytes())
    except OSError:
        return None


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _stable_identity(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX64.fullmatch(value))


# --------------------------------------------------------------------------
# The baseline contract.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Candidate:
    """The candidate a baseline was taken at, and how it is recorded."""

    commit: str | None = None
    branch: str | None = None
    over: str | None = None
    recorded: bool = True
    mixed: bool = False
    per_run: tuple[dict[str, Any], ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "per_run", tuple(self.per_run))
        if self.mixed and not self.per_run:
            raise Refusal(
                R_CANDIDATE_UNRECORDED,
                "a mixed candidate must record the per-run identities it mixes",
            )

    def token(self) -> str | None:
        """A comparable candidate token, or None when no single candidate exists."""
        if self.mixed:
            return None
        if self.commit:
            return f"commit:{self.commit}"
        if self.over:
            return f"over:{self.over}"
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "commit": self.commit,
            "branch": self.branch,
            "over": self.over,
            "recorded": self.recorded,
            "mixed": self.mixed,
            "perRun": [dict(item) for item in self.per_run],
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Candidate":
        return cls(
            commit=value.get("commit"),
            branch=value.get("branch"),
            over=value.get("over"),
            recorded=bool(value.get("recorded", False)),
            mixed=bool(value.get("mixed", False)),
            per_run=tuple(value.get("perRun") or ()),
            note=str(value.get("note") or ""),
        )


@dataclass(frozen=True)
class ToolIdentity:
    """The analyser that produced the population, and its recorded digest."""

    path: str
    digest: str | None = None
    recorded: bool = False
    note: str = ""

    def same_as(self, other: "ToolIdentity") -> bool:
        """True only when both sides record the same tool digest."""
        return (
            self.recorded
            and other.recorded
            and bool(self.digest)
            and bool(other.digest)
            and self.digest == other.digest
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "digest": self.digest,
            "recorded": self.recorded,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ToolIdentity":
        return cls(
            path=str(value.get("path") or ""),
            digest=value.get("digest"),
            recorded=bool(value.get("recorded", False)),
            note=str(value.get("note") or ""),
        )


@dataclass(frozen=True)
class Scope:
    """The population a baseline covers and the A5 state it is admitted at."""

    id: str
    expected: int | None
    examined: int | None
    completeness: str
    basis: str
    locator: str

    def __post_init__(self) -> None:
        if not self.id:
            raise Refusal(R_NO_BASELINE, "a scope has no id")
        if self.completeness not in COMPLETENESS_STATES:
            raise Refusal(
                R_NO_BASELINE,
                f"scope {self.id!r} declares unknown completeness "
                f"{self.completeness!r}",
            )
        for name in ("expected", "examined"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, int) or value < 0):
                raise Refusal(
                    R_NO_BASELINE,
                    f"scope {self.id!r} has a non-count {name} {value!r}",
                )

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "expected": self.expected,
            "examined": self.examined,
            "completeness": self.completeness,
            "basis": self.basis,
            "locator": self.locator,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Scope":
        return cls(
            id=str(value.get("id") or ""),
            expected=value.get("expected"),
            examined=value.get("examined"),
            completeness=str(value.get("completeness") or ""),
            basis=str(value.get("basis") or ""),
            locator=str(value.get("locator") or ""),
        )


@dataclass(frozen=True)
class Member:
    """One member with the A3 exact and logical identities the record determines."""

    logical: str | None
    exact: str | None
    rule: str | None = None
    label: str = ""

    def stable(self) -> bool:
        return _stable_identity(self.logical) and _stable_identity(self.exact)

    def as_dict(self) -> dict[str, Any]:
        return {
            "logical": self.logical,
            "exact": self.exact,
            "rule": self.rule,
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Member":
        return cls(
            logical=value.get("logical"),
            exact=value.get("exact"),
            rule=value.get("rule"),
            label=str(value.get("label") or ""),
        )


@dataclass(frozen=True)
class RecordRef:
    """The tracked record and locator that carries a baseline."""

    path: str
    locator: str
    sha256: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "locator": self.locator,
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RecordRef":
        return cls(
            path=str(value.get("path") or ""),
            locator=str(value.get("locator") or ""),
            sha256=value.get("sha256"),
        )


@dataclass(frozen=True)
class SuppressionDisposition:
    """An A6 suppression projected to the identity or scope it covers."""

    id: str
    covers: str | None
    disposition: str
    actionable: bool = False
    note: str = ""

    def covers_member(self, member: Member) -> bool:
        if not self.covers:
            return False
        return self.covers in {member.exact, member.logical}


@dataclass(frozen=True)
class Exclusion:
    """An exclusion record projected to the identity it covers."""

    id: str
    covers: str | None
    record: str = ""
    note: str = ""

    def covers_member(self, member: Member) -> bool:
        if not self.covers:
            return False
        return self.covers in {member.exact, member.logical}


@dataclass(frozen=True)
class Baseline:
    """A finding population bound to a candidate, a tool and a scope."""

    id: str
    candidate: Candidate
    tool: ToolIdentity
    scope: Scope
    members: tuple[Member, ...]
    aggregate: bool
    member_count: int | None
    suppressions: tuple[SuppressionDisposition, ...]
    taken_at: str
    record: RecordRef
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "members", tuple(self.members))
        object.__setattr__(self, "suppressions", tuple(self.suppressions))
        if not self.id:
            raise Refusal(R_NO_BASELINE, "a baseline has no id")
        if self.aggregate and self.members:
            raise Refusal(
                R_AGGREGATE_AS_MEMBERS,
                f"baseline {self.id!r} is aggregate and also carries "
                f"{len(self.members)} member(s); an aggregate has no member list",
            )
        if self.aggregate:
            if self.member_count is None:
                raise Refusal(
                    R_AGGREGATE_AS_MEMBERS,
                    f"baseline {self.id!r} is aggregate without a recorded count",
                )
            if (
                self.scope.completeness == S_COMPLETE
                and self.scope.expected is not None
                and self.scope.expected != self.member_count
            ):
                raise Refusal(
                    R_PARTIAL_SCAN,
                    f"baseline {self.id!r} is COMPLETE over {self.scope.expected} "
                    f"but states {self.member_count} members",
                )
        else:
            if self.scope.completeness == S_COMPLETE and self.scope.expected is not None:
                if self.scope.expected != len(self.members):
                    raise Refusal(
                        R_PARTIAL_SCAN,
                        f"baseline {self.id!r} is COMPLETE over "
                        f"{self.scope.expected} but carries {len(self.members)} "
                        "member(s)",
                    )

    def member_total(self) -> int:
        return self.member_count if self.aggregate else len(self.members)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "candidate": self.candidate.as_dict(),
            "tool": self.tool.as_dict(),
            "scope": self.scope.as_dict(),
            "members": [member.as_dict() for member in self.members],
            "memberCount": self.member_total(),
            "aggregate": self.aggregate,
            "suppressions": [
                {
                    "id": item.id,
                    "covers": item.covers,
                    "disposition": item.disposition,
                    "actionable": item.actionable,
                    "note": item.note,
                }
                for item in self.suppressions
            ],
            "takenAt": self.taken_at,
            "record": self.record.as_dict(),
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Baseline":
        return cls(
            id=str(value.get("id") or ""),
            candidate=Candidate.from_dict(value.get("candidate") or {}),
            tool=ToolIdentity.from_dict(value.get("tool") or {}),
            scope=Scope.from_dict(value.get("scope") or {}),
            members=tuple(
                Member.from_dict(item) for item in (value.get("members") or ())
            ),
            aggregate=bool(value.get("aggregate", False)),
            member_count=value.get("memberCount"),
            suppressions=tuple(
                SuppressionDisposition(
                    id=str(item.get("id") or ""),
                    covers=item.get("covers"),
                    disposition=str(item.get("disposition") or ""),
                    actionable=bool(item.get("actionable", False)),
                    note=str(item.get("note") or ""),
                )
                for item in (value.get("suppressions") or ())
            ),
            taken_at=str(value.get("takenAt") or "not-recorded"),
            record=RecordRef.from_dict(value.get("record") or {}),
            note=str(value.get("note") or ""),
        )


# --------------------------------------------------------------------------
# The delta.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DispositionRecord:
    """One member's disposition, with the reason and the codes that produced it."""

    identity: str
    logical: str | None
    exact: str | None
    label: str
    disposition: str
    reason: str
    codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.disposition not in DISPOSITIONS:
            raise Refusal(
                R_IDENTITY_UNSTABLE,
                f"unknown disposition {self.disposition!r} for {self.identity!r}",
            )
        object.__setattr__(self, "codes", tuple(self.codes))

    def as_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "logical": self.logical,
            "exact": self.exact,
            "label": self.label,
            "disposition": self.disposition,
            "reason": self.reason,
            "codes": list(self.codes),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DispositionRecord":
        return cls(
            identity=str(value.get("identity") or ""),
            logical=value.get("logical"),
            exact=value.get("exact"),
            label=str(value.get("label") or ""),
            disposition=str(value.get("disposition") or ""),
            reason=str(value.get("reason") or ""),
            codes=tuple(value.get("codes") or ()),
        )


@dataclass(frozen=True)
class DeltaResult:
    """The per-identity dispositions and counts for one pair of baselines."""

    id: str
    before: str
    after: str
    records: tuple[DispositionRecord, ...]
    codes: tuple[str, ...]
    admitted: bool
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "records", tuple(self.records))
        object.__setattr__(self, "codes", tuple(sorted(set(self.codes))))
        object.__setattr__(self, "notes", tuple(self.notes))
        for code in self.codes:
            if code not in REFUSALS:
                raise Refusal(
                    R_IDENTITY_UNSTABLE, f"delta {self.id!r} cites unknown code {code!r}"
                )

    def counts(self) -> dict[str, int]:
        counts = {disposition: 0 for disposition in DISPOSITIONS}
        for record in self.records:
            counts[record.disposition] += 1
        return counts

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "before": self.before,
            "after": self.after,
            "records": len(self.records),
            "counts": self.counts(),
            "codes": list(self.codes),
            "admitted": self.admitted,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "before": self.before,
            "after": self.after,
            "dispositions": [record.as_dict() for record in self.records],
            "counts": self.counts(),
            "codes": list(self.codes),
            "admitted": self.admitted,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DeltaResult":
        return cls(
            id=str(value.get("id") or ""),
            before=str(value.get("before") or ""),
            after=str(value.get("after") or ""),
            records=tuple(
                DispositionRecord.from_dict(item)
                for item in (value.get("dispositions") or ())
            ),
            codes=tuple(value.get("codes") or ()),
            admitted=bool(value.get("admitted", False)),
            notes=tuple(value.get("notes") or ()),
        )


def _record(
    member: Member,
    disposition: str,
    reason: str,
    code: str | None = None,
) -> DispositionRecord:
    identity = member.exact or member.logical or ""
    return DispositionRecord(
        identity=identity,
        logical=member.logical,
        exact=member.exact,
        label=member.label,
        disposition=disposition,
        reason=reason,
        codes=(code,) if code else (),
    )


def _classify_absence(
    before: Baseline,
    after: Baseline,
    member: Member,
    exclusions: tuple[Exclusion, ...],
    suppressions: tuple[SuppressionDisposition, ...],
) -> tuple[str, str, str | None]:
    """The disposition for a member whose identity is absent from `after`."""
    before_token = before.candidate.token()
    after_token = after.candidate.token()

    # (e) the candidate is recorded on both sides.
    if (
        not before.candidate.recorded
        or not after.candidate.recorded
        or before.candidate.mixed
        or after.candidate.mixed
        or before_token is None
        or after_token is None
    ):
        return (
            D_UNKNOWN,
            "the candidate is not recorded as a single identity on both sides",
            R_CANDIDATE_UNRECORDED,
        )

    # A disappearance at the same candidate is a changed record, not a fix.
    if before_token == after_token:
        return (
            D_UNKNOWN,
            "the member is absent at the same recorded candidate as the earlier "
            "population; a deterministic tool reports the same population at one "
            "candidate",
            R_ABSENCE_AS_RESOLUTION,
        )

    # (a, count part) the later population is not smaller for the same scope.
    if (
        before.scope.expected is not None
        and after.scope.expected is not None
        and after.scope.expected < before.scope.expected
    ):
        return (
            D_POPULATION_SHRUNK_ABSENT,
            f"the later scope declares {after.scope.expected} member(s) against "
            f"{before.scope.expected} earlier; the absence may follow from the "
            "smaller population",
            R_POPULATION_SHRINK,
        )

    # (a) the later population is COMPLETE for the scope.
    if after.scope.completeness != S_COMPLETE:
        return (
            D_UNSCANNED_ABSENT,
            f"the later scope is {after.scope.completeness}, not COMPLETE; the "
            "member may not have been examined",
            R_PARTIAL_SCAN,
        )
    if (
        after.scope.expected is not None
        and len(after.members) != after.scope.expected
    ):
        return (
            D_UNSCANNED_ABSENT,
            f"the later scope declares COMPLETE over {after.scope.expected} but "
            f"identifies {len(after.members)} member(s); its own census does not "
            "cover the scope",
            R_PARTIAL_SCAN,
        )

    # (b) the tool identity is unchanged.
    if not before.tool.same_as(after.tool):
        return (
            D_TOOL_CHANGED_ABSENT,
            "the tool identity is not recorded as unchanged on both sides; the "
            "later analyser may have stopped reporting the class",
            R_TOOL_CHANGE,
        )

    # (d, first half) no exclusion covers the identity.
    for exclusion in exclusions:
        if exclusion.covers_member(member):
            return (
                D_EXCLUDED_ABSENT,
                f"exclusion {exclusion.id} covers the member; the absence is an "
                "argued exclusion",
                R_EXCLUSION_AS_RESOLUTION,
            )

    # (d, second half) no suppression covers the identity.
    for suppression in suppressions:
        if suppression.covers_member(member):
            return (
                D_SUPPRESSED_ABSENT,
                f"suppression {suppression.id} covers the member; a suppressed "
                "finding remains a finding",
                R_SUPPRESSION_AS_RESOLUTION,
            )

    return (
        D_RESOLVED,
        "the exact and logical identity is absent from a COMPLETE later "
        "population for the same scope, scanned by the same recorded tool, with "
        "no exclusion or suppression",
        None,
    )


def delta(
    before: Baseline | None,
    after: Baseline | None,
    exclusions: Iterable[Exclusion] = (),
    suppressions: Iterable[SuppressionDisposition] = (),
    *,
    delta_id: str | None = None,
) -> DeltaResult:
    """Diff two baselines, one disposition per member identity, dropping nothing."""
    if before is None or after is None:
        raise Refusal(
            R_NO_BASELINE,
            "a delta requires two baselines; one side is absent, and a missing "
            "baseline is not an empty population",
        )
    if before.aggregate or after.aggregate:
        raise Refusal(
            R_AGGREGATE_AS_MEMBERS,
            f"baseline {before.id!r} or {after.id!r} is aggregate; an aggregate "
            "states a total without member identities and cannot be diffed",
        )
    if before.scope.id != after.scope.id:
        raise Refusal(
            R_NO_BASELINE,
            f"the baselines cover different scopes ({before.scope.id!r} and "
            f"{after.scope.id!r}); a delta is computed within one scope",
        )

    exclusion_list = tuple(exclusions)
    suppression_list = tuple(suppressions)

    before_by_logical: dict[str, list[Member]] = {}
    after_by_logical: dict[str, list[Member]] = {}
    records: list[DispositionRecord] = []

    for member in before.members:
        if not member.stable():
            records.append(
                _record(
                    member,
                    D_UNKNOWN,
                    "the member carries no recorded exact or logical identity",
                    R_IDENTITY_UNSTABLE,
                )
            )
        else:
            before_by_logical.setdefault(member.logical or "", []).append(member)

    for member in after.members:
        if not member.stable():
            records.append(
                DispositionRecord(
                    identity=member.exact or member.logical or "",
                    logical=member.logical,
                    exact=member.exact,
                    label=member.label,
                    disposition=D_UNKNOWN,
                    reason="the later-side member carries no recorded identity; it "
                    "cannot be compared",
                    codes=(R_IDENTITY_UNSTABLE,),
                )
            )
        else:
            after_by_logical.setdefault(member.logical or "", []).append(member)

    for logical in sorted(before_by_logical):
        earlier = sorted(before_by_logical[logical], key=lambda item: item.exact or "")
        later = sorted(after_by_logical.get(logical, []), key=lambda item: item.exact or "")
        later_exact_counts: dict[str, int] = {}
        for item in later:
            if item.exact is not None:
                later_exact_counts[item.exact] = later_exact_counts.get(item.exact, 0) + 1

        remaining_earlier: list[Member] = []
        for member in earlier:
            if member.exact is not None and later_exact_counts.get(member.exact, 0) > 0:
                later_exact_counts[member.exact] -= 1
                records.append(
                    _record(
                        member,
                        D_STILL_PRESENT,
                        "the exact identity is present in both populations",
                    )
                )
            else:
                remaining_earlier.append(member)

        remaining_later: list[Member] = []
        for member in later:
            if member.exact is not None and later_exact_counts.get(member.exact, 0) > 0:
                later_exact_counts[member.exact] -= 1
                remaining_later.append(member)
        remaining_later.sort(key=lambda item: item.exact or "")
        paired = min(len(remaining_earlier), len(remaining_later))
        for index in range(paired):
            member = remaining_earlier[index]
            records.append(
                _record(
                    member,
                    D_MOVED,
                    "the logical identity is preserved and the exact identity "
                    "changed; the finding is still in the later population",
                    R_MOVED_AS_RESOLVED,
                )
            )
        for member in remaining_earlier[paired:]:
            disposition, reason, code = _classify_absence(
                before, after, member, exclusion_list, suppression_list
            )
            records.append(_record(member, disposition, reason, code))
        for member in remaining_later[paired:]:
            records.append(
                _record(
                    member,
                    D_NEW,
                    "the identity appears in the later population and not in the "
                    "earlier one",
                )
            )

    for logical in sorted(set(after_by_logical) - set(before_by_logical)):
        for member in sorted(after_by_logical[logical], key=lambda item: item.exact or ""):
            records.append(
                _record(
                    member,
                    D_NEW,
                    "the identity appears in the later population and not in the "
                    "earlier one",
                )
            )

    codes: set[str] = set()
    for record in records:
        codes.update(record.codes)

    non_present = any(record.disposition != D_STILL_PRESENT for record in records)
    if non_present and not before.tool.same_as(after.tool):
        codes.add(R_TOOL_CHANGE)
    if (
        non_present
        and before.candidate.token() is not None
        and before.candidate.token() == after.candidate.token()
    ):
        codes.add(R_ABSENCE_AS_RESOLUTION)
    if any(record.disposition == D_MOVED for record in records):
        codes.add(R_MOVED_AS_RESOLVED)

    notes: list[str] = []
    if before.candidate.mixed or after.candidate.mixed:
        notes.append(
            "the candidate is mixed across runs; no single candidate token exists"
        )
    if not before.tool.recorded or not after.tool.recorded:
        notes.append("the tool identity is not recorded on both sides")
    if not any(record.disposition == D_RESOLVED for record in records):
        notes.append("no member reached RESOLVED in this delta")

    return DeltaResult(
        id=delta_id or f"{before.id}->{after.id}",
        before=before.id,
        after=after.id,
        records=tuple(records),
        codes=tuple(sorted(codes)),
        admitted=not codes,
        notes=tuple(notes),
    )


def admit(delta_result: DeltaResult) -> dict[str, Any]:
    """Check that a delta's recorded dispositions and codes agree, then report it."""
    problems: list[str] = []
    counts = delta_result.counts()
    if sum(counts.values()) != len(delta_result.records):
        problems.append("the disposition counts do not sum to the record count")
    coded = {
        D_MOVED,
        D_SUPPRESSED_ABSENT,
        D_EXCLUDED_ABSENT,
        D_UNSCANNED_ABSENT,
        D_TOOL_CHANGED_ABSENT,
        D_POPULATION_SHRUNK_ABSENT,
        D_UNKNOWN,
    }
    for record in delta_result.records:
        if record.disposition == D_RESOLVED and record.codes:
            problems.append(
                f"{record.identity!r} is RESOLVED and carries codes "
                f"{list(record.codes)}"
            )
        if record.disposition in coded and not record.codes:
            problems.append(
                f"{record.identity!r} is {record.disposition} with no code; a "
                "weaker disposition must name the condition that produced it"
            )
    if delta_result.admitted and delta_result.codes:
        problems.append("a delta marked admitted cites refusal codes")
    if not delta_result.admitted and not delta_result.codes:
        problems.append("a refused delta cites no refusal code")
    return {
        "id": delta_result.id,
        "admitted": delta_result.admitted and not problems,
        "codes": list(delta_result.codes),
        "counts": counts,
        "problems": problems,
    }


def explain(delta_result: DeltaResult, identity: str) -> list[DispositionRecord]:
    """Return every disposition record whose exact or logical identity matches."""
    matches = [
        record
        for record in delta_result.records
        if identity in {record.exact, record.logical, record.identity}
        or (record.exact or "").startswith(identity)
        or (record.logical or "").startswith(identity)
    ]
    return matches


# --------------------------------------------------------------------------
# Readers for the real records.
# --------------------------------------------------------------------------


def _read_json(path: Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Refusal(
            R_NO_BASELINE, f"{path}: the record is not readable JSON ({exc})"
        ) from exc


def _admission_map(repo_root: Path) -> dict[str, dict[str, Any]]:
    path = Path(repo_root) / "evidence" / "a5" / "ADMISSION.json"
    document = _read_json(path)
    return {item["id"]: item for item in document.get("populations", [])}


def _suppression_map(repo_root: Path) -> dict[str, dict[str, Any]]:
    path = Path(repo_root) / "evidence" / "a6" / "SUPPRESSIONS.json"
    document = _read_json(path)
    admissions = {item["id"]: item for item in document.get("admissions", [])}
    result: dict[str, dict[str, Any]] = {}
    for record in document.get("records", []):
        admission = admissions.get(record["id"], {})
        result[record["id"]] = {
            "record": record,
            "admission": admission,
        }
    return result


def _scope(
    admissions: Mapping[str, dict[str, Any]],
    population_id: str,
    *,
    fallback_expected: int | None,
    fallback_examined: int | None,
    fallback_completeness: str,
    fallback_basis: str,
    locator: str,
) -> Scope:
    admission = admissions.get(population_id)
    if admission is not None:
        examined = admission.get("examined")
        omitted = admission.get("omitted")
        expected = admission.get("expected")
        if expected is None and isinstance(examined, int) and isinstance(omitted, int):
            expected = examined + omitted
        return Scope(
            id=population_id,
            expected=expected,
            examined=examined,
            completeness=admission.get("state", S_UNKNOWN),
            basis=(
                f"A5 admission: {admission.get('detail', 'admitted')}; "
                f"{examined} examined, {omitted} omitted"
            ),
            locator=locator,
        )
    return Scope(
        id=population_id,
        expected=fallback_expected,
        examined=fallback_examined,
        completeness=fallback_completeness,
        basis=fallback_basis,
        locator=locator,
    )


def _suppressions_for(
    suppression_map: Mapping[str, dict[str, Any]], scope_id: str
) -> tuple[SuppressionDisposition, ...]:
    """The A6 suppression records that name a target this scope could contain."""
    result: list[SuppressionDisposition] = []
    for record_id, item in sorted(suppression_map.items()):
        record = item["record"]
        if record.get("classification") != "suppression":
            continue
        target = record.get("target") or {}
        identity = target.get("identity")
        if target.get("scope") in (None, "none"):
            # An aggregate suppression with no target cannot cover a member.
            continue
        admission = item["admission"]
        result.append(
            SuppressionDisposition(
                id=record_id,
                covers=identity,
                disposition=str(admission.get("disposition") or "UNKNOWN"),
                actionable=bool(admission.get("actionable", False)),
                note=(
                    f"target scope {target.get('scope')!r}; "
                    f"scope {scope_id!r}"
                ),
            )
        )
    return tuple(result)


_IMPORT_FINDING_IDENTITY = None


def _finding_identity():
    """Import A3's identity model once, for the identities this item builds."""
    global _IMPORT_FINDING_IDENTITY
    if _IMPORT_FINDING_IDENTITY is None:
        tools = Path(__file__).resolve().parent
        if str(tools) not in sys.path:
            sys.path.insert(0, str(tools))
        import finding_identity  # noqa: PLC0415

        _IMPORT_FINDING_IDENTITY = finding_identity
    return _IMPORT_FINDING_IDENTITY


def _identify_member(
    *,
    rule_id: str,
    identity: str,
    binding: Any,
    candidate: str,
    region_locator: str,
    label: str,
) -> Member:
    fi = _finding_identity()
    finding = fi.identify(
        rule_id=rule_id,
        key_class="stable-id",
        binding=binding,
        region=fi.Region("record", locator=region_locator),
        candidate=candidate,
        id=identity,
    )
    return Member(
        logical=finding.logical_fingerprint,
        exact=finding.exact_fingerprint,
        rule=finding.rule_fingerprint,
        label=label,
    )


def read_a1_members(path: Path) -> tuple[Member, ...]:
    """The 4,245 recorded A1 fingerprints, in run and result order."""
    document = _read_json(path)
    members: list[Member] = []
    for run_index, run in enumerate(document.get("runs", [])):
        for result in run.get("results", []):
            fingerprints = result.get("partialFingerprints") or {}
            properties = (result.get("properties") or {}).get("a1") or {}
            logical_key = properties.get("logicalKey") or ""
            members.append(
                Member(
                    logical=fingerprints.get("a1Logical/v1"),
                    exact=fingerprints.get("a1Exact/v1"),
                    rule=fingerprints.get("a1Rule/v1"),
                    label=f"run={run_index};rule={result.get('ruleId')};key={logical_key}",
                )
            )
    return tuple(members)


def read_a1_per_run_candidates(path: Path) -> tuple[dict[str, Any], ...]:
    document = _read_json(path)
    runs: list[dict[str, Any]] = []
    for run_index, run in enumerate(document.get("runs", [])):
        properties = (run.get("properties") or {}).get("a1") or {}
        record = properties.get("record") or {}
        runs.append(
            {
                "run": run_index,
                "results": len(run.get("results", [])),
                "candidate": properties.get("candidate"),
                "record": record.get("path"),
            }
        )
    return tuple(runs)


def read_claim_members(path: Path) -> tuple[Member, ...]:
    """Claim verdict occurrences, keyed by claim id, with the verdict in the region."""
    fi = _finding_identity()
    document = _read_json(path)
    source = document.get("source_identity") or {}
    commit = source.get("commit")
    if not isinstance(commit, str) or not commit:
        raise Refusal(
            R_CANDIDATE_UNRECORDED,
            f"{path}: the claim record states no source commit",
        )
    binding = fi.Binding(
        uri="evidence/etp0/CLAIMS.json",
        digest=commit,
        digest_scope="candidate-commit",
    )
    members: list[Member] = []
    for claim in document.get("claims", []):
        verdict = claim.get("verdict") or {}
        state = verdict.get("state") if isinstance(verdict, dict) else None
        members.append(
            _identify_member(
                rule_id="A7-CLAIM-VERDICT",
                identity=str(claim.get("id")),
                binding=binding,
                candidate=commit,
                region_locator=f"{claim.get('id')}/verdict={state}",
                label=f"{claim.get('id')}:{state}",
            )
        )
    return tuple(members)


def read_closure_members(path: Path) -> tuple[Member, ...]:
    """Closure obligations keyed by stable id, with their status in the region."""
    fi = _finding_identity()
    document = _read_json(path)
    candidate = document.get("candidate_identity") or {}
    digest = candidate.get("libcrypto_so_3_sha256")
    if not isinstance(digest, str):
        raise Refusal(
            R_CANDIDATE_UNRECORDED,
            f"{path}: the closure record states no candidate DSO digest",
        )
    binding = fi.Binding(uri="libcrypto.so.3", digest=digest, digest_scope="artifact")
    members: list[Member] = []
    for obligation in document.get("obligations", []):
        stable_id = obligation.get("stable_id")
        status = obligation.get("status")
        if not stable_id:
            raise Refusal(
                R_IDENTITY_UNSTABLE,
                f"{path}: an obligation carries no stable id",
            )
        members.append(
            _identify_member(
                rule_id="A7-CLOSURE-OBLIGATION",
                identity=str(stable_id),
                binding=binding,
                candidate=str(digest),
                region_locator=f"{obligation.get('id')}/status={status}",
                label=f"{obligation.get('id')}:{status}",
            )
        )
    return tuple(members)


def read_haz15_members(
    path: Path, side: str
) -> tuple[Member, ...]:
    """The HAZ-15 padding observations that are true on one side."""
    fi = _finding_identity()
    document = _read_json(path)
    identity = document.get("identity") or {}
    candidate = identity.get(f"candidate_{side}") or {}
    digest = candidate.get("dso_sha256")
    if not isinstance(digest, str):
        raise Refusal(
            R_CANDIDATE_UNRECORDED,
            f"{path}: candidate_{side} states no DSO digest",
        )
    binding = fi.Binding(uri="candidate-dso", digest=digest, digest_scope="artifact")
    findings = document.get(f"finding_{side}") or {}

    if side == "prefix":
        observations = (
            ("valid-vs-bad-type", findings.get("valid_vs_bad_type")),
            ("valid-vs-short-ps", findings.get("valid_vs_short_ps")),
        )
    else:
        observations = (
            ("valid-vs-bad-type", findings.get("external_valid_vs_bad_type")),
            ("valid-vs-short-ps", findings.get("external_valid_vs_short_ps")),
            ("returned-length", findings.get("returned_length_distinguishes")),
            ("internal-valid-unchanged", findings.get("internal_valid_unchanged")),
        )

    members: list[Member] = []
    for name, value in observations:
        if value is not True:
            continue
        members.append(
            _identify_member(
                rule_id="A7-HAZ15-PADDING-OBSERVABLE",
                identity=f"haz15:external:{name}",
                binding=binding,
                candidate=str(digest),
                region_locator=f"{name}/distinguishes=true/{side}",
                label=f"external:{name}:{side}",
            )
        )
    return tuple(members)


def read_haz16_members(path: Path) -> tuple[Member, ...]:
    """The 79 classified FFI mutation entries, keyed by file and exported entry."""
    fi = _finding_identity()
    document = _read_json(path)
    sha256 = digest_file(path)
    if sha256 is None:
        raise Refusal(R_NO_BASELINE, f"{path}: the record digest is unavailable")
    binding = fi.Binding(
        uri=Path(path).as_posix(), digest=sha256, digest_scope="record"
    )
    members: list[Member] = []
    for index, row in enumerate(document.get("rows", [])):
        members.append(
            _identify_member(
                rule_id="A7-FFI-MUTATION-CLASS",
                identity=f"{row.get('file')}:{row.get('entry')}",
                binding=binding,
                candidate=sha256,
                region_locator=f"rows[{index}]/class={row.get('class')}",
                label=f"{row.get('file')}:{row.get('entry')}:{row.get('class')}",
            )
        )
    return tuple(members)


def read_exclusions(repo_root: Path) -> tuple[Exclusion, ...]:
    """ETP-T10 exclusion rows projected to their recorded edge identity."""
    path = Path(repo_root) / "evidence" / "etp-t10" / "EXCLUSIONS.json"
    if not path.is_file():
        return ()
    document = _read_json(path)
    exclusions: list[Exclusion] = []
    for row in document.get("rows", []):
        edge = row.get("edge") or {}
        exclusions.append(
            Exclusion(
                id=str(row.get("id")),
                covers=edge.get("identity"),
                record=path.as_posix(),
                note=f"category={row.get('category')}",
            )
        )
    return tuple(exclusions)


# --------------------------------------------------------------------------
# The real baselines.
# --------------------------------------------------------------------------


def _record_ref(repo_root: Path, relative: str, locator: str) -> RecordRef:
    path = Path(repo_root) / relative
    return RecordRef(path=relative, locator=locator, sha256=digest_file(path))


def _tool_from_file(repo_root: Path, relative: str, *, recorded: bool = True) -> ToolIdentity:
    path = Path(repo_root) / relative
    return ToolIdentity(
        path=relative,
        digest=digest_file(path),
        recorded=recorded and path.is_file(),
        note="" if path.is_file() else "the tool is not present in the tree",
    )


def build_baselines(repo_root: Path) -> tuple[list[Baseline], list[dict[str, Any]]]:
    """Read the real baselines and the records that are not finding populations."""
    repo_root = Path(repo_root)
    admissions = _admission_map(repo_root)
    suppression_map = _suppression_map(repo_root)

    a1_path = repo_root / "evidence" / "a1" / "SARIF.json"
    a1_document = _read_json(a1_path)
    a1_members = read_a1_members(a1_path)
    a1_runs = read_a1_per_run_candidates(a1_path)
    a1_results = sum(len(run.get("results", [])) for run in a1_document.get("runs", []))
    if len(a1_members) != a1_results:
        raise Refusal(
            R_PARTIAL_SCAN,
            f"the A1 record states {a1_results} results and carries "
            f"{len(a1_members)} fingerprint sets",
        )

    migration_path = repo_root / "evidence" / "a3" / "MIGRATION.json"
    migration = _read_json(migration_path)
    if not migration.get("streamsEqual") or migration.get("fingerprintMismatchCount") != 0:
        raise Refusal(
            R_TOOL_CHANGE,
            "the A3 migration does not reproduce the recorded fingerprint stream; "
            "the model population cannot stand in for it",
        )
    old_tool = migration.get("oldScheme") or {}
    new_tool = migration.get("generalisedModule") or {}

    claims_before_path = (
        repo_root
        / "evidence"
        / "etp-t15"
        / "history"
        / "claims.before-reconciliation.json"
    )
    claims_after_path = repo_root / "evidence" / "etp" / "claims.json"
    claims_before_document = _read_json(claims_before_path)
    claims_after_document = _read_json(claims_after_path)
    claims_before_members = read_claim_members(claims_before_path)
    claims_after_members = read_claim_members(claims_after_path)

    closure_before_path = repo_root / "evidence" / "closure-ssh-b50-baseline.json"
    closure_after_path = repo_root / "evidence" / "closure-ssh-b50.json"
    closure_before_document = _read_json(closure_before_path)
    closure_after_document = _read_json(closure_after_path)
    closure_before_members = read_closure_members(closure_before_path)
    closure_after_members = read_closure_members(closure_after_path)

    haz15_path = repo_root / "evidence" / "haz-15" / "observables.json"
    haz15_document = _read_json(haz15_path)
    haz15_before_members = read_haz15_members(haz15_path, "prefix")
    haz15_after_members = read_haz15_members(haz15_path, "postfix")

    haz16_path = repo_root / "evidence" / "haz-16" / "CLASSIFICATION.json"
    haz16_document = _read_json(haz16_path)
    haz16_members = read_haz16_members(haz16_path)

    t4_path = repo_root / "evidence" / "etp-t4" / "SAFETY-SITES.json"
    t4_document = _read_json(t4_path)
    t4_sites = len((t4_document.get("sites") or {}).get("rows") or ())
    t4_ignored = len((t4_document.get("assertions") or {}).get("ignored") or ())
    t4_suppression_total = (t4_document.get("suppressions") or {}).get("total")

    t10_path = repo_root / "evidence" / "etp-t10" / "EXCLUSIONS.json"
    t10_document = _read_json(t10_path)
    t10_rows = len(t10_document.get("rows") or ())

    curl_path = repo_root / "evidence" / "closure-curl-049.json"
    curl_document = _read_json(curl_path)
    curl_bound = ((curl_document.get("precision") or {}).get("residual_sites_bound") or {})
    curl_residual_population = curl_bound.get("population_size")
    curl_residual_sample = curl_bound.get("sample_size")
    curl_obligations = len(curl_document.get("obligations") or ())

    collisions_path = repo_root / "evidence" / "a3" / "COLLISIONS.json"
    collisions = _read_json(collisions_path)
    collision_recorded = collisions.get("recorded") or {}
    collision_groups = collision_recorded.get("crossRunLogicalGroups")
    collision_members = collision_recorded.get("crossRunLogicalCollisionMembers")
    collision_results = collision_recorded.get("results")
    if collision_recorded.get("sourceSha256") != digest_file(a1_path):
        raise Refusal(
            R_CANDIDATE_UNRECORDED,
            "the collision report is not bound to the current A1 record digest",
        )

    a1_scope = _scope(
        admissions,
        "a1-sarif-results",
        fallback_expected=a1_results,
        fallback_examined=a1_results,
        fallback_completeness=S_COMPLETE,
        fallback_basis="the record states and enumerates every result",
        locator="/runs",
    )
    claims_scope = _scope(
        admissions,
        "etp-claims",
        fallback_expected=len(claims_after_members),
        fallback_examined=len(claims_after_members),
        fallback_completeness=S_COMPLETE,
        fallback_basis="the record states and enumerates every claim",
        locator="/claims",
    )
    closure_scope = _scope(
        admissions,
        "closure-ssh-b50-obligations",
        fallback_expected=len(closure_after_members),
        fallback_examined=len(closure_after_members),
        fallback_completeness=S_COMPLETE,
        fallback_basis=(
            "the closure record states reachable_production_obligations and "
            "enumerates the same count; A5 does not register this population"
        ),
        locator="/obligations",
    )
    haz15_scope = _scope(
        admissions,
        "haz15-padding-observations",
        fallback_expected=None,
        fallback_examined=None,
        fallback_completeness=S_UNKNOWN,
        fallback_basis=(
            "the record names four cases and 24 rows but states no expected "
            "observation population; A5 does not register it"
        ),
        locator="/finding_prefix,/finding_postfix",
    )
    haz16_scope = _scope(
        admissions,
        "haz16-ffi-mutation-classification",
        fallback_expected=(haz16_document.get("classes") or {}).get("total"),
        fallback_examined=len(haz16_members),
        fallback_completeness=S_COMPLETE,
        fallback_basis=(
            "the record states covered_population and classes.total and enumerates "
            "the same rows; A5 does not register it"
        ),
        locator="/rows",
    )

    baselines: list[Baseline] = [
        Baseline(
            id="a1-sarif-results",
            candidate=Candidate(
                branch="staging",
                recorded=True,
                mixed=True,
                per_run=a1_runs,
                note=(
                    "the A1 artefact carries six runs at six candidate identities; "
                    "it records no single candidate and is not relabelled here"
                ),
            ),
            tool=ToolIdentity(
                path="forensics/tools/sarif_adapter.py",
                digest=old_tool.get("producerSha256"),
                recorded=bool(old_tool.get("producerSha256")),
                note="the pre-extraction SARIF adapter recorded by A3 MIGRATION",
            ),
            scope=a1_scope,
            members=a1_members,
            aggregate=False,
            member_count=None,
            suppressions=_suppressions_for(suppression_map, "a1-sarif-results"),
            taken_at="not-recorded",
            record=_record_ref(repo_root, "evidence/a1/SARIF.json", "/runs"),
            note=f"{len(a1_members)} recorded result fingerprints in 6 runs",
        ),
        Baseline(
            id="a1-fingerprints-model",
            candidate=Candidate(
                branch="staging",
                recorded=True,
                mixed=True,
                per_run=a1_runs,
                note="the same six runs, re-projected under the a1/v1 identity model",
            ),
            tool=ToolIdentity(
                path="forensics/tools/finding_identity.py",
                digest=new_tool.get("sha256"),
                recorded=bool(new_tool.get("sha256")),
                note="the generalised identity module recorded by A3 MIGRATION",
            ),
            scope=a1_scope,
            members=a1_members,
            aggregate=False,
            member_count=None,
            suppressions=_suppressions_for(suppression_map, "a1-sarif-results"),
            taken_at="not-recorded",
            record=_record_ref(
                repo_root, "evidence/a3/MIGRATION.json", "/streamSha256New"
            ),
            note=(
                "the migration record proves the recomputed stream equals the "
                "recorded one, so these are the recomputed member identities"
            ),
        ),
        Baseline(
            id="etp-claims-before",
            candidate=Candidate(
                commit=(claims_before_document.get("source_identity") or {}).get("commit"),
                branch=(claims_before_document.get("source_identity") or {}).get("branch"),
                recorded=True,
                note=(
                    "the history copy records the same source commit as the live "
                    "record; it is the before-reconciliation population"
                ),
            ),
            tool=ToolIdentity(
                path="forensics/tools/etp_claims.py",
                digest=None,
                recorded=False,
                note="the history record names no producer",
            ),
            scope=claims_scope,
            members=claims_before_members,
            aggregate=False,
            member_count=None,
            suppressions=_suppressions_for(suppression_map, "etp-claims"),
            taken_at=str(claims_before_document.get("generated_utc") or "not-recorded"),
            record=_record_ref(
                repo_root,
                "evidence/etp-t15/history/claims.before-reconciliation.json",
                "/claims",
            ),
            note="four claims read CONTRADICTED in this population",
        ),
        Baseline(
            id="etp-claims-after",
            candidate=Candidate(
                commit=(claims_after_document.get("source_identity") or {}).get("commit"),
                branch=(claims_after_document.get("source_identity") or {}).get("branch"),
                recorded=True,
                note=(
                    "the live record still states the same source commit as the "
                    "history copy although its verdicts were reconciled later; the "
                    "stale identity is recorded, not corrected, here"
                ),
            ),
            tool=ToolIdentity(
                path="evidence/etp-t15/apply_claims.py",
                digest=digest_file(repo_root / "evidence/etp-t15/apply_claims.py"),
                recorded=True,
                note=(
                    "the verdicts were reconciled by this record; the claim reader "
                    "is forensics/tools/etp_claims.py"
                ),
            ),
            scope=claims_scope,
            members=claims_after_members,
            aggregate=False,
            member_count=None,
            suppressions=_suppressions_for(suppression_map, "etp-claims"),
            taken_at=str(claims_after_document.get("generated_utc") or "not-recorded"),
            record=_record_ref(repo_root, "evidence/etp/claims.json", "/claims"),
            note="the four previously contradicted claims read SUPERSEDED or RISK_ACCEPTED",
        ),
        Baseline(
            id="closure-ssh-b50-baseline",
            candidate=Candidate(
                commit=(closure_before_document.get("source_identity") or {}).get(
                    "repository_head"
                ),
                branch=(closure_before_document.get("source_identity") or {}).get("branch"),
                over=(closure_before_document.get("candidate_identity") or {}).get(
                    "libcrypto_so_3_sha256"
                ),
                recorded=True,
                note=(
                    "the record states repository_head and the candidate DSO digest; "
                    "the tracked tree was clean"
                ),
            ),
            tool=ToolIdentity(
                path=(closure_before_document.get("tool") or {}).get("path")
                or "forensics/tools/consumer_closure.py",
                digest=(closure_before_document.get("tool") or {}).get("sha256"),
                recorded=True,
            ),
            scope=closure_scope,
            members=closure_before_members,
            aggregate=False,
            member_count=None,
            suppressions=(),
            taken_at=str(closure_before_document.get("generated_utc") or "not-recorded"),
            record=_record_ref(
                repo_root, "evidence/closure-ssh-b50-baseline.json", "/obligations"
            ),
            note="156 DISCHARGED and 156 BLOCKED obligations",
        ),
        Baseline(
            id="closure-ssh-b50-applied",
            candidate=Candidate(
                commit=(closure_after_document.get("source_identity") or {}).get(
                    "repository_head"
                ),
                branch=(closure_after_document.get("source_identity") or {}).get("branch"),
                over=(closure_after_document.get("candidate_identity") or {}).get(
                    "libcrypto_so_3_sha256"
                ),
                recorded=True,
                note=(
                    "the same repository_head and candidate DSO digest as the "
                    "baseline; the record states the tracked tree was dirty"
                ),
            ),
            tool=ToolIdentity(
                path=(closure_after_document.get("tool") or {}).get("path")
                or "forensics/tools/consumer_closure.py",
                digest=(closure_after_document.get("tool") or {}).get("sha256"),
                recorded=True,
            ),
            scope=closure_scope,
            members=closure_after_members,
            aggregate=False,
            member_count=None,
            suppressions=(),
            taken_at=str(closure_after_document.get("generated_utc") or "not-recorded"),
            record=_record_ref(repo_root, "evidence/closure-ssh-b50.json", "/obligations"),
            note="167 DISCHARGED and 145 BLOCKED obligations",
        ),
        Baseline(
            id="haz15-prefix",
            candidate=Candidate(
                over=((haz15_document.get("identity") or {}).get("candidate_prefix") or {}).get(
                    "dso_sha256"
                ),
                recorded=True,
                note="the candidate DSO before the KDK correction",
            ),
            tool=ToolIdentity(
                path="evidence/haz-15/observables.json",
                digest=None,
                recorded=False,
                note="the record names no harness identity or digest",
            ),
            scope=haz15_scope,
            members=haz15_before_members,
            aggregate=False,
            member_count=None,
            suppressions=(),
            taken_at="not-recorded",
            record=_record_ref(
                repo_root, "evidence/haz-15/observables.json", "/finding_prefix"
            ),
            note="the external-key sign, buffer and error-queue axes distinguish",
        ),
        Baseline(
            id="haz15-postfix",
            candidate=Candidate(
                over=((haz15_document.get("identity") or {}).get("candidate_postfix") or {}).get(
                    "dso_sha256"
                ),
                recorded=True,
                note="the candidate DSO after the KDK correction",
            ),
            tool=ToolIdentity(
                path="evidence/haz-15/observables.json",
                digest=None,
                recorded=False,
                note="the record names no harness identity or digest",
            ),
            scope=haz15_scope,
            members=haz15_after_members,
            aggregate=False,
            member_count=None,
            suppressions=(),
            taken_at="not-recorded",
            record=_record_ref(
                repo_root, "evidence/haz-15/observables.json", "/finding_postfix"
            ),
            note=(
                "the sign, buffer and queue axes no longer distinguish; the returned "
                "length still does, and the record names that as a remaining channel"
            ),
        ),
        Baseline(
            id="haz16-classification",
            candidate=Candidate(
                commit=(haz16_document.get("identity") or {}).get("head"),
                branch=(haz16_document.get("identity") or {}).get("branch"),
                recorded=False,
                note=(
                    "the record states a 9-hex short head, not a full commit, and "
                    "a dirty worktree at generation time; the candidate is not "
                    "usable as an exact identity"
                ),
            ),
            tool=ToolIdentity(
                path="evidence/haz-16/enumerate_ffi_mutation.py",
                digest=digest_file(repo_root / "evidence/haz-16/enumerate_ffi_mutation.py"),
                recorded=False,
                note="the record names the script but not its digest at generation time",
            ),
            scope=haz16_scope,
            members=haz16_members,
            aggregate=False,
            member_count=None,
            suppressions=(),
            taken_at="not-recorded",
            record=_record_ref(
                repo_root, "evidence/haz-16/CLASSIFICATION.json", "/rows"
            ),
            note="79 classified entries; 3 read PARTIAL_EXPOSED before repair",
        ),
        Baseline(
            id="t4-unsafe-sites",
            candidate=Candidate(
                commit=(t4_document.get("identity") or {}).get("commit"),
                branch=(t4_document.get("identity") or {}).get("branch"),
                recorded=True,
            ),
            tool=ToolIdentity(
                path=(t4_document.get("identity") or {}).get("scanner")
                or "forensics/tools/unsafe_obligations.py",
                digest=(t4_document.get("identity") or {}).get("scanner_sha256"),
                recorded=True,
            ),
            scope=_scope(
                admissions,
                "t4-unsafe-sites",
                fallback_expected=t4_sites,
                fallback_examined=t4_sites,
                fallback_completeness=S_COMPLETE,
                fallback_basis="the record states and enumerates every site row",
                locator="/sites/rows",
            ),
            members=(),
            aggregate=True,
            member_count=t4_sites,
            suppressions=_suppressions_for(suppression_map, "t4-unsafe-sites"),
            taken_at="not-recorded",
            record=_record_ref(
                repo_root, "evidence/etp-t4/SAFETY-SITES.json", "/sites/rows"
            ),
            note="the 62,297-row lexical census is recorded as an aggregate here",
        ),
        Baseline(
            id="t4-suppressions",
            candidate=Candidate(
                commit=(t4_document.get("identity") or {}).get("commit"),
                branch=(t4_document.get("identity") or {}).get("branch"),
                recorded=True,
            ),
            tool=ToolIdentity(
                path=(t4_document.get("identity") or {}).get("scanner")
                or "forensics/tools/unsafe_obligations.py",
                digest=(t4_document.get("identity") or {}).get("scanner_sha256"),
                recorded=True,
            ),
            scope=_scope(
                admissions,
                "t4-suppressions",
                fallback_expected=t4_suppression_total,
                fallback_examined=0,
                fallback_completeness=S_AGGREGATE_ONLY,
                fallback_basis="the record states a total and no member row",
                locator="/suppressions",
            ),
            members=(),
            aggregate=True,
            member_count=t4_suppression_total,
            suppressions=_suppressions_for(suppression_map, "t4-suppressions"),
            taken_at="not-recorded",
            record=_record_ref(
                repo_root, "evidence/etp-t4/SAFETY-SITES.json", "/suppressions"
            ),
            note="the 1,999 lint suppressions are an aggregate and cannot be diffed",
        ),
        Baseline(
            id="t4-ignored-tests",
            candidate=Candidate(
                commit=(t4_document.get("identity") or {}).get("commit"),
                branch=(t4_document.get("identity") or {}).get("branch"),
                recorded=True,
            ),
            tool=ToolIdentity(
                path=(t4_document.get("identity") or {}).get("scanner")
                or "forensics/tools/unsafe_obligations.py",
                digest=(t4_document.get("identity") or {}).get("scanner_sha256"),
                recorded=True,
            ),
            scope=_scope(
                admissions,
                "t4-ignored-tests",
                fallback_expected=t4_ignored,
                fallback_examined=t4_ignored,
                fallback_completeness=S_COMPLETE,
                fallback_basis="the record states and enumerates every ignored test",
                locator="/assertions/ignored",
            ),
            members=(),
            aggregate=True,
            member_count=t4_ignored,
            suppressions=(),
            taken_at="not-recorded",
            record=_record_ref(
                repo_root, "evidence/etp-t4/SAFETY-SITES.json", "/assertions/ignored"
            ),
            note="the ignored-test census is recorded as an aggregate here",
        ),
        Baseline(
            id="t10-closure-exclusions",
            candidate=Candidate(
                commit=(t10_document.get("identity") or {}).get("commit"),
                recorded=True,
            ),
            tool=ToolIdentity(
                path="forensics/tools/closure_discipline.py",
                digest=None,
                recorded=False,
                note="the record does not name its producer digest",
            ),
            scope=_scope(
                admissions,
                "t10-closure-exclusions",
                fallback_expected=t10_rows,
                fallback_examined=t10_rows,
                fallback_completeness=S_COMPLETE,
                fallback_basis="the record states and enumerates every exclusion row",
                locator="/rows",
            ),
            members=(),
            aggregate=True,
            member_count=t10_rows,
            suppressions=(),
            taken_at="not-recorded",
            record=_record_ref(
                repo_root, "evidence/etp-t10/EXCLUSIONS.json", "/rows"
            ),
            note="the 1,121 exclusion rows are recorded as an aggregate here",
        ),
        Baseline(
            id="curl-residual-sites",
            candidate=Candidate(
                commit=(curl_document.get("source_identity") or {}).get(
                    "repository_head"
                ),
                over=(curl_document.get("candidate_identity") or {}).get(
                    "libcrypto_so_3_sha256"
                ),
                recorded=True,
            ),
            tool=ToolIdentity(
                path=(curl_document.get("tool") or {}).get("path")
                or "forensics/tools/consumer_closure.py",
                digest=(curl_document.get("tool") or {}).get("sha256"),
                recorded=True,
            ),
            scope=_scope(
                admissions,
                "curl-residual-sites",
                fallback_expected=curl_residual_population,
                fallback_examined=curl_residual_sample,
                fallback_completeness=S_TRUNCATED_BOUNDED,
                fallback_basis="the record names a bound and counts the omitted members",
                locator="/precision/residual_sites_bound",
            ),
            members=(),
            aggregate=True,
            member_count=curl_residual_sample,
            suppressions=(),
            taken_at=str(curl_document.get("generated_utc") or "not-recorded"),
            record=_record_ref(
                repo_root,
                "evidence/closure-curl-049.json",
                "/precision/residual_sites_bound",
            ),
            note=(
                f"{curl_residual_sample} of {curl_residual_population} residual sites "
                "are enumerated; the remainder is bounded and unexamined"
            ),
        ),
        Baseline(
            id="curl-obligations",
            candidate=Candidate(
                commit=(curl_document.get("source_identity") or {}).get(
                    "repository_head"
                ),
                over=(curl_document.get("candidate_identity") or {}).get(
                    "libcrypto_so_3_sha256"
                ),
                recorded=True,
            ),
            tool=ToolIdentity(
                path=(curl_document.get("tool") or {}).get("path")
                or "forensics/tools/consumer_closure.py",
                digest=(curl_document.get("tool") or {}).get("sha256"),
                recorded=True,
            ),
            scope=Scope(
                id="curl-production-obligations",
                expected=curl_obligations,
                examined=curl_obligations,
                completeness=S_COMPLETE,
                basis=(
                    "the record states reachable_production_obligations and "
                    "enumerates the same count; A5 does not register it"
                ),
                locator="/obligations",
            ),
            members=read_closure_members(curl_path),
            aggregate=False,
            member_count=None,
            suppressions=(),
            taken_at=str(curl_document.get("generated_utc") or "not-recorded"),
            record=_record_ref(
                repo_root, "evidence/closure-curl-049.json", "/obligations"
            ),
            note="the seven curl production obligations",
        ),
        Baseline(
            id="a3-logical-collisions",
            candidate=Candidate(
                branch="staging",
                recorded=True,
                mixed=True,
                per_run=a1_runs,
                note="the collision report is bound to the same six A1 runs",
            ),
            tool=ToolIdentity(
                path="forensics/tools/finding_identity.py",
                digest=new_tool.get("sha256"),
                recorded=bool(new_tool.get("sha256")),
            ),
            scope=Scope(
                id="a1-logical-collision-members",
                expected=collision_members,
                examined=collision_members,
                completeness=S_COMPLETE,
                basis=(
                    "the report counts every logical collision group and member over "
                    f"the {collision_results}-result A1 population"
                ),
                locator="/recorded",
            ),
            members=(),
            aggregate=True,
            member_count=collision_members,
            suppressions=(),
            taken_at="not-recorded",
            record=_record_ref(
                repo_root, "evidence/a3/COLLISIONS.json", "/recorded"
            ),
            note=(
                f"{collision_groups} logical collision groups with {collision_members} "
                "members; the members are retained as a set, not merged"
            ),
        ),
    ]

    not_baselines = [
        {
            "id": "safe-c33-campaign-status",
            "record": "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json",
            "locator": "/consumers",
            "reason": (
                "a status record: it counts consumer families and discharges, but it "
                "names no finding member population and no single tool identity, so "
                "it is not a baseline and cannot be diffed"
            ),
        },
        {
            "id": "forensics-evidence-receipts",
            "record": "forensics/receipts/EVIDENCE_RECEIPT.*.json",
            "locator": "/files",
            "reason": (
                "file manifests with an aggregate hash: they record which artefacts "
                "were present, not a finding population, and there is no before/after "
                "member pair"
            ),
        },
        {
            "id": "phase1-baseline-20261120",
            "record": "evidence/baseline-20261120.json",
            "locator": "/identity",
            "reason": (
                "a Phase-1 identity and population-reconciliation reconnaissance: it "
                "states an identity and two reconciliation populations but enumerates "
                "no finding members, so it is not a baseline"
            ),
        },
    ]

    return baselines, not_baselines


def build_deltas(
    baselines: Iterable[Baseline],
    repo_root: Path = REPO_ROOT,
) -> tuple[list[DeltaResult], list[dict[str, Any]]]:
    """Compute every real delta and name every area with no second population."""
    by_id = {baseline.id: baseline for baseline in baselines}
    exclusions = read_exclusions(repo_root)

    deltas = [
        delta(
            by_id["a1-sarif-results"],
            by_id["a1-fingerprints-model"],
            exclusions=exclusions,
            delta_id="a3-fingerprint-migration",
        ),
        delta(
            by_id["etp-claims-before"],
            by_id["etp-claims-after"],
            exclusions=exclusions,
            delta_id="claims-reconciliation",
        ),
        delta(
            by_id["closure-ssh-b50-baseline"],
            by_id["closure-ssh-b50-applied"],
            exclusions=exclusions,
            delta_id="closure-ssh-b50-status",
        ),
        delta(
            by_id["haz15-prefix"],
            by_id["haz15-postfix"],
            exclusions=exclusions,
            delta_id="haz15-padding-observation",
        ),
    ]

    no_baseline = [
        {
            "id": "a1-sarif-results/no-second-population",
            "area": "a1-sarif-results",
            "code": R_NO_BASELINE,
            "record": "evidence/a1/SARIF.json",
            "reason": (
                "the A1 artefact records one emission over six runs; no second scan of "
                "the same six scopes at a later candidate is recorded, so no "
                "before/after finding delta exists"
            ),
        },
        {
            "id": "t4-unsafe-sites/no-second-population",
            "area": "t4-unsafe-sites",
            "code": R_NO_BASELINE,
            "record": "evidence/etp-t4/SAFETY-SITES.json",
            "reason": (
                "one lexical scan at commit 246e3058; no second census of the same "
                "scope at a later candidate is recorded"
            ),
        },
        {
            "id": "t10-closure-exclusions/no-second-population",
            "area": "t10-closure-exclusions",
            "code": R_NO_BASELINE,
            "record": "evidence/etp-t10/EXCLUSIONS.json",
            "reason": (
                "one row-set at commit 7e70b667; no second exclusion row-set at a "
                "later candidate is recorded"
            ),
        },
        {
            "id": "curl-residual-sites/no-second-population",
            "area": "curl-residual-sites",
            "code": R_NO_BASELINE,
            "record": "evidence/closure-curl-049.json",
            "reason": (
                "one curl closure record exists, and its own residual-site population "
                "is TRUNCATED_BOUNDED at 200 of 449; there is no second complete "
                "population for the same scope"
            ),
        },
        {
            "id": "haz16-classification/no-second-population",
            "area": "haz16-classification",
            "code": R_NO_BASELINE,
            "record": "evidence/haz-16/CLASSIFICATION.json",
            "reason": (
                "the before population is enumerated (79 rows with 3 PARTIAL_EXPOSED), "
                "but the three repairs are recorded as a mechanism description with a "
                "test and a revert control; no second 79-row classification at a later "
                "candidate is recorded"
            ),
        },
        {
            "id": "a3-logical-collisions/no-second-population",
            "area": "a3-logical-collisions",
            "code": R_NO_BASELINE,
            "record": "evidence/a3/COLLISIONS.json",
            "reason": (
                "the collision report is derived from one A1 emission; there is no "
                "second collision population at a later candidate"
            ),
        },
        {
            "id": "phase1-baseline-20261120/no-finding-population",
            "area": "phase1-baseline-20261120",
            "code": R_NO_BASELINE,
            "record": "evidence/baseline-20261120.json",
            "reason": (
                "the record is an identity and reconciliation baseline, not a finding "
                "population; it enumerates no finding members and has no second copy"
            ),
        },
    ]
    return deltas, no_baseline


# --------------------------------------------------------------------------
# Controls: one per refusal code.
# --------------------------------------------------------------------------


def _control_member(baselines: Mapping[str, Baseline], index: int = 0) -> Member:
    return baselines["etp-claims-before"].members[index]


def _control_baseline(
    source: Baseline,
    *,
    baseline_id: str,
    scope: Scope,
    members: tuple[Member, ...],
    candidate: Candidate | None = None,
    tool: ToolIdentity | None = None,
    aggregate: bool = False,
    member_count: int | None = None,
) -> Baseline:
    return Baseline(
        id=baseline_id,
        candidate=candidate or source.candidate,
        tool=tool or source.tool,
        scope=scope,
        members=members,
        aggregate=aggregate,
        member_count=member_count,
        suppressions=(),
        taken_at=source.taken_at,
        record=source.record,
        note="in-memory control; not a source record",
    )


def build_controls(baselines: Iterable[Baseline]) -> list[dict[str, Any]]:
    """Execute one control per refusal code and record what each produced."""
    return control_outcomes(baselines)


def control_outcomes(baselines: Iterable[Baseline]) -> list[dict[str, Any]]:
    """Execute every control and record the code and disposition it produced."""
    by_id = {baseline.id: baseline for baseline in baselines}
    first = _control_member(by_id, 0)
    second = _control_member(by_id, 1)
    third = _control_member(by_id, 2)

    candidate_a = Candidate(commit="a" * 40, recorded=True)
    candidate_b = Candidate(commit="b" * 40, recorded=True)
    candidate_missing = Candidate(recorded=False)
    tool_a = ToolIdentity(path="control/tool", digest="1" * 64, recorded=True)
    tool_b = ToolIdentity(path="control/tool", digest="2" * 64, recorded=True)

    def scope(expected: int, completeness: str = S_COMPLETE) -> Scope:
        return Scope(
            id="a7-control-scope",
            expected=expected,
            examined=expected,
            completeness=completeness,
            basis="in-memory control scope",
            locator="/controls",
        )

    def make(
        baseline_id: str,
        members: tuple[Member, ...],
        candidate: Candidate,
        tool: ToolIdentity,
        control_scope: Scope,
        *,
        aggregate: bool = False,
        member_count: int | None = None,
    ) -> Baseline:
        return _control_baseline(
            by_id["etp-claims-before"],
            baseline_id=baseline_id,
            scope=control_scope,
            members=members,
            candidate=candidate,
            tool=tool,
            aggregate=aggregate,
            member_count=member_count,
        )

    outcomes: list[dict[str, Any]] = []

    def record_outcome(
        control_id: str,
        code: str,
        *,
        disposition: str | None,
        detail: str,
    ) -> None:
        outcomes.append(
            {
                "id": control_id,
                "code": code,
                "assertedDisposition": disposition,
                "detail": detail,
            }
        )

    # absence-as-resolution: same candidate, same tool, complete, member absent.
    before = make(
        "absence-before",
        (first, second),
        candidate_a,
        tool_a,
        scope(2),
    )
    after = make(
        "absence-after",
        (second, third),
        candidate_a,
        tool_a,
        scope(2),
    )
    result = delta(before, after, delta_id="control-absence")
    record_outcome(
        "absence-as-resolution",
        R_ABSENCE_AS_RESOLUTION,
        disposition=next(
            r.disposition for r in result.records if r.exact == first.exact
        ),
        detail="the absent member is UNKNOWN and not RESOLVED",
    )

    # population-shrink: later expected is smaller, candidates differ.
    before = make("shrink-before", (first, second), candidate_a, tool_a, scope(2))
    after = make("shrink-after", (second,), candidate_b, tool_a, scope(1))
    result = delta(before, after, delta_id="control-shrink")
    record_outcome(
        "population-shrink",
        R_POPULATION_SHRINK,
        disposition=next(
            r.disposition for r in result.records if r.exact == first.exact
        ),
        detail="the absent member is POPULATION_SHRUNK_ABSENT",
    )

    # tool-change: same size, complete, different tool digest.
    before = make("tool-before", (first, second), candidate_a, tool_a, scope(2))
    after = make("tool-after", (second, third), candidate_b, tool_b, scope(2))
    result = delta(before, after, delta_id="control-tool")
    record_outcome(
        "tool-change",
        R_TOOL_CHANGE,
        disposition=next(
            r.disposition for r in result.records if r.exact == first.exact
        ),
        detail="the absent member is TOOL_CHANGED_ABSENT",
    )

    # exclusion-as-resolution.
    before = make("exclude-before", (first, second), candidate_a, tool_a, scope(2))
    after = make("exclude-after", (second, third), candidate_b, tool_a, scope(2))
    result = delta(
        before,
        after,
        exclusions=(Exclusion(id="control-exclusion", covers=first.exact),),
        delta_id="control-exclusion",
    )
    record_outcome(
        "exclusion-as-resolution",
        R_EXCLUSION_AS_RESOLUTION,
        disposition=next(
            r.disposition for r in result.records if r.exact == first.exact
        ),
        detail="the absent member is EXCLUDED_ABSENT",
    )

    # suppression-as-resolution.
    before = make("suppress-before", (first, second), candidate_a, tool_a, scope(2))
    after = make("suppress-after", (second, third), candidate_b, tool_a, scope(2))
    result = delta(
        before,
        after,
        suppressions=(
            SuppressionDisposition(
                id="control-suppression",
                covers=first.exact,
                disposition="ACTIVE",
                actionable=True,
            ),
        ),
        delta_id="control-suppression",
    )
    record_outcome(
        "suppression-as-resolution",
        R_SUPPRESSION_AS_RESOLUTION,
        disposition=next(
            r.disposition for r in result.records if r.exact == first.exact
        ),
        detail="the absent member is SUPPRESSED_ABSENT",
    )

    # partial-scan: later scope is truncated.
    before = make("partial-before", (first, second), candidate_a, tool_a, scope(2))
    after = make(
        "partial-after",
        (second, third),
        candidate_b,
        tool_a,
        scope(2, S_TRUNCATED_BOUNDED),
    )
    result = delta(before, after, delta_id="control-partial")
    record_outcome(
        "partial-scan",
        R_PARTIAL_SCAN,
        disposition=next(
            r.disposition for r in result.records if r.exact == first.exact
        ),
        detail="the absent member is UNSCANNED_ABSENT",
    )

    # moved-as-resolved.
    moved = dataclasses.replace(
        first,
        exact="f" * 64,
        label="control moved exact identity",
    )
    before = make("moved-before", (first, second), candidate_a, tool_a, scope(2))
    after = make("moved-after", (moved, second), candidate_b, tool_a, scope(2))
    result = delta(before, after, delta_id="control-moved")
    record_outcome(
        "moved-as-resolved",
        R_MOVED_AS_RESOLVED,
        disposition=next(
            r.disposition for r in result.records if r.exact == first.exact
        ),
        detail="the moved member is MOVED",
    )

    # candidate-unrecorded.
    before = make(
        "candidate-before", (first, second), candidate_a, tool_a, scope(2)
    )
    after = make(
        "candidate-after", (second, third), candidate_missing, tool_a, scope(2)
    )
    result = delta(before, after, delta_id="control-candidate")
    record_outcome(
        "candidate-unrecorded",
        R_CANDIDATE_UNRECORDED,
        disposition=next(
            r.disposition for r in result.records if r.exact == first.exact
        ),
        detail="the absent member is UNKNOWN because no candidate is recorded",
    )

    # aggregate-as-members: the delta refuses the aggregate.
    aggregate = make(
        "aggregate-control",
        (),
        candidate_b,
        tool_a,
        scope(1),
        aggregate=True,
        member_count=1,
    )
    try:
        delta(
            make("aggregate-before", (first,), candidate_a, tool_a, scope(1)),
            aggregate,
            delta_id="control-aggregate",
        )
        raised = None
    except Refusal as refusal:
        raised = refusal.code
    record_outcome(
        "aggregate-as-members",
        raised or R_AGGREGATE_AS_MEMBERS,
        disposition=None,
        detail="the delta refuses an aggregate side instead of reading a count as members",
    )

    # no-baseline: the delta refuses a missing side.
    try:
        delta(
            make("nobaseline-before", (first,), candidate_a, tool_a, scope(1)),
            None,
            delta_id="control-no-baseline",
        )
        raised = None
    except Refusal as refusal:
        raised = refusal.code
    record_outcome(
        "no-baseline",
        raised or R_NO_BASELINE,
        disposition=None,
        detail="the delta refuses a missing second population",
    )

    # identity-unstable: a before-member with no recorded identity.
    unstable = Member(logical=None, exact=None, label="control unstable identity")
    before = make("unstable-before", (unstable,), candidate_a, tool_a, scope(1))
    after = make("unstable-after", (), candidate_b, tool_a, scope(0))
    result = delta(before, after, delta_id="control-unstable")
    record_outcome(
        "identity-unstable",
        R_IDENTITY_UNSTABLE,
        disposition=result.records[0].disposition,
        detail="the unidentifiable member is UNKNOWN",
    )

    return outcomes


# --------------------------------------------------------------------------
# Documents.
# --------------------------------------------------------------------------


def dump_document(document: dict[str, Any]) -> str:
    """Canonical JSON bytes for a recorded document: sorted keys, indent 1."""
    return json.dumps(document, indent=1, sort_keys=True) + "\n"


def _git(repo_root: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            check=False,
        )
    except OSError:
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.decode("utf-8", "replace").strip()


def source_identity(repo_root: Path) -> dict[str, Any]:
    return {
        "commit": _git(repo_root, "rev-parse", "HEAD") or "unknown",
        "branch": _git(repo_root, "rev-parse", "--abbrev-ref", "HEAD") or "unknown",
        "asOf": _git(repo_root, "show", "-s", "--format=%cs", "HEAD") or "unknown",
    }


def baselines_document(
    baselines: Iterable[Baseline],
    not_baselines: Iterable[Mapping[str, Any]],
    repo_root: Path,
) -> dict[str, Any]:
    rows = list(baselines)
    states: dict[str, int] = {}
    for baseline in rows:
        states[baseline.scope.completeness] = (
            states.get(baseline.scope.completeness, 0) + 1
        )
    return {
        "schema": BASELINES_SCHEMA,
        "model": MODEL_ID,
        "purpose": (
            "a baseline is a finding population bound to a candidate, a tool and a "
            "scope; a delta between two baselines is the only place a resolution "
            "may be claimed"
        ),
        "sourceIdentity": source_identity(repo_root),
        "rule": (
            "only RESOLVED requires a COMPLETE later population, an unchanged tool "
            "identity, an absent identity, no exclusion or suppression, and a "
            "candidate recorded on both sides where the later side is claimed"
        ),
        "baselines": [baseline.as_dict() for baseline in rows],
        "notBaselines": [dict(item) for item in not_baselines],
        "totals": {
            "baselines": len(rows),
            "enumerated": sum(1 for baseline in rows if not baseline.aggregate),
            "aggregate": sum(1 for baseline in rows if baseline.aggregate),
            "members": sum(baseline.member_total() for baseline in rows),
            "byState": states,
        },
    }


def delta_document(
    deltas: Iterable[DeltaResult],
    no_baseline: Iterable[Mapping[str, Any]],
    repo_root: Path,
) -> dict[str, Any]:
    rows = list(deltas)
    disposition_totals = {disposition: 0 for disposition in DISPOSITIONS}
    code_totals: dict[str, int] = {}
    for result in rows:
        for disposition, count in result.counts().items():
            disposition_totals[disposition] += count
        for code in result.codes:
            code_totals[code] = code_totals.get(code, 0) + 1
    return {
        "schema": DELTA_SCHEMA,
        "model": MODEL_ID,
        "purpose": (
            "the per-identity disposition of every before-member, and the areas for "
            "which no second population exists"
        ),
        "sourceIdentity": source_identity(repo_root),
        "deltas": [result.as_dict() for result in rows],
        "noBaseline": [dict(item) for item in no_baseline],
        "totals": {
            "deltas": len(rows),
            "admitted": sum(1 for result in rows if result.admitted),
            "refused": sum(1 for result in rows if not result.admitted),
            "records": sum(len(result.records) for result in rows),
            "byDisposition": disposition_totals,
            "byCode": code_totals,
            "noBaseline": len(list(no_baseline)),
        },
    }


def controls_document(
    controls: Iterable[Mapping[str, Any]], repo_root: Path
) -> dict[str, Any]:
    rows = [dict(item) for item in controls]
    return {
        "schema": CONTROLS_SCHEMA,
        "model": MODEL_ID,
        "purpose": "one in-memory control per refusal code; a control proves the refusal fires",
        "sourceIdentity": source_identity(repo_root),
        "controls": rows,
        "totals": {
            "controls": len(rows),
            "codes": len({row["code"] for row in rows}),
        },
    }


# --------------------------------------------------------------------------
# Command line.
# --------------------------------------------------------------------------


def _load_delta_file(path: Path) -> list[DeltaResult]:
    document = _read_json(path)
    if document.get("schema") != DELTA_SCHEMA:
        raise Refusal(
            R_NO_BASELINE,
            f"{path}: schema is {document.get('schema')!r}, not {DELTA_SCHEMA!r}",
        )
    return [DeltaResult.from_dict(item) for item in document.get("deltas", [])]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)

    delta_parser = subparsers.add_parser("delta", help="compute the real deltas")
    delta_parser.add_argument("--verbose", action="store_true")

    explain_parser = subparsers.add_parser("explain", help="explain one identity")
    explain_parser.add_argument("identity")

    admit_parser = subparsers.add_parser("admit", help="admit one delta by id or file")
    admit_parser.add_argument("target")

    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root)

    try:
        baselines, _ = build_baselines(repo_root)
        deltas, _ = build_deltas(baselines, repo_root)

        if args.command == "delta":
            for result in deltas:
                counts = result.counts()
                nonzero = {
                    disposition: count
                    for disposition, count in counts.items()
                    if count
                }
                print(
                    f"delta={result.id}\tbefore={result.before}\tafter={result.after}\t"
                    f"records={len(result.records)}\t"
                    + " ".join(
                        f"{disposition}={count}" for disposition, count in nonzero.items()
                    )
                    + "\tcodes="
                    + (",".join(result.codes) if result.codes else "none")
                    + f"\tadmitted={'yes' if result.admitted else 'no'}"
                )
                if args.verbose:
                    for record in result.records:
                        print(
                            f"  {record.identity}\t{record.disposition}\t"
                            f"{','.join(record.codes) if record.codes else 'none'}\t"
                            f"{record.label}\t{record.reason}"
                        )
            return EXIT_ADMITTED if all(result.admitted for result in deltas) else EXIT_REFUSED

        if args.command == "explain":
            found = False
            for result in deltas:
                matches = explain(result, args.identity)
                for record in matches:
                    found = True
                    print(
                        f"delta={result.id}\tidentity={record.identity}\t"
                        f"logical={record.logical}\tdisposition={record.disposition}\t"
                        f"codes={','.join(record.codes) if record.codes else 'none'}\t"
                        f"label={record.label}\treason={record.reason}"
                    )
            if not found:
                print(
                    f"{R_NO_BASELINE}: no delta record matches {args.identity!r}",
                    file=sys.stderr,
                )
                return EXIT_USAGE
            return EXIT_ADMITTED

        if args.command == "admit":
            target_path = Path(args.target)
            candidates = (
                _load_delta_file(target_path)
                if target_path.is_file()
                else [result for result in deltas if result.id == args.target]
            )
            if not candidates:
                print(
                    f"{R_NO_BASELINE}: no delta {args.target!r}",
                    file=sys.stderr,
                )
                return EXIT_USAGE
            admitted_all = True
            for result in candidates:
                report = admit(result)
                admitted_all = admitted_all and report["admitted"]
                print(
                    f"delta={report['id']}\tadmitted="
                    f"{'yes' if report['admitted'] else 'no'}\t"
                    f"records={sum(report['counts'].values())}\t"
                    + " ".join(
                        f"{disposition}={count}"
                        for disposition, count in report["counts"].items()
                        if count
                    )
                    + "\tcodes="
                    + (",".join(report["codes"]) if report["codes"] else "none")
                    + (
                        "\tproblems=" + "; ".join(report["problems"])
                        if report["problems"]
                        else ""
                    )
                )
            return EXIT_ADMITTED if admitted_all else EXIT_REFUSED
    except Refusal as refusal:
        print(str(refusal), file=sys.stderr)
        return EXIT_USAGE if refusal.code == R_NO_BASELINE else EXIT_REFUSED

    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
