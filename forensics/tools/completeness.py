#!/usr/bin/env python3
"""completeness.py -- admit a declared population only at the completeness it claims.

The normative document is `docs/COMPLETENESS-ADMISSION.md`. This module implements
the rule it states: a claim that a population was examined completely requires

  * an expected population stated by a record (never a denominator invented later),
  * an examined count equal to it, with every examined member identified,
  * no omitted members, and
  * a count partition that adds up (examined + omitted == expected).

Anything weaker is admitted at the weaker state it actually supports -- a sample,
a bounded truncation, an aggregate without members, a deferred population, an
absence or an unknown -- and a declaration that claims more than the facts support
is refused with a stable code naming the wrong conclusion it prevents.

What this module does
---------------------
* `Population` carries one declaration: the subject, the kind, the expected,
  examined and omitted counts, whether omitted members are recorded, whether the
  examined members are identified, whether the population is present, whether a
  truncation bound or a sample rule is declared, and the identity of the record
  that states each number.
* `admit(population)` derives the strongest honest state and returns a refusal
  code when the declaration claims more.
* `read_population(document, locator)` reads one population block and refuses a
  missing field rather than defaulting it. A missing presence field is never read
  as present; a missing expected count is never read as zero.
* `build_populations(repo_root)` reads the tracked records registered in `SPECS`
  and returns the declarations. Every number is read from the named record and
  cross-checked against a second statement in the same record; a disagreement is
  itself a refusal, not a preference for one of the numbers.
* `verify_declaration(population, repo_root)` re-reads the native record and the
  cited digests, so an admission cannot outlive the bytes it read.
* `build_controls(populations)` builds one in-memory control per refusal code from
  a real declaration. A control proves the refusal fires; it is not a source
  change and not a defect report.

What this module does not do
----------------------------
It does not decide whether a finding is true, whether an exclusion argument is
sound, or whether a consumer is safe. `COMPLETE` over a record-set says every
member of that set is present and identified; it says nothing about the tree the
set was drawn from. An absent record is not an empty population, and a process
exit status is not a population.

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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

MODEL_ID = "a5/v1"
POPULATIONS_SCHEMA = "openssl-rs/a5/populations/1"
ADMISSION_SCHEMA = "openssl-rs/a5/admission/1"
CONTROLS_SCHEMA = "openssl-rs/a5/controls/1"

EXIT_ADMITTED = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

#: The expected extent is not stated by any record. It is a string, not 0, so it
#: can never be compared with a count by accident.
EXTENT_UNKNOWN = "unknown"

# --------------------------------------------------------------------------
# Admission states. A state is stable: a document, receipt or test cites it.
# --------------------------------------------------------------------------

S_COMPLETE = "COMPLETE"
S_SAMPLED = "SAMPLED"
S_TRUNCATED_BOUNDED = "TRUNCATED_BOUNDED"
S_ABSENT = "ABSENT"
S_EMPTY = "EMPTY"
S_UNKNOWN = "UNKNOWN"
S_AGGREGATE_ONLY = "AGGREGATE_ONLY"
S_DEFERRED = "DEFERRED"

STATES = (
    S_COMPLETE,
    S_SAMPLED,
    S_TRUNCATED_BOUNDED,
    S_ABSENT,
    S_EMPTY,
    S_UNKNOWN,
    S_AGGREGATE_ONLY,
    S_DEFERRED,
)

# state -> (what it licenses, what it does not license)
STATE_MEANINGS = {
    S_COMPLETE: (
        "every member of the declared population is present and identified, the "
        "expected count is stated by a record, examined equals it, and nothing is "
        "omitted",
        "nothing about the tree the population was drawn from; a complete record-set "
        "is not a complete tree, and completeness is not correctness",
    ),
    S_SAMPLED: (
        "a declared selection rule drew the examined members from a stated expected "
        "population, and the examined members are identified",
        "a census: the unexamined members are a remainder whose properties are "
        "unknown unless a bound names them",
    ),
    S_TRUNCATED_BOUNDED: (
        "an enumeration stopped at a stated bound or cap; the omitted remainder is "
        "counted and the selection rule is recorded",
        "a census, and anything about the omitted members: the bound states how many "
        "were not examined, not what they would have shown",
    ),
    S_ABSENT: (
        "the record or the named input is not present, so nothing was examined and "
        "no member count follows",
        "an empty population: absence is a missing observation, not an observation "
        "of zero",
    ),
    S_EMPTY: (
        "the record is present and states that the population has zero members",
        "an absent population: zero examined is a result only when a record says the "
        "expected population is zero",
    ),
    S_UNKNOWN: (
        "the expected population is not stated, or the declaration is too weak to "
        "place it, so no completeness claim can be made",
        "any count as complete, and any state stronger than itself",
    ),
    S_AGGREGATE_ONLY: (
        "a total is stated without the identity of the members, so the count can be "
        "quoted and nothing can be reviewed or re-run from it",
        "a census or a sample: a number with no member row is not an examined "
        "population",
    ),
    S_DEFERRED: (
        "nothing was examined and every omitted member is named, so the gap is known "
        "exactly and is not an absence",
        "any result: a named not-run analysis is a declaration of a gap, never "
        "evidence of the property it would have measured",
    ),
}

# --------------------------------------------------------------------------
# Refusal codes. A code is stable: a document, receipt or test cites it verbatim.
# --------------------------------------------------------------------------

R_ABSENT_AS_EMPTY = "CA_REFUSED_ABSENT_AS_EMPTY"
R_EMPTY_AS_ABSENT = "CA_REFUSED_EMPTY_AS_ABSENT"
R_ABSENT_AS_OBSERVED = "CA_REFUSED_ABSENT_AS_OBSERVED"
R_UNRECORDED_POPULATION = "CA_REFUSED_UNRECORDED_POPULATION"
R_EXIT_AS_COMPLETENESS = "CA_REFUSED_EXIT_AS_COMPLETENESS"
R_OMITTED_UNRECORDED = "CA_REFUSED_OMITTED_UNRECORDED"
R_TRUNCATION_AS_COMPLETE = "CA_REFUSED_TRUNCATION_AS_COMPLETE"
R_SAMPLE_AS_CENSUS = "CA_REFUSED_SAMPLE_AS_CENSUS"
R_UNKNOWN_AS_COMPLETE = "CA_REFUSED_UNKNOWN_AS_COMPLETE"
R_POPULATION_DRIFT = "CA_REFUSED_POPULATION_DRIFT"
R_COUNT_INCONSISTENT = "CA_REFUSED_COUNT_INCONSISTENT"
R_DUPLICATE_MEMBER = "CA_REFUSED_DUPLICATE_MEMBER"
R_MEMBER_UNIDENTIFIED = "CA_REFUSED_MEMBER_UNIDENTIFIED"
R_SAMPLE_WITHOUT_POPULATION = "CA_REFUSED_SAMPLE_WITHOUT_POPULATION"
R_STATE_UNDECLARED = "CA_REFUSED_STATE_UNDECLARED"
R_STATE_CONTRADICTED = "CA_REFUSED_STATE_CONTRADICTED"

# code -> (the condition it refuses, the wrong conclusion it prevents)
REFUSALS = {
    R_ABSENT_AS_EMPTY: (
        "an absent record or input is read as a population of zero",
        "that a missing observation is an observation of nothing, so a tool that did "
        "not run is read as a tool that found no defect",
    ),
    R_EMPTY_AS_ABSENT: (
        "a population that was examined and is empty is recorded as an absent one",
        "that the examination did not happen, which discards a real zero result and "
        "makes an empty population indistinguishable from a missing one",
    ),
    R_ABSENT_AS_OBSERVED: (
        "an absent population is presented as complete, sampled or otherwise observed",
        "that members were examined when the record that would name them is not present",
    ),
    R_UNRECORDED_POPULATION: (
        "no record states the expected population, so a completeness claim has no "
        "denominator",
        "that a count is a census because no other number was offered; a total without "
        "a population cannot say what is missing",
    ),
    R_EXIT_AS_COMPLETENESS: (
        "a process exit status is used as a population or as proof that everything was "
        "examined",
        "that a zero exit means nothing was skipped; a harness that exits zero after "
        "skipping, truncating or stopping early is read as a complete run",
    ),
    R_OMITTED_UNRECORDED: (
        "members are omitted and the omission is neither identified nor bounded",
        "that a total stands for the members, so an aggregate cannot be reviewed and "
        "the unexamined remainder cannot even be counted",
    ),
    R_TRUNCATION_AS_COMPLETE: (
        "an enumeration stopped at a bound is presented as a census",
        "that every member was examined, when the record's own bound says how many "
        "were not",
    ),
    R_SAMPLE_AS_CENSUS: (
        "a declared sample is presented as a census",
        "that the unexamined remainder shares the sample's property; a sample licenses "
        "a statement about the sample only",
    ),
    R_UNKNOWN_AS_COMPLETE: (
        "a population whose extent is unknown is presented as complete",
        "that an unbounded observation is a bounded one, so a result cannot be "
        "falsified by a member it never looked for",
    ),
    R_POPULATION_DRIFT: (
        "two records state different populations for the same subject, or the live "
        "record no longer matches the declaration it produced",
        "that a count read at one identity applies at another; an admission outliving "
        "the bytes it read is an unverified claim",
    ),
    R_COUNT_INCONSISTENT: (
        "examined plus omitted does not equal expected, or examined exceeds expected",
        "that the stated parts account for the whole, when they do not add up",
    ),
    R_DUPLICATE_MEMBER: (
        "a census counts the same member twice",
        "that a population of N distinct members was examined, when fewer were",
    ),
    R_MEMBER_UNIDENTIFIED: (
        "a count is stated but the examined members are not identified",
        "that the count can be audited: a member with no identity cannot be re-read, "
        "deduplicated or checked, so the count is an assertion",
    ),
    R_SAMPLE_WITHOUT_POPULATION: (
        "a sample reports its examined count before any record states its expected "
        "population",
        "that the examined count is a fraction of something known; a numerator without "
        "a denominator is not a sample",
    ),
    R_STATE_UNDECLARED: (
        "a population declaration names no admission state",
        "that the state can be inferred from the count, when the count is exactly what "
        "is in question",
    ),
    R_STATE_CONTRADICTED: (
        "the declared state is contradicted by the recorded facts and no more specific "
        "code applies",
        "that a declaration is its own evidence",
    ),
}

EXIT_PATTERN = re.compile(r"(?i)\bexit\b|returncode|return_code|\$\?")


class Refusal(Exception):
    """A stable, citable refusal. `str(refusal)` is `CODE: detail`."""

    def __init__(self, code: str, detail: str) -> None:
        if code not in REFUSALS:
            raise ValueError(f"unknown refusal code {code!r}")
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# The population declaration
# --------------------------------------------------------------------------


def _source(record: str, locator: str, sha256: str | None = None) -> dict:
    item = {"record": record, "locator": locator}
    if sha256 is not None:
        item["sha256"] = sha256
    return item


KINDS = (
    "census",
    "sample",
    "scan",
    "enumeration",
    "record-set",
    "not-run",
    "truncation",
)


@dataclass(frozen=True)
class Population:
    """One declared population and the facts its records state about it."""

    id: str
    subject: str
    kind: str
    record: str
    locator: str
    method: str
    expected: Any  # int, or EXTENT_UNKNOWN
    examined: int
    omitted: Any  # int, or EXTENT_UNKNOWN
    omitted_members_recorded: bool
    members_identified: bool
    present: bool
    bound_declared: bool
    selection_declared: bool
    distinct_members: int | None
    sources: dict = field(default_factory=dict)
    declared: str = ""
    declared_basis: str = ""
    presence_basis: str = ""
    members_basis: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise Refusal(R_STATE_UNDECLARED, f"{self.id}: unknown kind {self.kind!r}")
        if self.declared not in STATES:
            raise Refusal(
                R_STATE_UNDECLARED,
                f"{self.id}: declared state {self.declared!r} is not one of {STATES}",
            )
        if not self.record or not self.locator:
            raise Refusal(
                R_UNRECORDED_POPULATION,
                f"{self.id}: no record and locator identify the population",
            )
        for name in ("expected", "examined", "omitted"):
            if name not in self.sources or not isinstance(self.sources[name], dict):
                raise Refusal(
                    R_UNRECORDED_POPULATION,
                    f"{self.id}: no source is recorded for the {name} count",
                )
            if "record" not in self.sources[name] or "locator" not in self.sources[name]:
                raise Refusal(
                    R_UNRECORDED_POPULATION,
                    f"{self.id}: the {name} source names no record and locator",
                )
        for name, source in self.sources.items():
            if isinstance(source, dict) and (
                EXIT_PATTERN.search(source.get("record", ""))
                or EXIT_PATTERN.search(source.get("locator", ""))
            ):
                raise Refusal(
                    R_EXIT_AS_COMPLETENESS,
                    f"{self.id}: the {name} count is sourced from a process exit "
                    f"status ({source.get('record')}#{source.get('locator')})",
                )
        if self.expected != EXTENT_UNKNOWN:
            if not isinstance(self.expected, int) or self.expected < 0:
                raise Refusal(
                    R_COUNT_INCONSISTENT,
                    f"{self.id}: expected {self.expected!r} is not a non-negative count",
                )
            if not self.sources["expected"]["record"]:
                raise Refusal(
                    R_UNRECORDED_POPULATION,
                    f"{self.id}: the expected population is not stated by any record",
                )
        if not isinstance(self.examined, int) or self.examined < 0:
            raise Refusal(
                R_COUNT_INCONSISTENT,
                f"{self.id}: examined {self.examined!r} is not a non-negative count",
            )
        if self.omitted != EXTENT_UNKNOWN:
            if not isinstance(self.omitted, int) or self.omitted < 0:
                raise Refusal(
                    R_COUNT_INCONSISTENT,
                    f"{self.id}: omitted {self.omitted!r} is not a non-negative count",
                )
        if self.expected == EXTENT_UNKNOWN:
            if self.omitted != EXTENT_UNKNOWN:
                raise Refusal(
                    R_COUNT_INCONSISTENT,
                    f"{self.id}: an omitted count is stated while the expected "
                    "population is unknown",
                )
        else:
            if self.omitted == EXTENT_UNKNOWN:
                raise Refusal(
                    R_COUNT_INCONSISTENT,
                    f"{self.id}: the expected population is stated but the omitted "
                    "count is not",
                )
            if self.examined > self.expected:
                raise Refusal(
                    R_COUNT_INCONSISTENT,
                    f"{self.id}: examined {self.examined} exceeds expected "
                    f"{self.expected}",
                )
            if self.examined + self.omitted != self.expected:
                raise Refusal(
                    R_COUNT_INCONSISTENT,
                    f"{self.id}: examined {self.examined} + omitted {self.omitted} "
                    f"!= expected {self.expected}",
                )
        if self.distinct_members is not None and self.distinct_members != self.examined:
            raise Refusal(
                R_DUPLICATE_MEMBER,
                f"{self.id}: {self.examined} examined members but "
                f"{self.distinct_members} distinct identities",
            )

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "subject": self.subject,
            "kind": self.kind,
            "record": self.record,
            "locator": self.locator,
            "method": self.method,
            "expected": self.expected,
            "examined": self.examined,
            "omitted": self.omitted,
            "omittedMembersRecorded": self.omitted_members_recorded,
            "membersIdentified": self.members_identified,
            "present": self.present,
            "boundDeclared": self.bound_declared,
            "selectionDeclared": self.selection_declared,
            "distinctMembers": self.distinct_members,
            "sources": self.sources,
            "declared": self.declared,
            "declaredBasis": self.declared_basis,
            "presenceBasis": self.presence_basis,
            "membersBasis": self.members_basis,
        }

    @classmethod
    def from_dict(cls, item: dict) -> "Population":
        missing = [k for k in ("id", "subject", "kind", "record", "locator", "method",
                               "expected", "examined", "omitted",
                               "omittedMembersRecorded", "membersIdentified", "present",
                               "boundDeclared", "selectionDeclared", "declared")
                   if k not in item]
        if missing:
            raise Refusal(
                R_STATE_UNDECLARED if "declared" in missing else R_UNRECORDED_POPULATION,
                f"population declaration is missing required field(s) {missing}",
            )
        return cls(
            id=item["id"],
            subject=item["subject"],
            kind=item["kind"],
            record=item["record"],
            locator=item["locator"],
            method=item["method"],
            expected=item["expected"],
            examined=item["examined"],
            omitted=item["omitted"],
            omitted_members_recorded=item["omittedMembersRecorded"],
            members_identified=item["membersIdentified"],
            present=item["present"],
            bound_declared=item["boundDeclared"],
            selection_declared=item["selectionDeclared"],
            distinct_members=item.get("distinctMembers"),
            sources=item.get("sources", {}),
            declared=item["declared"],
            declared_basis=item.get("declaredBasis", ""),
            presence_basis=item.get("presenceBasis", ""),
            members_basis=item.get("membersBasis", ""),
        )


# --------------------------------------------------------------------------
# Admission
# --------------------------------------------------------------------------


def supported_state(population: Population) -> str:
    """The strongest honest state the recorded facts support."""
    if not population.present:
        return S_ABSENT
    if population.expected == EXTENT_UNKNOWN:
        return S_UNKNOWN
    if population.expected == 0:
        return S_EMPTY if population.examined == 0 else S_UNKNOWN
    if population.examined == population.expected:
        return S_COMPLETE if population.members_identified else S_AGGREGATE_ONLY
    if population.examined == 0:
        if population.omitted_members_recorded and population.members_identified:
            return S_DEFERRED
        return S_AGGREGATE_ONLY
    if population.bound_declared:
        return S_TRUNCATED_BOUNDED
    if population.selection_declared:
        return S_SAMPLED
    return S_UNKNOWN


@dataclass(frozen=True)
class Admission:
    population_id: str
    declared: str
    examined: Any
    omitted: Any
    members_recorded: bool
    state: str
    refusal: str | None
    detail: str

    @property
    def admitted(self) -> bool:
        return self.refusal is None

    def as_dict(self) -> dict:
        return {
            "id": self.population_id,
            "declared": self.declared,
            "examined": self.examined,
            "omitted": self.omitted,
            "membersRecorded": self.members_recorded,
            "state": self.state,
            "refusal": self.refusal,
            "detail": self.detail,
        }


def _overclaim_code(population: Population, state: str) -> str:
    """The code for a declaration that claims more than `state` supports."""
    if state == S_ABSENT:
        return R_ABSENT_AS_OBSERVED
    if state == S_SAMPLED:
        return R_SAMPLE_AS_CENSUS
    if state == S_TRUNCATED_BOUNDED:
        return R_TRUNCATION_AS_COMPLETE
    if state == S_UNKNOWN:
        if (
            population.expected == EXTENT_UNKNOWN
            and not population.sources.get("expected", {}).get("record")
        ):
            return R_UNRECORDED_POPULATION
        return R_UNKNOWN_AS_COMPLETE
    if state == S_AGGREGATE_ONLY:
        if isinstance(population.omitted, int) and population.omitted > 0:
            return R_OMITTED_UNRECORDED
        return R_MEMBER_UNIDENTIFIED
    if state == S_DEFERRED:
        return R_OMITTED_UNRECORDED
    return R_STATE_CONTRADICTED


def admit(population: Population) -> Admission:
    """Admit `population` at the state its facts support, or refuse the excess."""
    state = supported_state(population)
    refusal: str | None = None
    detail = f"declared {population.declared}, facts support {state}"

    if population.declared == S_ABSENT:
        if state == S_EMPTY:
            refusal = R_EMPTY_AS_ABSENT
            detail = "an examined population with zero members is recorded as absent"
        elif state != S_ABSENT:
            refusal = R_STATE_CONTRADICTED
            detail = f"absent is declared but the population is present ({state})"
    elif population.declared == S_EMPTY:
        if state == S_ABSENT:
            refusal = R_ABSENT_AS_EMPTY
            detail = "an absent population is recorded as an examined population of zero"
        elif state != S_EMPTY:
            refusal = R_STATE_CONTRADICTED
            detail = f"empty is declared but the facts support {state}"
    elif population.declared == S_COMPLETE:
        if state == S_EMPTY:
            refusal = None
            detail = "complete is admitted as EMPTY: the expected population is zero"
        elif state != S_COMPLETE:
            refusal = _overclaim_code(population, state)
            detail = f"complete is declared but the facts support {state}"
    elif population.declared in (S_SAMPLED, S_TRUNCATED_BOUNDED):
        if state == S_ABSENT:
            refusal = R_ABSENT_AS_OBSERVED
        elif state in (S_COMPLETE, S_EMPTY, S_SAMPLED, S_TRUNCATED_BOUNDED):
            refusal = None
        elif population.expected == EXTENT_UNKNOWN:
            refusal = R_SAMPLE_WITHOUT_POPULATION
            detail = "a sample is declared with no expected population"
        else:
            refusal = _overclaim_code(population, state)
    elif population.declared == S_UNKNOWN:
        if state == S_ABSENT:
            detail = "unknown is declared; the record is absent"
        refusal = None
    elif population.declared == S_AGGREGATE_ONLY:
        if state == S_ABSENT:
            refusal = R_ABSENT_AS_OBSERVED
        else:
            refusal = None
    elif population.declared == S_DEFERRED:
        if state == S_ABSENT:
            refusal = R_ABSENT_AS_OBSERVED
        else:
            refusal = None

    if refusal is not None:
        detail = f"{detail}; {REFUSALS[refusal][0]}"
    return Admission(
        population_id=population.id,
        declared=population.declared,
        examined=population.examined,
        omitted=population.omitted,
        members_recorded=population.omitted_members_recorded,
        state=state,
        refusal=refusal,
        detail=detail,
    )


def from_exit_status(code: int, subject: str) -> Population:
    """A process exit status is not a population; constructing one is refused."""
    raise Refusal(
        R_EXIT_AS_COMPLETENESS,
        f"{subject}: exit status {code} is not a population and does not state what "
        "was examined",
    )


# --------------------------------------------------------------------------
# Reading records: refusal, never a default
# --------------------------------------------------------------------------


def _pointer(document: Any, locator: str) -> Any:
    if locator in ("", "/"):
        return document
    node = document
    for raw in locator.strip("/").split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list):
            try:
                node = node[int(token)]
            except (ValueError, IndexError):
                raise Refusal(
                    R_UNRECORDED_POPULATION,
                    f"locator {locator!r}: {token!r} is not an index into a list",
                )
        elif isinstance(node, dict):
            if token not in node:
                raise Refusal(
                    R_UNRECORDED_POPULATION,
                    f"locator {locator!r}: key {token!r} is not present",
                )
            node = node[token]
        else:
            raise Refusal(
                R_UNRECORDED_POPULATION,
                f"locator {locator!r}: {token!r} indexes a scalar",
            )
    return node


READ_POPULATION_KEYS = (
    "expected",
    "examined",
    "omitted",
    "omittedMembersRecorded",
    "membersIdentified",
    "present",
    "boundDeclared",
    "selectionDeclared",
)


def read_population(document: Any, locator: str = "") -> dict:
    """Read a population block, refusing a missing field instead of defaulting it.

    `expected` and `omitted` may be the string `unknown`; every other field must be
    present with the right type. A missing presence field is never read as present,
    and a missing expected count is never read as zero.
    """
    block = _pointer(document, locator)
    if not isinstance(block, dict):
        raise Refusal(
            R_UNRECORDED_POPULATION,
            f"locator {locator!r}: the population block is a {type(block).__name__}",
        )
    for key in READ_POPULATION_KEYS:
        if key not in block:
            code = (
                R_OMITTED_UNRECORDED
                if key == "omittedMembersRecorded"
                else R_UNRECORDED_POPULATION
            )
            raise Refusal(code, f"locator {locator!r}: field {key!r} is absent")
    for key in ("expected", "omitted"):
        value = block[key]
        if value != EXTENT_UNKNOWN and (not isinstance(value, int) or isinstance(value, bool)
                                        or value < 0):
            raise Refusal(
                R_COUNT_INCONSISTENT,
                f"locator {locator!r}: {key} {value!r} is neither a count nor 'unknown'",
            )
    if not isinstance(block["examined"], int) or isinstance(block["examined"], bool):
        raise Refusal(
            R_COUNT_INCONSISTENT,
            f"locator {locator!r}: examined {block['examined']!r} is not a count",
        )
    for key in ("omittedMembersRecorded", "membersIdentified", "present",
                "boundDeclared", "selectionDeclared"):
        if not isinstance(block[key], bool):
            raise Refusal(
                R_STATE_UNDECLARED,
                f"locator {locator!r}: {key} {block[key]!r} is not a boolean",
            )
    return block


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load(repo_root: Path, relpath: str) -> tuple[Any, str]:
    path = repo_root / relpath
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise Refusal(
            R_UNRECORDED_POPULATION,
            f"{relpath}: the record cannot be read ({error.strerror}); an absent "
            "record is not an empty population",
        )
    try:
        return json.loads(raw), hashlib.sha256(raw).hexdigest()
    except json.JSONDecodeError as error:
        raise Refusal(
            R_UNRECORDED_POPULATION, f"{relpath}: the record is not JSON ({error})"
        )


def _tracked(repo_root: Path, relpath: str) -> tuple[bool, str]:
    """Whether `relpath` is a tracked file, with the command that decided it."""
    command = ["git", "-C", str(repo_root), "ls-files", "--error-unmatch", "--", relpath]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
    except OSError as error:
        raise Refusal(
            R_UNRECORDED_POPULATION,
            f"{relpath}: cannot decide whether the named input is tracked ({error})",
        )
    if result.returncode == 0:
        return True, "git ls-files lists the path as tracked"
    if result.returncode == 1:
        return False, (
            "git ls-files does not list the path, so it is untracked or gitignored "
            "and is not part of the evidence record"
        )
    raise Refusal(
        R_UNRECORDED_POPULATION,
        f"{relpath}: git ls-files failed ({result.stderr.strip()})",
    )


def _require(mapping: Any, key: str, where: str) -> Any:
    if not isinstance(mapping, dict):
        raise Refusal(R_UNRECORDED_POPULATION, f"{where}: expected an object")
    if key not in mapping:
        raise Refusal(
            R_UNRECORDED_POPULATION, f"{where}: field {key!r} is absent"
        )
    return mapping[key]


def _count(value: Any, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise Refusal(
            R_COUNT_INCONSISTENT, f"{where}: {value!r} is not a non-negative count"
        )
    return value


# --------------------------------------------------------------------------
# Registered readers, one per tracked population
# --------------------------------------------------------------------------


def _facts(**kwargs: Any) -> dict:
    base = {
        "omittedMembersRecorded": False,
        "membersIdentified": False,
        "present": True,
        "boundDeclared": False,
        "selectionDeclared": False,
        "distinctMembers": None,
        "presenceBasis": "the cited record is present in the tracked tree",
        "membersBasis": "",
    }
    base.update(kwargs)
    return base


def _read_sarif_results(repo_root: Path, doc: Any, sha: str) -> dict:
    runs = _require(doc, "runs", "SARIF.json")
    record = "evidence/a1/SARIF.json"
    expected = examined = 0
    identities: list[str] = []
    for index, run in enumerate(runs):
        where = f"{record}#/runs/{index}"
        results = _require(run, "results", where)
        projection = _require(
            _require(_require(run, "properties", where), "a1", where),
            "projection", where,
        )
        projected = _count(
            _require(projection, "projectedTotal", where), f"{where}/projectedTotal"
        )
        if projected != len(results):
            raise Refusal(
                R_COUNT_INCONSISTENT,
                f"{record}#/runs/{index}: projectedTotal {projected} != "
                f"{len(results)} result(s)",
            )
        if _require(projection, "sumMatchesPopulation", where) is not True:
            raise Refusal(
                R_COUNT_INCONSISTENT,
                f"{record}#/runs/{index}: sumMatchesPopulation is not true",
            )
        expected += projected
        examined += len(results)
        for result in results:
            fingerprints = _require(result, "partialFingerprints", where)
            identities.append(_require(fingerprints, "a1Exact/v1", where))
    return _facts(
        expected=expected,
        examined=examined,
        omitted=0,
        **{
            "omittedMembersRecorded": True,
            "membersIdentified": len(set(identities)) == examined,
            "distinctMembers": len(set(identities)),
            "sources": {
                "expected": _source(
                    record, "runs[*].properties.a1.projection.projectedTotal", sha
                ),
                "examined": _source(record, "runs[*].results (length)", sha),
                "omitted": _source(record, "derived: expected - examined", sha),
            },
            "membersBasis": (
                "every result carries a distinct a1Exact/v1 fingerprint; "
                f"{len(set(identities))} distinct over {examined} results"
            ),
        },
    )


def _read_t4_sites(repo_root: Path, doc: Any, sha: str) -> dict:
    record = "evidence/etp-t4/SAFETY-SITES.json"
    summary = _require(doc, "summary", record)
    sites = _require(doc, "sites", record)
    rows = _require(sites, "rows", f"{record}#/sites")
    columns = _require(sites, "columns", f"{record}#/sites")
    expected = _count(_require(summary, "sites", f"{record}#/summary"),
                      f"{record}#/summary/sites")
    examined = len(rows)
    try:
        id_index = columns.index("id")
    except ValueError:
        raise Refusal(
            R_MEMBER_UNIDENTIFIED, f"{record}#/sites/columns: no 'id' column"
        )
    identities = [row[id_index] for row in rows]
    distinct = len(set(identities))
    if distinct != examined:
        raise Refusal(
            R_DUPLICATE_MEMBER,
            f"{record}#/sites/rows: {examined} rows, {distinct} distinct ids",
        )
    return _facts(
        expected=expected,
        examined=examined,
        omitted=0,
        **{
            "omittedMembersRecorded": True,
            "membersIdentified": True,
            "distinctMembers": distinct,
            "sources": {
                "expected": _source(record, "summary.sites", sha),
                "examined": _source(record, "sites.rows (length)", sha),
                "omitted": _source(record, "derived: expected - examined", sha),
            },
            "membersBasis": f"{distinct} distinct site ids over {examined} rows",
        },
    )


def _read_t4_suppressions(repo_root: Path, doc: Any, sha: str) -> dict:
    record = "evidence/etp-t4/SAFETY-SITES.json"
    suppressions = _require(doc, "suppressions", record)
    summary = _require(doc, "summary", record)
    expected = _count(_require(suppressions, "total", f"{record}#/suppressions"),
                      f"{record}#/suppressions/total")
    stated = _count(_require(summary, "suppressions", f"{record}#/summary"),
                    f"{record}#/summary/suppressions")
    if stated != expected:
        raise Refusal(
            R_POPULATION_DRIFT,
            f"{record}: suppressions.total {expected} != summary.suppressions {stated}",
        )
    by_lint = _require(suppressions, "by_lint", f"{record}#/suppressions")
    partition = sum(_count(value, f"{record}#/suppressions/by_lint") for value in by_lint.values())
    if partition != expected:
        raise Refusal(
            R_COUNT_INCONSISTENT,
            f"{record}#/suppressions/by_lint: the per-lint partition sums to "
            f"{partition}, not {expected}",
        )
    return _facts(
        expected=expected,
        examined=0,
        omitted=expected,
        **{
            "omittedMembersRecorded": False,
            "membersIdentified": False,
            "sources": {
                "expected": _source(record, "suppressions.total", sha),
                "examined": _source(
                    record, "suppressions (no member row exists)", sha
                ),
                "omitted": _source(record, "derived: expected - examined", sha),
            },
            "membersBasis": (
                "the record carries a per-lint partition and no member row, so no "
                "suppression is identified"
            ),
        },
    )


def _read_t4_ignored(repo_root: Path, doc: Any, sha: str) -> dict:
    record = "evidence/etp-t4/SAFETY-SITES.json"
    summary = _require(doc, "summary", record)
    assertions = _require(doc, "assertions", record)
    rows = _require(assertions, "ignored", f"{record}#/assertions")
    expected = _count(_require(summary, "ignored_tests", f"{record}#/summary"),
                      f"{record}#/summary/ignored_tests")
    examined = len(rows)
    identities = {
        (
            _require(row, "path", f"{record}#/assertions/ignored"),
            _require(row, "line", f"{record}#/assertions/ignored"),
        )
        for row in rows
    }
    if len(identities) != examined:
        raise Refusal(
            R_DUPLICATE_MEMBER,
            f"{record}#/assertions/ignored: {examined} rows, "
            f"{len(identities)} distinct path/line identities",
        )
    return _facts(
        expected=expected,
        examined=examined,
        omitted=0,
        **{
            "omittedMembersRecorded": True,
            "membersIdentified": True,
            "distinctMembers": examined,
            "sources": {
                "expected": _source(record, "summary.ignored_tests", sha),
                "examined": _source(record, "assertions.ignored (length)", sha),
                "omitted": _source(record, "derived: expected - examined", sha),
            },
            "membersBasis": "each row names its path and line, and the pairs are distinct",
        },
    )


def _read_t10_exclusions(repo_root: Path, doc: Any, sha: str) -> dict:
    record = "evidence/etp-t10/EXCLUSIONS.json"
    expected = _count(_require(doc, "exclusion_rows", record),
                      f"{record}#/exclusion_rows")
    rows = _require(doc, "rows", record)
    examined = len(rows)
    passing = _count(_require(doc, "exclusions_passing", record),
                     f"{record}#/exclusions_passing")
    failing = _count(_require(doc, "exclusions_failing", record),
                     f"{record}#/exclusions_failing")
    if passing + failing != expected:
        raise Refusal(
            R_COUNT_INCONSISTENT,
            f"{record}: passing {passing} + failing {failing} != rows {expected}",
        )
    by_category = _require(doc, "totals_by_category", record)
    for name, block in by_category.items():
        rows_n = _count(_require(block, "rows", f"{record}#/totals_by_category"),
                        f"{record}#/totals_by_category/{name}/rows")
        pass_n = _count(_require(block, "passing", f"{record}#/totals_by_category"),
                        f"{record}#/totals_by_category/{name}/passing")
        fail_n = _count(_require(block, "failing", f"{record}#/totals_by_category"),
                        f"{record}#/totals_by_category/{name}/failing")
        if pass_n + fail_n != rows_n:
            raise Refusal(
                R_COUNT_INCONSISTENT,
                f"{record}#/totals_by_category/{name}: {pass_n} + {fail_n} != {rows_n}",
            )
    if sum(_count(b["rows"], record) for b in by_category.values()) != expected:
        raise Refusal(
            R_POPULATION_DRIFT,
            f"{record}: the category partitions do not sum to exclusion_rows",
        )
    identities = [_require(row, "id", f"{record}#/rows") for row in rows]
    distinct = len(set(identities))
    if distinct != examined:
        raise Refusal(
            R_DUPLICATE_MEMBER,
            f"{record}#/rows: {examined} rows, {distinct} distinct ids",
        )
    return _facts(
        expected=expected,
        examined=examined,
        omitted=0,
        **{
            "omittedMembersRecorded": True,
            "membersIdentified": True,
            "distinctMembers": distinct,
            "sources": {
                "expected": _source(record, "exclusion_rows", sha),
                "examined": _source(record, "rows (length)", sha),
                "omitted": _source(record, "derived: expected - examined", sha),
            },
            "membersBasis": (
                f"{distinct} distinct row ids; {passing} rows pass the bar and "
                f"{failing} do not, which is the rows' content, not their completeness"
            ),
        },
    )


def _read_curl_residual(repo_root: Path, doc: Any, sha: str) -> dict:
    record = "evidence/closure-curl-049.json"
    precision = _require(doc, "precision", record)
    bound = _require(precision, "residual_sites_bound", f"{record}#/precision")
    expected = _count(_require(bound, "population_size", f"{record}#/precision/residual_sites_bound"),
                      "population_size")
    sample = _count(_require(bound, "sample_size", f"{record}#/precision/residual_sites_bound"),
                    "sample_size")
    omitted = _count(_require(bound, "omitted_members", f"{record}#/precision/residual_sites_bound"),
                     "omitted_members")
    listed = _require(precision, "residual_sites", f"{record}#/precision")
    totals = _require(precision, "totals", f"{record}#/precision")
    reachable = _count(_require(totals, "reachable_unresolved_sites", f"{record}#/precision/totals"),
                       "reachable_unresolved_sites")
    if expected != reachable:
        raise Refusal(
            R_POPULATION_DRIFT,
            f"{record}: residual_sites_bound.population_size {expected} != "
            f"precision.totals.reachable_unresolved_sites {reachable}",
        )
    if len(listed) != sample:
        raise Refusal(
            R_COUNT_INCONSISTENT,
            f"{record}: sample_size {sample} != {len(listed)} listed rows",
        )
    identities = {
        (
            _require(row, "dso", f"{record}#/precision/residual_sites"),
            _require(row, "function", f"{record}#/precision/residual_sites"),
            _require(row, "call_site", f"{record}#/precision/residual_sites"),
        )
        for row in listed
    }
    status = _require(bound, "status", f"{record}#/precision/residual_sites_bound")
    return _facts(
        expected=expected,
        examined=sample,
        omitted=omitted,
        **{
            "omittedMembersRecorded": bool(
                _require(bound, "omitted_members_recorded",
                         f"{record}#/precision/residual_sites_bound")
            ),
            "membersIdentified": len(identities) == sample,
            "boundDeclared": status == S_TRUNCATED_BOUNDED,
            "distinctMembers": len(identities),
            "sources": {
                "expected": _source(record, "precision.residual_sites_bound.population_size", sha),
                "examined": _source(record, "precision.residual_sites_bound.sample_size", sha),
                "omitted": _source(record, "precision.residual_sites_bound.omitted_members", sha),
            },
            "membersBasis": f"{len(identities)} distinct (dso, function, call-site) keys",
        },
    )


def _read_edge_records(repo_root: Path, doc: Any, sha: str, record: str) -> dict:
    provenance = _require(doc, "edge_provenance", record)
    expected = _count(_require(provenance, "count", f"{record}#/edge_provenance"),
                      f"{record}#/edge_provenance/count")
    precision = _require(doc, "precision", record)
    totals = _require(precision, "totals", f"{record}#/precision")
    indirect = _count(_require(totals, "indirect_sites", f"{record}#/precision/totals"),
                      "indirect_sites")
    if indirect != expected:
        raise Refusal(
            R_POPULATION_DRIFT,
            f"{record}: edge_provenance.count {expected} != "
            f"precision.totals.indirect_sites {indirect}",
        )
    sidecar = _require(provenance, "records_path", f"{record}#/edge_provenance")
    present, basis = _tracked(repo_root, sidecar)
    if present:
        raise Refusal(
            R_UNRECORDED_POPULATION,
            f"{record}: the sidecar {sidecar} is tracked, but no reader enumerates it; "
            "the population cannot be admitted from a total alone",
        )
    return _facts(
        expected=expected,
        examined=0,
        omitted=expected,
        **{
            "omittedMembersRecorded": False,
            "membersIdentified": False,
            "present": present,
            "sources": {
                "expected": _source(record, "edge_provenance.count", sha),
                "examined": _source(
                    record, "edge_provenance (no member row in the receipt)", sha
                ),
                "omitted": _source(record, "derived: expected - examined", sha),
            },
            "presenceBasis": (
                f"records_path {sidecar}: {basis}. The bytes exist outside the "
                "tracked tree, so the member population is absent from the evidence"
            ),
            "membersBasis": "no member row for the full population is in the receipt",
        },
    )


def _read_edge_sample(repo_root: Path, doc: Any, sha: str, record: str) -> dict:
    provenance = _require(doc, "edge_provenance", record)
    expected = _count(
        _require(provenance, "records_sample_eligible", f"{record}#/edge_provenance"),
        "records_sample_eligible",
    )
    sample = _require(provenance, "records_sample", f"{record}#/edge_provenance")
    cap = _count(_require(provenance, "sample_cap", f"{record}#/edge_provenance"),
                 "sample_cap")
    examined = len(sample)
    if examined != min(expected, cap):
        raise Refusal(
            R_COUNT_INCONSISTENT,
            f"{record}: {examined} sampled records, expected min({expected}, cap {cap})",
        )
    if _count(_require(provenance, "count", f"{record}#/edge_provenance"), "count") < expected:
        raise Refusal(
            R_POPULATION_DRIFT,
            f"{record}: the eligible sample population exceeds edge_provenance.count",
        )
    identities = [_require(row, "edge_id", f"{record}#/edge_provenance/records_sample")
                  for row in sample]
    distinct = len(set(identities))
    if distinct != examined:
        raise Refusal(
            R_DUPLICATE_MEMBER,
            f"{record}: {examined} sampled rows, {distinct} distinct edge ids",
        )
    truncated = _require(provenance, "records_sample_truncated",
                         f"{record}#/edge_provenance")
    return _facts(
        expected=expected,
        examined=examined,
        omitted=expected - examined,
        **{
            "omittedMembersRecorded": False,
            "membersIdentified": True,
            "boundDeclared": truncated is True,
            "selectionDeclared": bool(
                _require(provenance, "sample_policy", f"{record}#/edge_provenance")
            ),
            "distinctMembers": distinct,
            "sources": {
                "expected": _source(record, "edge_provenance.records_sample_eligible", sha),
                "examined": _source(record, "edge_provenance.records_sample (length)", sha),
                "omitted": _source(record, "derived: expected - examined", sha),
            },
            "membersBasis": f"{distinct} distinct edge ids over {examined} sampled rows",
        },
    )


def _read_timing_not_run(repo_root: Path, doc: Any, sha: str) -> dict:
    record = "evidence/timing-bn-findings.json"
    items = _require(doc, "not_run", record)
    expected = len(items)
    identities = {json.dumps(item, sort_keys=True) for item in items}
    if len(identities) != expected:
        raise Refusal(
            R_DUPLICATE_MEMBER, f"{record}#/not_run: duplicate not-run entries"
        )
    return _facts(
        expected=expected,
        examined=0,
        omitted=expected,
        **{
            "omittedMembersRecorded": True,
            "membersIdentified": True,
            "distinctMembers": None,
            "sources": {
                "expected": _source(record, "not_run (length)", sha),
                "examined": _source(record, "not_run: none of the analyses was run", sha),
                "omitted": _source(record, "not_run (length)", sha),
            },
            "membersBasis": "every not-run analysis is named in the list",
        },
    )


def _read_o11_scripts(repo_root: Path, doc: Any, sha: str) -> dict:
    record = "courts/phase18/interop/MANIFEST-o11-A.json"
    result = _require(doc, "result", record)
    counts = _require(result, "counts", f"{record}#/result")
    examined = _count(_require(counts, "scripts_executed", f"{record}#/result/counts"),
                      "scripts_executed")
    per_script = _require(result, "per_script", f"{record}#/result")
    if len(per_script) != examined:
        raise Refusal(
            R_COUNT_INCONSISTENT,
            f"{record}: scripts_executed {examined} != {len(per_script)} per-script rows",
        )
    rules = _require(result, "rules", f"{record}#/result")
    _require(rules, "executed", f"{record}#/result/rules")
    return _facts(
        expected=EXTENT_UNKNOWN,
        examined=examined,
        omitted=EXTENT_UNKNOWN,
        **{
            "membersIdentified": True,
            "selectionDeclared": True,
            "distinctMembers": examined,
            "sources": {
                "expected": _source(
                    "", "result.counts: no record states a script population"
                ),
                "examined": _source(record, "result.counts.scripts_executed", sha),
                "omitted": _source(
                    "", "derived: unknown because no expected population is stated"
                ),
            },
            "membersBasis": (
                "each executed script has a per-script row; the record does not state "
                "how many scripts the suite contains"
            ),
        },
    )


def _read_t11_runs(repo_root: Path, doc: Any, sha: str) -> dict:
    record = "evidence/etp-t11/RUNS.json"
    runs = _require(doc, "runs", record)
    satisfied = [
        run for run in runs
        if _require(run, "status", f"{record}#/runs") == "SATISFIED"
    ]
    statuses = {_require(run, "status", f"{record}#/runs") for run in runs}
    if not statuses <= {"SATISFIED", "NOT_RUN"}:
        raise Refusal(
            R_STATE_UNDECLARED,
            f"{record}: run status vocabulary {sorted(statuses)} is not the recorded pair",
        )
    examined = len(satisfied)
    identified = all(run.get("identity") is not None for run in satisfied)
    return _facts(
        expected=examined,
        examined=examined,
        omitted=0,
        **{
            "omittedMembersRecorded": True,
            "membersIdentified": identified,
            "distinctMembers": examined,
            "sources": {
                "expected": _source(record, "runs[*].status == 'SATISFIED' (count)", sha),
                "examined": _source(record, "runs[*].status == 'SATISFIED' (count)", sha),
                "omitted": _source(record, "derived: expected - examined", sha),
            },
            "membersBasis": (
                f"{examined} satisfied run declaration(s); "
                + (
                    "every one carries a non-null identity"
                    if identified
                    else "every one carries identity: null, so what was examined is "
                    "not identified"
                )
            ),
        },
    )


def _read_etp6_inputs(repo_root: Path, doc: Any, sha: str) -> dict:
    record = "evidence/etp6/MANIFEST.json"
    examined = _count(_require(doc, "input_count", record), f"{record}#/input_count")
    inputs = _require(doc, "inputs", record)
    if len(inputs) != examined:
        raise Refusal(
            R_COUNT_INCONSISTENT,
            f"{record}: input_count {examined} != {len(inputs)} input rows",
        )
    identities = {_require(row, "path", f"{record}#/inputs") for row in inputs}
    return _facts(
        expected=EXTENT_UNKNOWN,
        examined=examined,
        omitted=EXTENT_UNKNOWN,
        **{
            "membersIdentified": len(identities) == examined,
            "distinctMembers": len(identities),
            "selectionDeclared": bool(
                _require(_require(doc, "selection", record), "method",
                         f"{record}#/selection")
            ),
            "sources": {
                "expected": _source(
                    "", "input_count: no record states a package denominator"
                ),
                "examined": _source(record, "input_count", sha),
                "omitted": _source(
                    "", "derived: unknown because no expected population is stated"
                ),
            },
            "membersBasis": (
                f"{len(identities)} distinct input paths; the record states no "
                "expected package population"
            ),
        },
    )


def _read_p1000(repo_root: Path, doc: Any, sha: str) -> dict:
    record = "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json"
    consumers = _require(doc, "consumers", record)
    corpus = _require(consumers, "p1000_corpus", f"{record}#/consumers")
    families = _count(_require(corpus, "families", f"{record}#/consumers/p1000_corpus"),
                      "families")
    omitted = _count(_require(corpus, "not_attempted", f"{record}#/consumers/p1000_corpus"),
                     "not_attempted")
    with_recipe = _count(_require(corpus, "with_recipe", f"{record}#/consumers/p1000_corpus"),
                         "with_recipe")
    no_recipe = _count(_require(corpus, "no_recipe", f"{record}#/consumers/p1000_corpus"),
                       "no_recipe")
    loaded = _count(_require(corpus, "candidate_loaded", f"{record}#/consumers/p1000_corpus"),
                    "candidate_loaded")
    l7 = _count(_require(corpus, "candidate_l7_functional",
                         f"{record}#/consumers/p1000_corpus"), "candidate_l7_functional")
    if with_recipe + no_recipe != families:
        raise Refusal(
            R_COUNT_INCONSISTENT,
            f"{record}: with_recipe {with_recipe} + no_recipe {no_recipe} != "
            f"families {families}",
        )
    examined = families - omitted
    if examined < 0 or not (l7 <= loaded <= examined):
        raise Refusal(
            R_COUNT_INCONSISTENT,
            f"{record}: families {families} - not_attempted {omitted} = {examined}, "
            f"which does not contain candidate_loaded {loaded} and L7 {l7}",
        )
    return _facts(
        expected=families,
        examined=examined,
        omitted=omitted,
        **{
            "omittedMembersRecorded": False,
            "membersIdentified": False,
            "boundDeclared": omitted > 0,
            "sources": {
                "expected": _source(record, "consumers.p1000_corpus.families", sha),
                "examined": _source(
                    record,
                    "consumers.p1000_corpus: families - not_attempted",
                    sha,
                ),
                "omitted": _source(record, "consumers.p1000_corpus.not_attempted", sha),
            },
            "membersBasis": (
                "the record states family counts; it names no per-family member list "
                "for the not-attempted remainder"
            ),
        },
    )


def _read_etp_claims(repo_root: Path, doc: Any, sha: str) -> dict:
    record = "evidence/etp/claims.json"
    claims = _require(doc, "claims", record)
    examined = len(claims)
    identities = {_require(claim, "id", f"{record}#/claims") for claim in claims}
    other, other_sha = _load(repo_root, "evidence/etp0/CLAIMS.json")
    other_claims = _require(other, "claims", "evidence/etp0/CLAIMS.json")
    expected = len(other_claims)
    other_ids = {
        _require(claim, "id", "evidence/etp0/CLAIMS.json#/claims")
        for claim in other_claims
    }
    if expected != examined or other_ids != identities:
        raise Refusal(
            R_POPULATION_DRIFT,
            f"{record} and evidence/etp0/CLAIMS.json state different claim sets "
            f"({examined} vs {expected})",
        )
    return _facts(
        expected=expected,
        examined=examined,
        omitted=0,
        **{
            "omittedMembersRecorded": True,
            "membersIdentified": len(identities) == examined,
            "distinctMembers": len(identities),
            "sources": {
                "expected": _source("evidence/etp0/CLAIMS.json", "claims (length)", other_sha),
                "examined": _source(record, "claims (length)", sha),
                "omitted": _source(record, "derived: expected - examined", sha),
            },
            "membersBasis": (
                f"{len(identities)} distinct claim ids, equal to the ETP-0 inventory's"
            ),
        },
    )


def _reader(record: str, fn: Callable[..., dict]) -> Callable[[Path], dict]:
    def run(repo_root: Path) -> dict:
        doc, sha = _load(repo_root, record)
        return fn(repo_root, doc, sha)

    return run


def _reader_edge(record: str, kind: str) -> Callable[[Path], dict]:
    def run(repo_root: Path) -> dict:
        doc, sha = _load(repo_root, record)
        fn = _read_edge_records if kind == "records" else _read_edge_sample
        return fn(repo_root, doc, sha, record)

    return run


@dataclass(frozen=True)
class Spec:
    id: str
    subject: str
    kind: str
    record: str
    locator: str
    method: str
    declared: str
    declared_basis: str
    reader: Callable[[Path], dict]
    expect_state: str
    expect_refusal: str | None


SPECS: tuple[Spec, ...] = (
    Spec(
        "a1-sarif-results",
        "every result the A1 SARIF adapter emits, across its six runs",
        "record-set",
        "evidence/a1/SARIF.json",
        "/runs",
        "each run's projectedTotal is compared with its result count and with "
        "sumMatchesPopulation; each result's a1Exact/v1 fingerprint is collected",
        S_COMPLETE,
        "a record-set: every projected result is present and carries a distinct exact "
        "fingerprint",
        _reader("evidence/a1/SARIF.json", _read_sarif_results),
        S_COMPLETE,
        None,
    ),
    Spec(
        "t4-unsafe-sites",
        "the lexical unsafe-site census",
        "census",
        "evidence/etp-t4/SAFETY-SITES.json",
        "/sites/rows",
        "summary.sites is compared with the row count and with the distinct id set",
        S_COMPLETE,
        "a census: the summary count and every row's unique id are both present",
        _reader("evidence/etp-t4/SAFETY-SITES.json", _read_t4_sites),
        S_COMPLETE,
        None,
    ),
    Spec(
        "t4-suppressions",
        "the lint suppressions reported for the scanned tree",
        "enumeration",
        "evidence/etp-t4/SAFETY-SITES.json",
        "/suppressions",
        "suppressions.total is compared with summary.suppressions and with the sum of "
        "the per-lint partition; no member row exists",
        S_COMPLETE,
        "the record presents suppressions.total with a complete per-lint partition and "
        "no member row, which a consumer reads as the whole suppression population",
        _reader("evidence/etp-t4/SAFETY-SITES.json", _read_t4_suppressions),
        S_AGGREGATE_ONLY,
        R_OMITTED_UNRECORDED,
    ),
    Spec(
        "t4-ignored-tests",
        "the ignored-test census",
        "census",
        "evidence/etp-t4/SAFETY-SITES.json",
        "/assertions/ignored",
        "summary.ignored_tests is compared with the row count and with the distinct "
        "path/line pairs",
        S_COMPLETE,
        "the census lists every ignored test and the summary states the count",
        _reader("evidence/etp-t4/SAFETY-SITES.json", _read_t4_ignored),
        S_COMPLETE,
        None,
    ),
    Spec(
        "t10-closure-exclusions",
        "the closure exclusion rows audited by the closure discipline",
        "record-set",
        "evidence/etp-t10/EXCLUSIONS.json",
        "/rows",
        "exclusion_rows is compared with the row count, with passing + failing and "
        "with the category partition; every row id is collected",
        S_COMPLETE,
        "a record-set: every row is present and identified; the 744 failing rows are "
        "the rows' content, not a completeness defect",
        _reader("evidence/etp-t10/EXCLUSIONS.json", _read_t10_exclusions),
        S_COMPLETE,
        None,
    ),
    Spec(
        "curl-residual-sites",
        "the reachable unresolved indirect sites of the curl closure",
        "truncation",
        "evidence/closure-curl-049.json",
        "/precision/residual_sites_bound",
        "population_size is compared with precision.totals.reachable_unresolved_sites "
        "and with sample_size + omitted_members; sample_size is compared with the "
        "listed rows",
        S_TRUNCATED_BOUNDED,
        "residual_sites_bound.status is TRUNCATED_BOUNDED and the block states its "
        "cap, its omitted count and the selection rule",
        _reader("evidence/closure-curl-049.json", _read_curl_residual),
        S_TRUNCATED_BOUNDED,
        None,
    ),
    Spec(
        "curl-edge-records",
        "every edge record of the curl closure",
        "enumeration",
        "evidence/closure-curl-049.json",
        "/edge_provenance",
        "edge_provenance.count is compared with precision.totals.indirect_sites; the "
        "records_path sidecar is tested for trackedness",
        S_COMPLETE,
        "sample_policy states that the complete population is the JSONL sidecar named "
        "by records_path",
        _reader_edge("evidence/closure-curl-049.json", "records"),
        S_ABSENT,
        R_ABSENT_AS_OBSERVED,
    ),
    Spec(
        "curl-edge-sample",
        "the bounded sample of curl edge records embedded in the receipt",
        "sample",
        "evidence/closure-curl-049.json",
        "/edge_provenance/records_sample",
        "records_sample_eligible and sample_cap bound the sample; the sampled rows' "
        "edge ids are checked for distinctness",
        S_TRUNCATED_BOUNDED,
        "records_sample_truncated is true and sample_cap is stated",
        _reader_edge("evidence/closure-curl-049.json", "sample"),
        S_TRUNCATED_BOUNDED,
        None,
    ),
    Spec(
        "ssh-edge-records",
        "every edge record of the OpenSSH closure",
        "enumeration",
        "evidence/closure-ssh-b86.json",
        "/edge_provenance",
        "edge_provenance.count is compared with precision.totals.indirect_sites; the "
        "records_path sidecar is tested for trackedness",
        S_COMPLETE,
        "sample_policy states that the complete population is the JSONL sidecar named "
        "by records_path",
        _reader_edge("evidence/closure-ssh-b86.json", "records"),
        S_ABSENT,
        R_ABSENT_AS_OBSERVED,
    ),
    Spec(
        "ssh-edge-sample",
        "the bounded sample of OpenSSH edge records embedded in the receipt",
        "sample",
        "evidence/closure-ssh-b86.json",
        "/edge_provenance/records_sample",
        "records_sample_eligible and sample_cap bound the sample; the sampled rows' "
        "edge ids are checked for distinctness",
        S_TRUNCATED_BOUNDED,
        "records_sample_truncated is true and sample_cap is stated",
        _reader_edge("evidence/closure-ssh-b86.json", "sample"),
        S_TRUNCATED_BOUNDED,
        None,
    ),
    Spec(
        "timing-not-run",
        "the timing analyses the BN record names as not run",
        "not-run",
        "evidence/timing-bn-findings.json",
        "/not_run",
        "every entry of not_run is read; none was run, and each entry is distinct",
        S_DEFERRED,
        "not_run names every analysis that was not run and claims nothing about them",
        _reader("evidence/timing-bn-findings.json", _read_timing_not_run),
        S_DEFERRED,
        None,
    ),
    Spec(
        "o11-interop-scripts",
        "the interop scripts the O11 manifest reports as executed",
        "scan",
        "courts/phase18/interop/MANIFEST-o11-A.json",
        "/result/counts",
        "scripts_executed is compared with the per-script row count; the manifest "
        "states no expected script population",
        S_UNKNOWN,
        "the manifest reports the examined count and states no expected population, so "
        "it claims no completeness",
        _reader("courts/phase18/interop/MANIFEST-o11-A.json", _read_o11_scripts),
        S_UNKNOWN,
        None,
    ),
    Spec(
        "t11-satisfied-runs",
        "the scheduling runs that declare SATISFIED",
        "record-set",
        "evidence/etp-t11/RUNS.json",
        "/runs",
        "every run with status SATISFIED is counted; each one's identity field is read",
        S_COMPLETE,
        "six runs carry status SATISFIED, which a consumer reads as six satisfied checks",
        _reader("evidence/etp-t11/RUNS.json", _read_t11_runs),
        S_AGGREGATE_ONLY,
        R_MEMBER_UNIDENTIFIED,
    ),
    Spec(
        "etp6-package-inputs",
        "the inputs the external package manifest lists as verified",
        "enumeration",
        "evidence/etp6/MANIFEST.json",
        "/inputs",
        "input_count is compared with the input row count; the manifest states no "
        "expected package population",
        S_COMPLETE,
        "the manifest presents input_count as the verified inputs of the package",
        _reader("evidence/etp6/MANIFEST.json", _read_etp6_inputs),
        S_UNKNOWN,
        R_UNRECORDED_POPULATION,
    ),
    Spec(
        "p1000-campaign-families",
        "the 1000-family corpus the campaign status reports",
        "scan",
        "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json",
        "/consumers/p1000_corpus",
        "families is compared with with_recipe + no_recipe; the examined count is "
        "families - not_attempted and is required to contain candidate_loaded and L7",
        S_TRUNCATED_BOUNDED,
        "not_attempted states how many families were not attempted",
        _reader(
            "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json",
            _read_p1000,
        ),
        S_TRUNCATED_BOUNDED,
        None,
    ),
    Spec(
        "etp-claims",
        "the claim set carried by the evidence registry",
        "record-set",
        "evidence/etp/claims.json",
        "/claims",
        "the claim ids are compared with the ETP-0 claim inventory's ids",
        S_COMPLETE,
        "the claim set and the ETP-0 inventory state the same identified claims",
        _reader("evidence/etp/claims.json", _read_etp_claims),
        S_COMPLETE,
        None,
    ),
)

SPECS_BY_ID = {spec.id: spec for spec in SPECS}


def build_populations(repo_root: Path) -> list[Population]:
    """Read every registered record and return the declarations, in registry order."""
    populations = []
    for spec in SPECS:
        facts = read_population(spec.reader(repo_root))
        populations.append(
            Population(
                id=spec.id,
                subject=spec.subject,
                kind=spec.kind,
                record=spec.record,
                locator=spec.locator,
                method=spec.method,
                expected=facts["expected"],
                examined=facts["examined"],
                omitted=facts["omitted"],
                omitted_members_recorded=facts["omittedMembersRecorded"],
                members_identified=facts["membersIdentified"],
                present=facts["present"],
                bound_declared=facts["boundDeclared"],
                selection_declared=facts["selectionDeclared"],
                distinct_members=facts["distinctMembers"],
                sources=facts["sources"],
                declared=spec.declared,
                declared_basis=spec.declared_basis,
                presence_basis=facts["presenceBasis"],
                members_basis=facts["membersBasis"],
            )
        )
    return populations


# --------------------------------------------------------------------------
# Verification against the live records
# --------------------------------------------------------------------------


def verify_declaration(population: Population, repo_root: Path) -> str:
    """Re-read the native record and the cited digests.

    Returns a short status string. A changed count or a changed record digest is
    `CA_REFUSED_POPULATION_DRIFT`: the declaration is evidence about the bytes it
    read, and those bytes are gone.
    """
    spec = SPECS_BY_ID.get(population.id)
    if spec is None:
        return "NOT_RUN: no native reader is registered for this population"
    facts = spec.reader(repo_root)
    for name in ("expected", "examined", "omitted", "present"):
        recorded = getattr(population, name)
        live = facts[
            {"expected": "expected", "examined": "examined", "omitted": "omitted",
             "present": "present"}[name]
        ]
        if recorded != live:
            raise Refusal(
                R_POPULATION_DRIFT,
                f"{population.id}: the declaration records {name} {recorded!r} but "
                f"{population.record} now states {live!r}",
            )
    live_digests = {
        name: source.get("sha256")
        for name, source in facts["sources"].items()
        if source.get("sha256")
    }
    for name, recorded in (
        (name, source.get("sha256")) for name, source in population.sources.items()
    ):
        live = live_digests.get(name)
        if recorded and live and recorded != live:
            raise Refusal(
                R_POPULATION_DRIFT,
                f"{population.id}: the {name} source digest {recorded[:12]} is not the "
                f"live digest {live[:12]}",
            )
    return "checked"


def detect_drift(populations: list[Population]) -> None:
    """Two declarations of the same id must state the same population."""
    seen: dict[str, Population] = {}
    for population in populations:
        first = seen.get(population.id)
        if first is not None and (
            first.expected != population.expected
            or first.examined != population.examined
            or first.omitted != population.omitted
        ):
            raise Refusal(
                R_POPULATION_DRIFT,
                f"{population.id}: two declarations state different populations",
            )
        seen.setdefault(population.id, population)


# --------------------------------------------------------------------------
# Documents
# --------------------------------------------------------------------------


def dump_document(document: dict) -> str:
    """Canonical JSON bytes for a recorded document: sorted keys, indent 1."""
    return json.dumps(document, indent=1, sort_keys=True) + "\n"


def inventory_document(populations: list[Population]) -> dict:
    return {
        "schema": POPULATIONS_SCHEMA,
        "model": MODEL_ID,
        "purpose": (
            "every population this project states in a tracked record, with the "
            "expected, examined and omitted counts, whether omitted members are "
            "recorded, and the record and locator that state each number"
        ),
        "states": list(STATES),
        "stateMeanings": {
            state: {"licenses": licenses, "doesNotLicense": does_not}
            for state, (licenses, does_not) in STATE_MEANINGS.items()
        },
        "refusals": {
            code: {"condition": condition, "prevents": prevents}
            for code, (condition, prevents) in REFUSALS.items()
        },
        "populations": [population.as_dict() for population in populations],
    }


def admission_document(populations: list[Population]) -> dict:
    admissions = [admit(population) for population in populations]
    by_state: dict[str, int] = {state: 0 for state in STATES}
    by_refusal: dict[str, int] = {}
    for admission in admissions:
        by_state[admission.state] += 1
        if admission.refusal is not None:
            by_refusal[admission.refusal] = by_refusal.get(admission.refusal, 0) + 1
    return {
        "schema": ADMISSION_SCHEMA,
        "model": MODEL_ID,
        "purpose": (
            "the state each declared population is admitted at, and the refusal code "
            "where the declaration claims more than its record supports"
        ),
        "populations": [admission.as_dict() for admission in admissions],
        "totals": {
            "populations": len(admissions),
            "admitted": sum(1 for a in admissions if a.admitted),
            "refused": sum(1 for a in admissions if not a.admitted),
            "byState": by_state,
            "byRefusal": by_refusal,
        },
    }


def _mutate(population: Population, **changes: Any) -> Population:
    return dataclasses.replace(population, **changes)


def build_controls(populations: list[Population], repo_root: Path) -> list[dict]:
    """One in-memory control per refusal code, built from a real declaration."""
    by_id = {population.id: population for population in populations}

    def observed(fn: Callable[[], Any]) -> str | None:
        try:
            result = fn()
        except Refusal as refusal:
            return refusal.code
        if isinstance(result, str):
            return result
        return result.refusal if isinstance(result, Admission) else None

    controls: list[dict] = []

    def add(
        control_id: str,
        base: str,
        mutation: str,
        expected: str,
        fn: Callable[[], Any],
    ) -> None:
        code = observed(fn)
        if code != expected:
            raise AssertionError(
                f"{control_id}: expected {expected}, observed {code}"
            )
        controls.append(
            {
                "id": control_id,
                "base": base,
                "mutation": mutation,
                "expectedCode": expected,
                "observedCode": code,
            }
        )

    residual = by_id["curl-residual-sites"]
    sample = by_id["curl-edge-sample"]
    absent = by_id["curl-edge-records"]
    absent_ssh = by_id["ssh-edge-records"]
    suppression = by_id["t4-suppressions"]
    sites = by_id["t4-unsafe-sites"]
    ignored = by_id["t4-ignored-tests"]
    runs = by_id["t11-satisfied-runs"]
    scripts = by_id["o11-interop-scripts"]
    inputs = by_id["etp6-package-inputs"]

    add(
        "sample-as-census",
        sample.id,
        "the declared sample's bound flag is cleared so the facts support SAMPLED, and "
        "the declaration is relabelled COMPLETE",
        R_SAMPLE_AS_CENSUS,
        lambda: admit(_mutate(sample, bound_declared=False, declared=S_COMPLETE)),
    )
    add(
        "truncation-as-complete",
        residual.id,
        "a declared TRUNCATED_BOUNDED population is relabelled COMPLETE",
        R_TRUNCATION_AS_COMPLETE,
        lambda: admit(_mutate(residual, declared=S_COMPLETE)),
    )
    add(
        "absent-as-empty",
        absent.id,
        "an absent population is relabelled EMPTY",
        R_ABSENT_AS_EMPTY,
        lambda: admit(_mutate(absent, declared=S_EMPTY)),
    )
    add(
        "empty-as-absent",
        ignored.id,
        "a present population whose expected count is zero is relabelled ABSENT",
        R_EMPTY_AS_ABSENT,
        lambda: admit(
            _mutate(
                ignored,
                expected=0,
                examined=0,
                omitted=0,
                distinct_members=0,
                declared=S_ABSENT,
            )
        ),
    )
    add(
        "exit-as-completeness",
        absent.id,
        "an exit status is supplied where a population is required",
        R_EXIT_AS_COMPLETENESS,
        lambda: from_exit_status(0, "the harness script"),
    )
    add(
        "omitted-unrecorded",
        suppression.id,
        "a population with an unrecorded omitted remainder is relabelled COMPLETE; "
        "the real declaration already fires this code",
        R_OMITTED_UNRECORDED,
        lambda: admit(suppression),
    )
    add(
        "unknown-as-complete",
        scripts.id,
        "a population with no expected count is relabelled COMPLETE after a source is "
        "recorded for the unknown",
        R_UNKNOWN_AS_COMPLETE,
        lambda: admit(
            _mutate(
                scripts,
                declared=S_COMPLETE,
                sources={
                    **scripts.sources,
                    "expected": _source(
                        scripts.record, "result.counts: no denominator is stated", ""
                    ),
                },
            )
        ),
    )
    add(
        "population-drift",
        residual.id,
        "a declaration's population is changed while the native record still states "
        "the original, and the declaration is re-read",
        R_POPULATION_DRIFT,
        lambda: _drift_control(residual, repo_root),
    )
    add(
        "count-inconsistent-sum",
        ignored.id,
        "one omitted member is added without changing expected or examined",
        R_COUNT_INCONSISTENT,
        lambda: _mutate(ignored, omitted=1),
    )
    add(
        "count-inconsistent-exceeds",
        ignored.id,
        "the examined count is raised above the expected population",
        R_COUNT_INCONSISTENT,
        lambda: _mutate(ignored, examined=ignored.expected + 1),
    )
    add(
        "duplicate-member",
        sites.id,
        "a census reports one fewer distinct member than examined members",
        R_DUPLICATE_MEMBER,
        lambda: _mutate(sites, distinct_members=sites.examined - 1),
    )
    add(
        "member-unidentified",
        runs.id,
        "six SATISFIED declarations with identity: null are relabelled COMPLETE; the "
        "real declaration already fires this code",
        R_MEMBER_UNIDENTIFIED,
        lambda: admit(runs),
    )
    add(
        "sample-without-population",
        sample.id,
        "a sample keeps its examined count after its expected population is removed",
        R_SAMPLE_WITHOUT_POPULATION,
        lambda: admit(
            _mutate(
                sample,
                expected=EXTENT_UNKNOWN,
                omitted=EXTENT_UNKNOWN,
                declared=S_SAMPLED,
            )
        ),
    )
    add(
        "state-undeclared",
        sites.id,
        "a declaration names no admission state",
        R_STATE_UNDECLARED,
        lambda: _mutate(sites, declared=""),
    )
    add(
        "absent-as-observed",
        absent_ssh.id,
        "an absent population is relabelled COMPLETE; the real declaration already "
        "fires this code",
        R_ABSENT_AS_OBSERVED,
        lambda: admit(absent_ssh),
    )
    add(
        "absent-declared-over-present",
        sites.id,
        "a present, fully enumerated census is relabelled ABSENT",
        R_STATE_CONTRADICTED,
        lambda: admit(_mutate(sites, declared=S_ABSENT)),
    )
    add(
        "unrecorded-population",
        inputs.id,
        "a count with no expected population is relabelled COMPLETE; the real "
        "declaration already fires this code",
        R_UNRECORDED_POPULATION,
        lambda: admit(inputs),
    )
    return controls


def _drift_control(population: Population, repo_root: Path) -> str | None:
    """Re-read the native record for a mutated declaration."""
    if population.expected == EXTENT_UNKNOWN or population.omitted == EXTENT_UNKNOWN:
        return None
    mutated = _mutate(
        population,
        expected=population.expected + 1,
        omitted=population.omitted + 1,
    )
    try:
        verify_declaration(mutated, repo_root)
    except Refusal as refusal:
        return refusal.code
    return None


def controls_document(controls: list[dict]) -> dict:
    by_code: dict[str, int] = {}
    for control in controls:
        by_code[control["expectedCode"]] = by_code.get(control["expectedCode"], 0) + 1
    return {
        "schema": CONTROLS_SCHEMA,
        "model": MODEL_ID,
        "purpose": (
            "one in-memory control per refusal code, each built from a real population "
            "declaration; a control proves the refusal fires and is not a source change"
        ),
        "controls": controls,
        "totals": {"controls": len(controls), "byCode": by_code},
    }


# --------------------------------------------------------------------------
# Discovery: what a bounded structural scan of the evidence tree finds
# --------------------------------------------------------------------------

DECLARATION_KEYS = (
    "population",
    "population_size",
    "sample_size",
    "omitted",
    "examined",
    "expected",
    "records_sample",
    "membersRecorded",
    "members_recorded",
    "not_run",
)
DECLARATION_PATTERN = re.compile(
    rb'"(' + b"|".join(key.encode() for key in DECLARATION_KEYS) + rb')"'
)
SCAN_BYTES_LIMIT = 40_000_000


def _declaration_nodes(value: Any, locator: str = "", depth: int = 0) -> list[str]:
    if depth > 12:
        return []
    found: list[str] = []
    if isinstance(value, dict):
        keys = set(value.keys()) & set(DECLARATION_KEYS)
        if len(keys) >= 2 or "not_run" in keys:
            found.append(locator or "/")
        for key, item in value.items():
            found.extend(_declaration_nodes(item, f"{locator}/{key}", depth + 1))
    elif isinstance(value, list):
        for index, item in enumerate(value[:5000]):
            found.extend(_declaration_nodes(item, f"{locator}/{index}", depth + 1))
    return found


def _category(relpath: str) -> str:
    if relpath.startswith("evidence/a2/"):
        return "preservation-projection"
    if "claims" in relpath or relpath.startswith("evidence/etp5/probes/"):
        return "claim-quantification"
    if relpath in (
        "evidence/a1/SARIF.json",
        "evidence/closure-curl-049.json",
        "evidence/timing-bn-findings.json",
    ):
        return "admitted-reader-record"
    return "narrative-or-summary"


def discover(repo_root: Path) -> dict:
    """A bounded scan of `evidence/**/*.json` for population-shaped blocks.

    The scan reports what it found, not what exists: a key outside
    `DECLARATION_KEYS` is not detected, a file above the size bound is skipped and
    named, and a hit that no registered reader admits is listed as a retained
    obligation. The scan is discovery, never admission.
    """
    hits: list[dict] = []
    scanned = 0
    oversize: list[dict] = []
    unreadable: list[dict] = []
    for path in sorted((repo_root / "evidence").rglob("*.json")):
        relpath = path.relative_to(repo_root).as_posix()
        if relpath.startswith("evidence/a5/"):
            continue
        try:
            size = path.stat().st_size
        except OSError as error:
            unreadable.append({"record": relpath, "error": error.strerror})
            continue
        if size > SCAN_BYTES_LIMIT:
            oversize.append({"record": relpath, "bytes": size})
            continue
        try:
            raw = path.read_bytes()
        except OSError as error:
            unreadable.append({"record": relpath, "error": error.strerror})
            continue
        scanned += 1
        if not DECLARATION_PATTERN.search(raw):
            continue
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as error:
            unreadable.append({"record": relpath, "error": str(error)})
            continue
        for locator in _declaration_nodes(document):
            hits.append(
                {
                    "record": relpath,
                    "locator": locator,
                    "category": _category(relpath),
                }
            )
    categories: dict[str, int] = {}
    for hit in hits:
        categories[hit["category"]] = categories.get(hit["category"], 0) + 1
    return {
        "roots": ["evidence"],
        "excludedRoots": ["evidence/a5"],
        "declarationKeys": list(DECLARATION_KEYS),
        "predicate": "a mapping with at least two declaration keys, or a not_run key",
        "bytesLimit": SCAN_BYTES_LIMIT,
        "filesScanned": scanned,
        "filesOversize": oversize,
        "filesUnreadable": unreadable,
        "declarationHits": hits,
        "hitCount": len(hits),
        "categories": categories,
        "inventoriedPopulations": len(SPECS),
    }


def inventory_report(populations: list[Population]) -> dict:
    admissions = [admit(population) for population in populations]
    rows = []
    for population, admission in zip(populations, admissions):
        rows.append(
            {
                "id": population.id,
                "record": population.record,
                "locator": population.locator,
                "kind": population.kind,
                "expected": population.expected,
                "examined": population.examined,
                "omitted": population.omitted,
                "omittedMembersRecorded": population.omitted_members_recorded,
                "membersIdentified": population.members_identified,
                "declared": population.declared,
                "state": admission.state,
                "refusal": admission.refusal,
            }
        )
    return {
        "model": MODEL_ID,
        "populations": rows,
        "totals": admission_document(populations)["totals"],
    }


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

DEFAULT_INVENTORY = "evidence/a5/POPULATIONS.json"
REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_declarations(path: Path) -> list[Population]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Refusal(
            R_UNRECORDED_POPULATION, f"{path}: cannot read the declarations ({error})"
        )
    if isinstance(document, dict) and "populations" in document:
        items = document["populations"]
    elif isinstance(document, dict) and "id" in document:
        items = [document]
    elif isinstance(document, list):
        items = document
    else:
        raise Refusal(
            R_UNRECORDED_POPULATION,
            f"{path}: no populations list and no single declaration",
        )
    return [Population.from_dict(item) for item in items]


def _lines(admissions: list[Admission]) -> list[str]:
    return [
        f"{admission.population_id}\tdeclared={admission.declared}\t"
        f"state={admission.state}\t"
        f"refusal={admission.refusal or 'admitted'}"
        for admission in admissions
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory_parser = subparsers.add_parser(
        "inventory", help="print the population inventory"
    )
    inventory_parser.add_argument("--inventory", type=Path, default=None)

    admit_parser = subparsers.add_parser(
        "admit", help="admit a population id or a declaration file"
    )
    admit_parser.add_argument("target", help="a population id, or a JSON declaration file")
    admit_parser.add_argument("--inventory", type=Path, default=None)

    check_parser = subparsers.add_parser(
        "check", help="admit every population in the given records"
    )
    check_parser.add_argument("records", nargs="*", type=Path)

    subparsers.add_parser(
        "discover", help="print the bounded structural scan of the evidence tree"
    )

    args = parser.parse_args(argv)
    inventory_path = (
        args.inventory
        if getattr(args, "inventory", None) is not None
        else Path(args.repo_root) / DEFAULT_INVENTORY
    )

    try:
        if args.command == "inventory":
            populations = (
                _load_declarations(Path(inventory_path))
                if Path(inventory_path).exists()
                else build_populations(Path(args.repo_root))
            )
            report = inventory_report(populations)
            print(dump_document(report), end="")
            return EXIT_ADMITTED if report["totals"]["refused"] == 0 else EXIT_REFUSED

        if args.command == "admit":
            target = Path(args.target)
            if target.exists():
                populations = _load_declarations(target)
            else:
                populations = [
                    population
                    for population in _load_declarations(Path(inventory_path))
                    if population.id == args.target
                ]
                if not populations:
                    print(
                        f"{R_UNRECORDED_POPULATION}: no population {args.target!r} in "
                        f"{inventory_path}",
                        file=sys.stderr,
                    )
                    return EXIT_USAGE
            return _run_admissions(populations, Path(args.repo_root))

        if args.command == "check":
            records = args.records or [Path(inventory_path)]
            populations = []
            for record in records:
                populations.extend(_load_declarations(Path(record)))
            return _run_admissions(populations, Path(args.repo_root))

        if args.command == "discover":
            print(dump_document(discover(Path(args.repo_root))), end="")
            return EXIT_ADMITTED
    except Refusal as refusal:
        print(str(refusal), file=sys.stderr)
        return EXIT_USAGE

    return EXIT_USAGE


def _run_admissions(populations: list[Population], repo_root: Path) -> int:
    detect_drift(populations)
    state_counts: dict[str, int] = {}
    admitted = 0
    refused = 0
    for population in populations:
        try:
            native = verify_declaration(population, repo_root)
        except Refusal as refusal:
            print(f"{population.id}\trefusal={refusal.code}\t{refusal.detail}")
            refused += 1
            continue
        if native.startswith("NOT_RUN"):
            print(f"{population.id}\tnative={native}")
        admission = admit(population)
        for line in _lines([admission]):
            print(line)
        state_counts[admission.state] = state_counts.get(admission.state, 0) + 1
        if admission.refusal is None:
            admitted += 1
        else:
            refused += 1
    print(
        f"populations={len(populations)} admitted={admitted} refused={refused} "
        + " ".join(f"{state}={count}" for state, count in sorted(state_counts.items()))
    )
    return EXIT_REFUSED if refused else EXIT_ADMITTED


if __name__ == "__main__":
    sys.exit(main())
