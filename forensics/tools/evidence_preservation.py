#!/usr/bin/env python3
"""A2 lossless evidence preservation and native/exported population reconciliation.

What this tool does, and what it deliberately does not do
---------------------------------------------------------

Every finding in an export came from a native record. This tool preserves, for
each native record that feeds an export:

* the exact bytes that were read, written to a content-addressed store and named
  by SHA-256;
* the recorded invocation or procedure and the producer instrument identity;
* the candidate identity, copied verbatim from the record;
* the population definition and counts, both as the record declares them and as
  this tool enumerates them independently from the same bytes;
* the unsupported operations, exclusions, not-run analyses and declared
  limitations;
* every bound, timeout and resource cap, with the statement of what was not
  examined;
* the time the record says it was produced.

It then reconciles, per export run, the native population enumerated from the
record against the members the export emitted, and names the difference in both
directions. A population that the record counts but does not list is reported as
`unidentified`, never as covered. An emitted member that the record does not
contain is reported as `fabricated`. A member that is neither emitted nor
declared omitted is reported as `unaccounted`.

The reconciliation never rounds a sample up to a census. A run whose population
is only partly emitted is marked `covers_population: false`, and
:func:`assert_covers_population` refuses a caller that claims otherwise.

Scope boundaries
----------------

* A5 owns completeness admission: expected versus examined population, skips,
  truncation policy, and whether an absent population may be read as empty.
  This tool records the *facts* A5 judges and refuses a coverage claim; it does
  not admit completeness.
* A6 owns suppression governance. A suppression aggregate is preserved here with
  its declared count and the statement that no member row is recorded; whether a
  suppression is justified remains A6's.
* This tool writes only under its own evidence directory and never modifies a
  native record, an export produced by another item, or source code.

Refusal conditions
------------------

``PRESERVATION_REFUSED_RAW_BYTES_ABSENT``
    The content-addressed copy of a native record is missing.
``PRESERVATION_REFUSED_DIGEST_MISMATCH``
    The preserved bytes, the live native bytes or the export's recorded digest
    disagree with the recorded address.
``PRESERVATION_REFUSED_STALE_REEXPORT_DIGEST``
    The native bytes changed after capture and the export still cites the
    superseded digest.
``PRESERVATION_REFUSED_MANIFEST_STALE``
    The native bytes changed after capture and the export cites the new digest,
    so the preservation record no longer describes the export's input.
``PRESERVATION_REFUSED_POPULATION_MISMATCH``
    A population the record counts disagrees with the members it lists, or with
    the export's declared native population, and no declared bound reconciles
    the difference.
``PRESERVATION_REFUSED_MISSING_INVOCATION_AND_INSTRUMENT``
    A native record carries neither a structured invocation nor a structured
    instrument identity.
``PRESERVATION_REFUSED_MISSING_INSTRUMENT_IDENTITY``
    A structured invocation is recorded but no structured producer identity is.
``PRESERVATION_REFUSED_MISSING_INVOCATION``
    A structured producer identity is recorded but no invocation is.
``PRESERVATION_REFUSED_BOUND_UNEXPLAINED``
    A bound, timeout or resource cap is declared without a statement of what was
    not examined.
``PRESERVATION_REFUSED_EXPORT_UNACCOUNTED``
    A native member is neither emitted nor covered by a declared omission.
``PRESERVATION_REFUSED_EXPORT_FABRICATED``
    The export emits a member the native record does not contain.
``PRESERVATION_REFUSED_UNROUTED_RESULT``
    An exported result cannot be assigned to a native population block, so the
    reconciliation cannot answer the membership question for it.
``PRESERVATION_REFUSED_TOOL_IDENTITY``
    The document was produced by a different version of this tool than the one
    now reading it.
``PRESERVATION_REFUSED_COVERAGE_CLAIM``
    A caller asserts that an export covers a population the reconciliation found
    it does not cover.

Determinism
-----------

No clock, machine, account, process, working directory or absolute path enters
either document. Production times are copied from the records, which state them.
Members are ordered lexicographically and JSON is written with sorted keys and a
fixed indent, so two runs over the same bytes produce identical files. The store
write is idempotent.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable, Iterable

SCHEMA_PRESERVATION = "openssl-rs/etp-a2/preservation/v1"
SCHEMA_RECONCILIATION = "openssl-rs/etp-a2/reconciliation/v1"

STORE_ROOT = "evidence/a2/raw/sha256"
SARIF_PATH = "evidence/a1/SARIF.json"

R_RAW_ABSENT = "PRESERVATION_REFUSED_RAW_BYTES_ABSENT"
R_DIGEST_MISMATCH = "PRESERVATION_REFUSED_DIGEST_MISMATCH"
R_STALE_REEXPORT = "PRESERVATION_REFUSED_STALE_REEXPORT_DIGEST"
R_MANIFEST_STALE = "PRESERVATION_REFUSED_MANIFEST_STALE"
R_POPULATION = "PRESERVATION_REFUSED_POPULATION_MISMATCH"
R_NO_INVOCATION_OR_INSTRUMENT = "PRESERVATION_REFUSED_MISSING_INVOCATION_AND_INSTRUMENT"
R_NO_INSTRUMENT = "PRESERVATION_REFUSED_MISSING_INSTRUMENT_IDENTITY"
R_NO_INVOCATION = "PRESERVATION_REFUSED_MISSING_INVOCATION"
R_BOUND_UNEXPLAINED = "PRESERVATION_REFUSED_BOUND_UNEXPLAINED"
R_UNACCOUNTED = "PRESERVATION_REFUSED_EXPORT_UNACCOUNTED"
R_FABRICATED = "PRESERVATION_REFUSED_EXPORT_FABRICATED"
R_UNROUTED = "PRESERVATION_REFUSED_UNROUTED_RESULT"
R_COVERAGE_CLAIM = "PRESERVATION_REFUSED_COVERAGE_CLAIM"
R_TOOL_IDENTITY = "PRESERVATION_REFUSED_TOOL_IDENTITY"
R_UNREADABLE = "PRESERVATION_REFUSED_RECORD_UNREADABLE"

TOOL_PATH = "forensics/tools/evidence_preservation.py"

ROLES = frozenset(
    {"finding", "record_condition", "census", "aggregate_only", "declared_scope"}
)


class Refusal(Exception):
    """A preservation or reconciliation condition that must not be reported as a pass."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Bytes, digests and the content-addressed store
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tool_identity() -> dict:
    """Path and digest of this tool, so an artefact names what produced it."""
    path = Path(__file__).resolve()
    return {"path": TOOL_PATH, "sha256": sha256_bytes(path.read_bytes())}


def address(digest: str) -> str:
    return f"preservation:sha256:{digest}"


def dump_json(document: Any) -> str:
    return json.dumps(document, sort_keys=True, indent=2) + "\n"


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise Refusal(R_UNREADABLE, f"{path}: {exc}") from exc


def load_json(path: Path) -> Any:
    raw = read_bytes(path)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Refusal(R_UNREADABLE, f"{path}: invalid JSON: {exc}") from exc


def store_path(repo_root: Path, digest: str, store_root: Path | None) -> Path:
    root = store_root if store_root is not None else repo_root / STORE_ROOT
    return Path(root) / digest


def write_store(path: Path, data: bytes, digest: str) -> str:
    """Write the exact bytes under their digest. Idempotent and verified.

    Returns ``"existing"`` when a byte-identical copy was already present and
    ``"written"`` when the copy was created.
    """
    path = Path(path)
    if path.exists():
        present = path.read_bytes()
        if sha256_bytes(present) != digest:
            raise Refusal(
                R_DIGEST_MISMATCH,
                f"{path}: stored bytes do not hash to the address {digest}; "
                "the store entry is corrupt and must not be overwritten silently",
            )
        if present != data:
            raise Refusal(
                R_DIGEST_MISMATCH,
                f"{path}: stored bytes differ from the source bytes at the same digest",
            )
        return "existing"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(path)
    return "written"


def read_store(path: Path, digest: str) -> bytes:
    if not Path(path).exists():
        raise Refusal(R_RAW_ABSENT, f"{path}: no preserved copy for {address(digest)}")
    data = Path(path).read_bytes()
    if sha256_bytes(data) != digest:
        raise Refusal(
            R_DIGEST_MISMATCH,
            f"{path}: preserved bytes do not hash to {digest}",
        )
    return data


def preserved_path_text(repo_root: Path, path: Path) -> str:
    """Repository-relative path of a store entry, or a stable marker if external."""
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return f"external-store:{path.name}"


# ---------------------------------------------------------------------------
# Locators: resolution and member keys
# ---------------------------------------------------------------------------

_LOCATOR_TOKEN = re.compile(r"\[(\d+)\]|([^.\[\]]+)")


def resolve_locator(document: Any, locator: str) -> Any:
    """Resolve a dotted/bracketed locator into a parsed native record."""
    node = document
    for match in _LOCATOR_TOKEN.finditer(locator):
        index, key = match.group(1), match.group(2)
        if index is not None:
            node = node[int(index)]
        else:
            node = node[key]
    return node


def locator_exists(document: Any, locator: str) -> bool:
    try:
        resolve_locator(document, locator)
        return True
    except (KeyError, IndexError, TypeError):
        return False


def member_candidates(locator: str) -> Iterable[str]:
    """Yield the locator and every enclosing member-shaped prefix, longest first.

    ``obligations[2].disposition_conflicts[0]`` yields itself, then
    ``obligations[2]``, so a nested result attaches to its member without a
    second lookup structure for 62 000 members.
    """
    yield locator
    for position in range(len(locator) - 1, 0, -1):
        if locator[position] in ".[":
            yield locator[:position]


# ---------------------------------------------------------------------------
# Population blocks
# ---------------------------------------------------------------------------

def block(
    name: str,
    role: str,
    declared: int,
    declared_sources: Iterable[tuple[str, Any]],
    members: Iterable[str],
    route: Iterable[str] = (),
    aggregates: Iterable[str] = (),
    bound: dict | None = None,
    not_projected: dict | None = None,
    note: str | None = None,
    export_native_keys: Iterable[str] = (),
) -> dict:
    if role not in ROLES:
        raise Refusal(R_UNROUTED, f"block {name!r}: unknown role {role!r}")
    for locator, value in declared_sources:
        if value != declared:
            raise Refusal(
                R_POPULATION,
                f"block {name!r}: declared population disagrees between its own "
                f"sources ({locator}={value!r} versus {declared!r})",
            )
    entry = {
        "name": name,
        "role": role,
        "declared": declared,
        "declared_sources": [
            {"locator": locator, "value": value} for locator, value in declared_sources
        ],
        "members": list(members),
        "route": list(route),
        "aggregates": list(aggregates),
        "bound": bound,
        "not_projected": not_projected,
        "export_native_keys": list(export_native_keys),
    }
    if note is not None:
        entry["note"] = note
    return entry


def bound(
    kind: str,
    population: int,
    sample: int | None,
    omitted: int | None,
    members_recorded: bool,
    what_was_not_examined: str,
    source: str,
    selection_rule: str | None = None,
) -> dict:
    if not what_was_not_examined:
        raise Refusal(
            R_BOUND_UNEXPLAINED,
            f"bound {kind!r} at {source} declares a limit without naming what was "
            "not examined",
        )
    entry = {
        "kind": kind,
        "population": population,
        "sample": sample,
        "omitted": omitted,
        "members_recorded": members_recorded,
        "what_was_not_examined": what_was_not_examined,
        "source": source,
    }
    if selection_rule is not None:
        entry["selection_rule"] = selection_rule
    return entry


# ---------------------------------------------------------------------------
# Source descriptors. Each one reads only structured fields; a producer named
# only in prose is not treated as an instrument identity.
# ---------------------------------------------------------------------------

def _record_condition(name: str, locator: str) -> dict:
    return block(
        name,
        "record_condition",
        declared=1,
        declared_sources=[(locator, 1)],
        members=[locator],
        route=(locator,),
    )


def _describe_curl(document: dict) -> dict:
    obligations = document["obligations"]
    precision = document["precision"]
    residual_rows = precision["residual_sites"]
    residual_bound = precision.get("residual_sites_bound") or {}
    totals = precision.get("totals") or {}
    counts = document.get("counts") or {}
    refusals = document.get("refusals") or []

    residual_declared = residual_bound.get("population_size")
    residual_from_totals = totals.get("reachable_unresolved_sites")
    if residual_declared is None and residual_from_totals is None:
        raise Refusal(
            R_POPULATION,
            "evidence/closure-curl-049.json: no declared residual-site population",
        )
    if residual_declared is None:
        residual_declared = residual_from_totals
    declared_pairs = [("precision.residual_sites_bound.population_size", residual_declared)]
    if residual_from_totals is not None:
        declared_pairs.append(
            ("precision.totals.reachable_unresolved_sites", residual_from_totals)
        )

    omission_text = residual_bound.get("omitted_members_note") or ""
    omission_rule = (residual_bound.get("selection_rule") or {}).get("rule") or ""
    residual_limit = None
    if residual_bound:
        residual_limit = bound(
            kind="truncation",
            population=residual_declared,
            sample=residual_bound.get("sample_size", len(residual_rows)),
            omitted=residual_bound.get(
                "omitted_members", residual_declared - len(residual_rows)
            ),
            members_recorded=bool(residual_bound.get("omitted_members_recorded")),
            what_was_not_examined=(
                f"{residual_bound.get('omitted_members', residual_declared - len(residual_rows))} "
                "members of the reachable unresolved population are counted but not "
                f"listed: {omission_text}"
            ),
            source="precision.residual_sites_bound",
            selection_rule=omission_rule or None,
        )

    exclusion_block = (document.get("closure_scope") or {}).get(
        "excluded_from_upper_bound"
    ) or []

    return {
        "candidate": {
            "source_identity": document.get("source_identity"),
            "candidate_identity": document.get("candidate_identity"),
        },
        "produced": {
            "field": "generated_utc",
            "value": document.get("generated_utc"),
            "source": "generated_utc",
        },
        "invocation": {
            "recorded": True,
            "kind": "procedure",
            "exact_arguments": False,
            "entries": [
                {
                    "text": (residual_bound.get("selection_rule") or {}).get("requires"),
                    "source": "precision.residual_sites_bound.selection_rule.requires",
                },
                {
                    "text": (residual_bound.get("selection_rule") or {}).get("locator"),
                    "source": "precision.residual_sites_bound.selection_rule.locator",
                },
                {
                    "text": document.get("tool", {}).get("path"),
                    "source": "tool.path",
                },
            ],
            "limitation": (
                "the record names the procedure, the option that prints the whole "
                "population and the producer path; no argument vector or working "
                "directory is recorded, so the invocation is not reproduced exactly"
            ),
        },
        "instrument": {
            "recorded": True,
            "kind": "producer-tool",
            "identity_complete": bool(
                document.get("tool", {}).get("path")
                and (
                    document.get("tool", {}).get("sha256")
                    or document.get("tool", {}).get("version") is not None
                )
            ),
            "entries": [
                {
                    "path": document.get("tool", {}).get("path"),
                    "version": document.get("tool", {}).get("version"),
                    "sha256": document.get("tool", {}).get("sha256"),
                    "record_schema": document.get("tool", {}).get("schema"),
                    "source": "tool",
                }
            ],
        },
        "populations": [
            block(
                "obligations",
                "finding",
                declared=counts.get("reachable_production_obligations", len(obligations)),
                declared_sources=[
                    ("counts.reachable_production_obligations",
                     counts.get("reachable_production_obligations", len(obligations))),
                    ("len(obligations)", len(obligations)),
                ],
                members=[f"obligations[{index}]" for index in range(len(obligations))],
                route=("obligations[",),
                export_native_keys=("obligations",),
            ),
            block(
                "residual_sites",
                "finding",
                declared=residual_declared,
                declared_sources=declared_pairs,
                members=[
                    f"precision.residual_sites[{index}]"
                    for index in range(len(residual_rows))
                ],
                route=("precision.residual_sites[",),
                aggregates=("precision.residual_sites_bound",),
                bound=residual_limit,
                export_native_keys=("residual_sites_population", "residual_sites_sample"),
            ),
            _record_condition("verdict", "verdict"),
            _record_condition("predicate_element_7", "precision.predicate_element_7"),
            block(
                "refusals",
                "finding",
                declared=len(refusals),
                declared_sources=[("len(refusals)", len(refusals))],
                members=[f"refusals[{index}]" for index in range(len(refusals))],
                route=("refusals[",),
            ),
        ],
        "bounds": [residual_limit] if residual_limit is not None else [],
        "unsupported_operations": [
            {
                "kind": "excluded_from_upper_bound",
                "count": len(exclusion_block),
                "source": "closure_scope.excluded_from_upper_bound",
                "members": exclusion_block,
            }
        ],
        "non_claims": list(document.get("non_claims") or []),
    }


def _decode_site_row(row: list, columns: list, tables: dict, vocabulary: dict) -> dict:
    literal = {"id", "line", "column", "contract_sha256"}
    decoded = {}
    for column, value in zip(columns, row):
        if column in literal:
            decoded[column] = value
        elif column in tables:
            decoded[column] = tables[column][value]
        elif column in vocabulary:
            decoded[column] = vocabulary[column][value]
        else:
            decoded[column] = value
    return decoded


def _describe_safety(document: dict) -> dict:
    identity = document["identity"]
    sites = document["sites"]
    columns = sites["columns"]
    tables = sites["tables"]
    vocabulary = sites["vocabularies"]
    rows = sites["rows"]
    summary = document["summary"]
    vacuity = document.get("vacuity") or {}
    vacuity_findings = vacuity.get("findings") or []
    vacuity_summary = vacuity.get("summary") or {}
    suppressions = document.get("suppressions") or {}
    by_lint = suppressions.get("by_lint") or {}

    absent_indexes = [
        index
        for index, row in enumerate(rows)
        if _decode_site_row(row, columns, tables, vocabulary)["contract_state"] == "absent"
    ]

    status_total = sum(
        value
        for key, value in vacuity_summary.items()
        if key
        in {
            "vacuous_precondition",
            "caller_obligation_unestablished",
            "implementer_obligation",
            "cited_by_caller",
            "external_caller_contract",
        }
    )

    suppression_total = suppressions.get("total")
    suppression_bound = bound(
        kind="aggregate_only",
        population=suppression_total or 0,
        sample=0,
        omitted=suppression_total or 0,
        members_recorded=False,
        what_was_not_examined=(
            "the identity, path, line and lint of each of the "
            f"{suppression_total} suppressions is not recorded; only a per-lint "
            "count is present"
        ),
        source="suppressions",
        selection_rule=(
            "by_lint partitions the total into lint classes; no member row exists "
            "at any finer granularity"
        ),
    )

    vacuity_declared_pairs = [("len(vacuity.findings)", len(vacuity_findings))]
    if status_total:
        vacuity_declared_pairs.append(
            ("sum(vacuity.summary status counts)", status_total)
        )

    return {
        "candidate": {"identity": identity},
        "produced": {
            "field": None,
            "value": None,
            "source": (
                "the record declares no generation time; identity.commit and "
                "identity.source_tree_sha256 carry its identity instead"
            ),
        },
        "invocation": {
            "recorded": True,
            "kind": "command-string",
            "exact_arguments": True,
            "entries": [
                {
                    "text": identity.get("settling_method"),
                    "source": "identity.settling_method",
                }
            ],
            "limitation": (
                "the command string is recorded verbatim; no argument vector or "
                "working directory is recorded"
            ),
        },
        "instrument": {
            "recorded": True,
            "kind": "scanner",
            "identity_complete": bool(identity.get("scanner") and identity.get("scanner_sha256")),
            "entries": [
                {
                    "path": identity.get("scanner"),
                    "version": None,
                    "sha256": identity.get("scanner_sha256"),
                    "heuristic": identity.get("heuristic"),
                    "granularity": identity.get("granularity"),
                    "source": "identity.scanner, identity.scanner_sha256",
                }
            ],
            "limitation": (
                "no version field is recorded; the scanner digest is the identity"
            ),
        },
        "populations": [
            block(
                "contract_absent_sites",
                "finding",
                declared=summary.get("contract_absent", len(absent_indexes)),
                declared_sources=[
                    ("summary.contract_absent", summary.get("contract_absent", len(absent_indexes))),
                    ("len(sites.rows where contract_state == 'absent')", len(absent_indexes)),
                ],
                members=[f"sites.rows[{index}]" for index in absent_indexes],
                route=("sites.rows[",),
                export_native_keys=("contract_absent",),
            ),
            block(
                "vacuity_findings",
                "finding",
                declared=len(vacuity_findings),
                declared_sources=vacuity_declared_pairs,
                members=[f"vacuity.findings[{index}]" for index in range(len(vacuity_findings))],
                route=("vacuity.findings[",),
                export_native_keys=("vacuity_findings",),
            ),
            block(
                "suppressions",
                "aggregate_only",
                declared=suppression_total or 0,
                declared_sources=[
                    ("suppressions.total", suppression_total or 0),
                    ("sum(suppressions.by_lint)", sum(by_lint.values())),
                ],
                members=[],
                route=("suppressions",),
                aggregates=("suppressions",),
                bound=suppression_bound,
                export_native_keys=("suppressions",),
                note=(
                    "suppression governance is A6; this block records the declared "
                    "aggregate and the absence of member rows"
                ),
            ),
            block(
                "sites_census",
                "census",
                declared=summary.get("sites", len(rows)),
                declared_sources=[
                    ("summary.sites", summary.get("sites", len(rows))),
                    ("len(sites.rows)", len(rows)),
                ],
                members=[f"sites.rows[{index}]" for index in range(len(rows))],
                not_projected={
                    "block": "sites.rows",
                    "count": len(rows),
                    "reason": (
                        "lexical unsafe-site census, not a finding population; the "
                        "export projects its contract_state=absent members under the "
                        "contract_absent_sites block"
                    ),
                },
                export_native_keys=("sites",),
            ),
            block(
                "operations",
                "declared_scope",
                declared=len((document.get("operations") or {}).get("rows") or []),
                declared_sources=[
                    (
                        "len(operations.rows)",
                        len((document.get("operations") or {}).get("rows") or []),
                    )
                ],
                members=[
                    f"operations.rows[{index}]"
                    for index in range(
                        len((document.get("operations") or {}).get("rows") or [])
                    )
                ],
                not_projected={
                    "block": "operations.rows",
                    "count": len((document.get("operations") or {}).get("rows") or []),
                    "reason": "named raw-operation rows; a separate population",
                },
            ),
            block(
                "contracts",
                "declared_scope",
                declared=len(((document.get("contracts") or {}).get("entries")) or {}),
                declared_sources=[
                    (
                        "len(contracts.entries)",
                        len(((document.get("contracts") or {}).get("entries")) or {}),
                    )
                ],
                members=[
                    f"contracts.entries.{key}"
                    for key in sorted(((document.get("contracts") or {}).get("entries")) or {})
                ],
                not_projected={
                    "block": "contracts.entries",
                    "count": len(((document.get("contracts") or {}).get("entries")) or {}),
                    "reason": "contract text dictionary referenced by row prefix; not findings",
                },
            ),
            block(
                "ignored_tests",
                "declared_scope",
                declared=summary.get("ignored_tests", 0),
                declared_sources=[("summary.ignored_tests", summary.get("ignored_tests", 0))],
                members=[],
                not_projected={
                    "block": "assertions.ignored",
                    "count": summary.get("ignored_tests", 0),
                    "reason": "ignored-test census; suppression governance is A6",
                },
                note=(
                    "the record counts ignored tests without listing them; the count "
                    "is preserved and the member rows are absent by construction"
                ),
            ),
        ],
        "bounds": [suppression_bound],
        "unsupported_operations": [
            {
                "kind": "heuristic-scanner",
                "text": identity.get("granularity"),
                "source": "identity.granularity",
            },
            {
                "kind": "heuristic-census",
                "text": (
                    "the site census is lexical, not a compiler-derived HIR/MIR walk; "
                    "identity.heuristic is recorded verbatim beside it"
                ),
                "source": "identity.heuristic",
            },
            {
                "kind": "ignored-tests",
                "count": summary.get("ignored_tests", 0),
                "source": "summary.ignored_tests",
            },
        ],
        "non_claims": list(document.get("non_claims") or []),
    }


def _describe_timing(document: dict) -> dict:
    primitives = document.get("primitives") or {}
    not_run = document.get("not_run") or []
    instruments = document.get("instruments") or {}
    dudect = document.get("dudect") or {}
    ctgrind = document.get("ctgrind") or {}
    screen = document.get("phase18_screen") or {}

    resource_bound = bound(
        kind="resource",
        population=len(not_run),
        sample=None,
        omitted=len(not_run),
        members_recorded=True,
        what_was_not_examined=(
            "the seven named analyses in not_run were not executed; the run is "
            "further bounded by the declared court caps"
        ),
        source="instruments.court_caps, not_run",
        selection_rule="not_run names each analysis that was not executed",
    )

    return {
        "candidate": {"candidate": document.get("candidate")},
        "produced": {
            "field": "generated_utc",
            "value": document.get("generated_utc"),
            "source": "generated_utc",
        },
        "invocation": {
            "recorded": True,
            "kind": "harness-invocations",
            "exact_arguments": True,
            "entries": [
                {
                    "text": dudect.get("compile"),
                    "source": "dudect.compile",
                    "harness": dudect.get("harness"),
                },
                {
                    "text": (ctgrind.get("harness") or None),
                    "source": "ctgrind.harness",
                },
                {
                    "text": screen.get("instrument"),
                    "source": "phase18_screen.instrument",
                },
                {
                    "text": (document.get("reachability") or {}).get("method"),
                    "source": "reachability.method",
                },
            ],
            "limitation": (
                "compile lines and harness paths are recorded verbatim; the "
                "reachability method is recorded as a structured object"
            ),
        },
        "instrument": {
            "recorded": True,
            "kind": "instrument-register",
            "identity_complete": bool(instruments),
            "entries": [
                {"name": name, "identity": identity, "source": f"instruments.{name}"}
                for name, identity in sorted(instruments.items())
            ],
        },
        "populations": [
            block(
                "primitives",
                "finding",
                declared=len(primitives),
                declared_sources=[("len(primitives)", len(primitives))],
                members=[f"primitives.{name}" for name in sorted(primitives)],
                route=("primitives.",),
                export_native_keys=("primitives",),
            ),
            block(
                "not_run",
                "finding",
                declared=len(not_run),
                declared_sources=[("len(not_run)", len(not_run))],
                members=[f"not_run[{index}]" for index in range(len(not_run))],
                route=("not_run[",),
                export_native_keys=("not_run",),
            ),
        ],
        "bounds": [resource_bound],
        "unsupported_operations": [
            {
                "kind": "not-run",
                "count": len(not_run),
                "source": "not_run",
                "members": list(not_run),
            },
            {
                "kind": "instrument-not-used",
                "text": instruments.get("binsec"),
                "source": "instruments.binsec",
            },
        ],
        "non_claims": list(document.get("non_claims") or []),
    }


def _describe_secrets(document: dict) -> dict:
    entries = document.get("entries") or []
    counts = document.get("counts") or {}
    return {
        "candidate": {"candidate": document.get("candidate")},
        "produced": {
            "field": "generated",
            "value": document.get("generated"),
            "source": "generated",
        },
        "invocation": {"recorded": False, "kind": None, "entries": []},
        "instrument": {
            "recorded": False,
            "kind": None,
            "identity_complete": False,
            "entries": [],
        },
        "populations": [
            block(
                "entries",
                "finding",
                declared=sum(counts.values()) if counts else len(entries),
                declared_sources=[
                    ("sum(counts)", sum(counts.values()) if counts else len(entries)),
                    ("len(entries)", len(entries)),
                ],
                members=[f"entries[{index}]" for index in range(len(entries))],
                route=("entries[",),
                export_native_keys=("entries",),
            )
        ],
        "bounds": [],
        "unsupported_operations": [],
        "non_claims": list(document.get("non_claims") or []),
    }


def _describe_adjudication(document: dict) -> dict:
    mechanisms = ((document.get("item4_mechanisms") or {}).get("per_mechanism")) or {}
    refutations = document.get("ordered_refutations") or []
    return {
        "candidate": {
            "head_at_adjudication": document.get("head_at_adjudication"),
            "evidence_source_head": document.get("evidence_source_head"),
            "source_content_commit": document.get("source_content_commit"),
            "src_content_sha256": document.get("src_content_sha256"),
            "freeze": document.get("freeze"),
        },
        "produced": {
            "field": None,
            "value": None,
            "source": (
                "the record declares no generation time; head_at_adjudication and "
                "freeze.generated_utc carry its identity"
            ),
        },
        "invocation": {"recorded": False, "kind": None, "entries": []},
        "instrument": {
            "recorded": False,
            "kind": None,
            "identity_complete": False,
            "entries": [],
        },
        "populations": [
            block(
                "mechanisms",
                "finding",
                declared=len(mechanisms),
                declared_sources=[("len(item4_mechanisms.per_mechanism)", len(mechanisms))],
                members=[
                    f"item4_mechanisms.per_mechanism.{name}" for name in sorted(mechanisms)
                ],
                route=("item4_mechanisms.per_mechanism.",),
                export_native_keys=("mechanisms",),
            ),
            _record_condition("cross_cutting", "item4_mechanisms.cross_cutting"),
            block(
                "refutations",
                "finding",
                declared=len(refutations),
                declared_sources=[("len(ordered_refutations)", len(refutations))],
                members=[f"ordered_refutations[{index}]" for index in range(len(refutations))],
                route=("ordered_refutations[",),
                export_native_keys=("ordered_refutations",),
            ),
            _record_condition("verdict", "verdict"),
            block(
                "ordered_items",
                "declared_scope",
                declared=len(
                    [key for key in document if re.fullmatch(r"item[1-5]_.*", key)]
                ),
                declared_sources=[
                    (
                        "len(item1_..item5_)",
                        len([key for key in document if re.fullmatch(r"item[1-5]_.*", key)]),
                    )
                ],
                members=[
                    key
                    for key in sorted(document)
                    if re.fullmatch(r"item[1-5]_.*", key)
                ],
                not_projected={
                    "block": "item1..item5",
                    "count": len(
                        [key for key in document if re.fullmatch(r"item[1-5]_.*", key)]
                    ),
                    "reason": (
                        "prose summaries that restate the structured per-mechanism "
                        "and refutation rows; assigning them a level would require "
                        "interpretation the record does not supply"
                    ),
                },
            ),
            block(
                "non_claims",
                "declared_scope",
                declared=len(document.get("non_claims") or []),
                declared_sources=[
                    ("len(non_claims)", len(document.get("non_claims") or []))
                ],
                members=[],
                not_projected={
                    "block": "non_claims",
                    "count": len(document.get("non_claims") or []),
                    "reason": "carried verbatim at run.properties.a1.nativeNonClaims",
                },
            ),
        ],
        "bounds": [],
        "unsupported_operations": [],
        "non_claims": list(document.get("non_claims") or []),
    }


def _describe_row_reconciliation(document: dict) -> dict:
    rows = document.get("rows") or []
    narrative = [
        key
        for key in ("conflict", "cross_check", "closure_evidence_quality_note")
        if key in document
    ]
    return {
        "candidate": {
            "source_candidate": document.get("source_candidate"),
            "head_at_review": document.get("head_at_review"),
        },
        "produced": {
            "field": "generated_utc",
            "value": document.get("generated_utc"),
            "source": "generated_utc",
        },
        "invocation": {"recorded": False, "kind": None, "entries": []},
        "instrument": {
            "recorded": False,
            "kind": None,
            "identity_complete": False,
            "entries": [],
        },
        "populations": [
            block(
                "rows",
                "finding",
                declared=len(rows),
                declared_sources=[("len(rows)", len(rows))],
                members=[f"rows[{index}]" for index in range(len(rows))],
                route=("rows[",),
                export_native_keys=("rows",),
            ),
            _record_condition("limits", "limits"),
            block(
                "narrative",
                "declared_scope",
                declared=len(narrative),
                declared_sources=[
                    (
                        "len(conflict, cross_check, closure_evidence_quality_note)",
                        len(narrative),
                    )
                ],
                members=list(narrative),
                not_projected={
                    "block": "conflict / cross_check / closure_evidence_quality_note",
                    "count": len(narrative),
                    "reason": "reviewer narrative around the reconciled rows; not finding rows",
                },
            ),
        ],
        "bounds": [],
        "unsupported_operations": [],
        "non_claims": [
            value
            for value in (document.get("limits") or {}).values()
            if isinstance(value, str)
        ],
    }


DESCRIBERS: dict[str, Callable[[dict], dict]] = {
    "evidence/b85c-adjudication.json": _describe_adjudication,
    "evidence/b85c-row-reconciliation.json": _describe_row_reconciliation,
    "evidence/closure-curl-049.json": _describe_curl,
    "evidence/etp-t4/SAFETY-SITES.json": _describe_safety,
    "evidence/etp-t7/SECRETS.json": _describe_secrets,
    "evidence/timing-bn-findings.json": _describe_timing,
}

# Why a source without a structured producer identity is refused, and where the
# record mentions the producer without recording it as a field.
IDENTITY_NOTES = {
    "evidence/b85c-adjudication.json": (
        "the record is a human adjudication; item2_closures and item3_instruments "
        "name tool digests and stored logs in prose, and no field records the "
        "producer path, version or digest as a machine identity"
    ),
    "evidence/b85c-row-reconciliation.json": (
        "the record is a reviewer reconciliation; its narrative blocks and limits "
        "record what was not reviewed in prose, and no field records the producer "
        "as a machine identity"
    ),
    "evidence/etp-t7/SECRETS.json": (
        "the record is a hand-maintained classification register; it names "
        "governing documents, not a producing instrument, and no field records an "
        "invocation"
    ),
}

INSTRUMENT_FIELDS = (
    "tool.path with tool.version or tool.sha256",
    "identity.scanner with identity.scanner_sha256",
    "instruments.* (the instrument register)",
)
INVOCATION_FIELDS = (
    "a structured command, harness, compile line or procedure field",
)


def describe_source(record: str, document: dict) -> dict:
    if record not in DESCRIBERS:
        raise Refusal(R_UNREADABLE, f"{record}: no preservation descriptor")
    return DESCRIBERS[record](document)


def certification(record: str, described: dict) -> dict:
    invocation = described["invocation"]
    instrument = described["instrument"]
    invoked = bool(invocation.get("recorded"))
    identified = bool(instrument.get("recorded")) and bool(
        instrument.get("identity_complete")
    )
    searched = {
        "instrument_fields": list(INSTRUMENT_FIELDS),
        "invocation_fields": list(INVOCATION_FIELDS),
    }
    if not invoked and not identified:
        code = R_NO_INVOCATION_OR_INSTRUMENT
    elif not identified:
        code = R_NO_INSTRUMENT
    elif not invoked:
        code = R_NO_INVOCATION
    else:
        code = None
    entry = {
        "certified": code is None,
        "refusal": code,
        "searched": searched,
    }
    if code is not None and record in IDENTITY_NOTES:
        entry["note"] = IDENTITY_NOTES[record]
    return entry


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

def _sarif_runs(repo_root: Path) -> dict[str, dict]:
    path = repo_root / SARIF_PATH
    if not path.exists():
        return {}
    document = load_json(path)
    runs = {}
    for index, run in enumerate(document.get("runs") or []):
        record = ((run.get("properties") or {}).get("a1") or {}).get("record") or {}
        runs[record.get("path")] = {
            "run_index": index,
            "sha256": record.get("sha256"),
            "schema": record.get("schema"),
        }
    return runs


def capture(
    repo_root: Path | str,
    sources: Iterable[str] | None = None,
    store_root: Path | str | None = None,
) -> dict:
    """Preserve the bytes, producer identity and populations of each source."""
    repo_root = Path(repo_root)
    store = Path(store_root) if store_root is not None else None
    names = list(sources) if sources is not None else sorted(DESCRIBERS)
    unknown = [name for name in names if name not in DESCRIBERS]
    if unknown:
        raise Refusal(R_UNREADABLE, f"unknown source(s): {', '.join(unknown)}")

    runs = _sarif_runs(repo_root)
    entries = []
    refusals = []
    for record in names:
        data = read_bytes(repo_root / record)
        digest = sha256_bytes(data)
        try:
            document = json.loads(data)
        except json.JSONDecodeError as exc:
            raise Refusal(R_UNREADABLE, f"{record}: invalid JSON: {exc}") from exc
        path = store_path(repo_root, digest, store)
        write_store(path, data, digest)

        described = describe_source(record, document)
        for limit in described["bounds"]:
            if not limit.get("what_was_not_examined"):
                raise Refusal(
                    R_BOUND_UNEXPLAINED,
                    f"{record}: bound {limit.get('kind')!r} at {limit.get('source')} "
                    "does not name what was not examined",
                )

        populations = []
        for item in described["populations"]:
            enumerated = len(item["members"])
            bound_info = item.get("bound")
            if item["role"] in {"finding", "census"} and enumerated < item["declared"]:
                if bound_info is None:
                    raise Refusal(
                        R_POPULATION,
                        f"{record}: block {item['name']!r} declares "
                        f"{item['declared']} members and lists {enumerated} with no "
                        "declared bound",
                    )
                if bound_info.get("population") != item["declared"]:
                    raise Refusal(
                        R_POPULATION,
                        f"{record}: block {item['name']!r} declares "
                        f"{item['declared']} members; its bound declares "
                        f"{bound_info.get('population')}",
                    )
            populations.append(
                {
                    "name": item["name"],
                    "role": item["role"],
                    "declared": item["declared"],
                    "declared_sources": item["declared_sources"],
                    "enumerated": enumerated,
                    "members_recorded": True,
                    "member_selector": (
                        "the member locators are a deterministic function of the "
                        "preserved bytes and the block selector in "
                        "forensics/tools/evidence_preservation.py"
                    ),
                    "bound": bound_info,
                    "export_native_keys": item["export_native_keys"],
                }
            )

        certification_entry = certification(record, described)
        entry = {
            "record": record,
            "schema": document.get("schema"),
            "export": {
                "path": SARIF_PATH,
                "run_index": runs.get(record, {}).get("run_index"),
                "run_record_sha256": runs.get(record, {}).get("sha256"),
            },
            "raw": {
                "sha256": digest,
                "byte_length": len(data),
                "address": address(digest),
                "preserved_path": preserved_path_text(repo_root, path),
            },
            "candidate": described["candidate"],
            "produced": described["produced"],
            "invocation": described["invocation"],
            "instrument": described["instrument"],
            "populations": populations,
            "bounds": described["bounds"],
            "unsupported_operations": described["unsupported_operations"],
            "non_claims": described["non_claims"],
            "certification": certification_entry,
        }
        entries.append(entry)
        if not certification_entry["certified"]:
            refusals.append(
                {
                    "record": record,
                    "code": certification_entry["refusal"],
                    "detail": (
                        "the native record carries no structured invocation and no "
                        "structured instrument identity"
                        if certification_entry["refusal"] == R_NO_INVOCATION_OR_INSTRUMENT
                        else certification_entry["refusal"]
                    ),
                }
            )

    document_out = {
        "schema": SCHEMA_PRESERVATION,
        "tool": tool_identity(),
        "purpose": (
            "the bytes, producer identity, populations, bounds and declared "
            "limitations of every native record that feeds the A1 export, each "
            "content-addressed and named by digest"
        ),
        "address_scheme": {
            "algorithm": "sha-256",
            "address": "preservation:sha256:<hex>",
            "store": STORE_ROOT,
            "rule": (
                "the store entry named by the digest holds the exact bytes that "
                "were read; verification re-derives the digest from those bytes"
            ),
        },
        "export": {
            "path": SARIF_PATH,
            "sha256": sha256_bytes((repo_root / SARIF_PATH).read_bytes())
            if (repo_root / SARIF_PATH).exists()
            else None,
        },
        "sources": entries,
        "refusals": refusals,
        "not_claims": [
            "Preservation is not completeness: a preserved record can still "
            "describe an incomplete population, and A5 owns that judgement.",
            "Preservation is not correctness: preserved bytes can encode a wrong "
            "result.",
            "The store copies bytes; it does not interpret them, and no claim is "
            "made that a preserved record was produced honestly.",
        ],
    }
    return document_out


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------

def _route_length(block_entry: dict, locator: str) -> int | None:
    lengths = []
    for prefix in block_entry["route"]:
        if locator == prefix:
            lengths.append(len(prefix))
        elif prefix.endswith((".", "[")) and locator.startswith(prefix):
            lengths.append(len(prefix))
    if locator in block_entry["aggregates"]:
        lengths.append(len(locator))
    return max(lengths) if lengths else None


def _classify(blocks: list[dict], locator: str) -> int | None:
    best = None
    best_length = -1
    for index, item in enumerate(blocks):
        length = _route_length(item, locator)
        if length is None:
            continue
        if length > best_length:
            best, best_length = index, length
    return best


def _reconcile_block(
    item: dict,
    document: dict,
    results: list[dict],
    assigned: dict[int, list[dict]],
    index: int,
) -> dict:
    members = item["members"]
    member_set = set(members)
    route_results = assigned.get(index, [])

    exported_members: set[str] = set()
    attached = 0
    aggregates = 0
    fabricated: list[str] = []
    for result in route_results:
        locator = result["locator"]
        if locator in item["aggregates"]:
            aggregates += 1
            continue
        resolved = None
        for candidate in member_candidates(locator):
            if candidate in member_set:
                resolved = candidate
                break
        if resolved is None:
            fabricated.append(locator)
            continue
        exported_members.add(resolved)
        if resolved != locator:
            attached += 1

    role = item["role"]
    members_listed = role in {"finding", "census", "record_condition"}

    not_projected = item.get("not_projected")
    uncovered = member_set - exported_members
    if not_projected is not None:
        declared_omitted = not_projected["count"]
        if declared_omitted < len(uncovered) and role != "census":
            # The declaration covers fewer members than are missing.
            unaccounted = sorted(uncovered)[declared_omitted:]
        else:
            unaccounted = []
    else:
        unaccounted = sorted(uncovered)
        declared_omitted = 0

    members_not_enumerated = item["declared"] - len(members)
    if members_not_enumerated < 0:
        raise Refusal(
            R_POPULATION,
            f"{item['name']!r}: {len(members)} members enumerated against a declared "
            f"population of {item['declared']}",
        )
    unidentified = members_not_enumerated if members_listed else 0
    bound_info = item.get("bound")

    if role == "finding":
        covers = (
            unidentified == 0
            and not unaccounted
            and not fabricated
            and exported_members == member_set
        )
        if covers:
            coverage = "CENSUS"
        elif unidentified and bound_info is not None:
            coverage = "TRUNCATED_BOUNDED"
        elif unidentified:
            coverage = "NOT_CENSUS"
        else:
            coverage = "INCOMPLETE"
    elif role == "record_condition":
        covers = exported_members == member_set and not fabricated
        coverage = "RECORD_CONDITION" if covers else "INCOMPLETE"
    elif role == "census":
        covers = False
        coverage = "CENSUS_DECLARED_NOT_PROJECTED" if not_projected else "NOT_CENSUS"
    elif role == "aggregate_only":
        covers = False
        coverage = "AGGREGATE_ONLY"
    else:  # declared_scope
        covers = False
        coverage = "DECLARED_SCOPE"

    if fabricated:
        raise Refusal(
            R_FABRICATED,
            f"{item['name']!r}: the export emits {len(fabricated)} member(s) the "
            f"native record does not contain: {sorted(fabricated)[:5]}",
        )
    if unaccounted:
        raise Refusal(
            R_UNACCOUNTED,
            f"{item['name']!r}: {len(unaccounted)} native member(s) are neither "
            f"emitted nor covered by a declared omission: {unaccounted[:5]}",
        )

    return {
        "name": item["name"],
        "role": role,
        "declared": item["declared"],
        "declared_sources": item["declared_sources"],
        "enumerated": len(members),
        "members_listed": members_listed,
        "exported_results": len(route_results),
        "exported_members": len(exported_members),
        "attached_results": attached,
        "aggregate_results": aggregates,
        "not_projected_declared": not_projected["count"] if not_projected else None,
        "members_not_enumerated": members_not_enumerated,
        "unidentified": unidentified,
        "bound": bound_info,
        "unaccounted": unaccounted,
        "fabricated": fabricated,
        "covers_population": covers,
        "coverage": coverage,
    }


def reconcile(
    repo_root: Path | str,
    preservation: dict,
    sarif_path: Path | str | None = None,
) -> dict:
    """Compare each export run's emitted members with the native population."""
    repo_root = Path(repo_root)
    sarif_file = Path(sarif_path) if sarif_path is not None else repo_root / SARIF_PATH
    sarif_bytes = read_bytes(sarif_file)
    sarif_digest = sha256_bytes(sarif_bytes)
    try:
        sarif = json.loads(sarif_bytes)
    except json.JSONDecodeError as exc:
        raise Refusal(R_UNREADABLE, f"{sarif_file}: invalid JSON: {exc}") from exc

    runs = sarif.get("runs") or []
    run_by_record: dict[str, tuple[int, dict]] = {}
    for index, run in enumerate(runs):
        record = ((run.get("properties") or {}).get("a1") or {}).get("record") or {}
        run_by_record[record.get("path")] = (index, run)

    reconciled = []
    totals = {
        "runs": 0,
        "runs_certified": 0,
        "runs_refused": 0,
        "results": 0,
        "results_reconciled": 0,
        "native_members_enumerated": 0,
        "exported_members_matched": 0,
        "unaccounted": 0,
        "fabricated": 0,
        "unidentified": 0,
        "coverage_claims_refused": 0,
    }
    for source in preservation["sources"]:
        record = source["record"]
        if record not in run_by_record:
            raise Refusal(
                R_POPULATION,
                f"{record}: the export contains no run for this preserved source",
            )
        run_index, run = run_by_record[record]
        run_record = ((run.get("properties") or {}).get("a1") or {}).get("record") or {}
        a1 = (run.get("properties") or {}).get("a1") or {}
        projection = a1.get("projection") or {}
        declared_projected = projection.get("projected") or {}

        document = load_json(repo_root / record)
        described = describe_source(record, document)
        blocks = described["populations"]

        results = []
        for result in run.get("results") or []:
            native = ((result.get("properties") or {}).get("a1") or {}).get("native") or {}
            results.append(
                {
                    "rule": result.get("ruleId"),
                    "locator": native.get("locator"),
                }
            )
        if any(result["locator"] is None for result in results):
            raise Refusal(R_UNROUTED, f"{record}: a result carries no native locator")

        assigned: dict[int, list[dict]] = {index: [] for index in range(len(blocks))}
        for result in results:
            index = _classify(blocks, result["locator"])
            if index is None:
                raise Refusal(
                    R_UNROUTED,
                    f"{record}: result at {result['locator']!r} matches no native "
                    "population block",
                )
            assigned[index].append(result)

        block_reports = [
            _reconcile_block(item, document, results, assigned, index)
            for index, item in enumerate(blocks)
        ]

        # The export's own declaration of what it omitted is checked against the
        # native count of the same block. A declared omission that re-scopes a
        # population is a population disagreement, not a limitation.
        declared_not_projected = {
            entry.get("block"): entry.get("count")
            for entry in (projection.get("notProjected") or [])
        }
        for item, report in zip(blocks, block_reports):
            if item.get("not_projected") is None:
                continue
            name = item["not_projected"]["block"]
            if name not in declared_not_projected:
                raise Refusal(
                    R_POPULATION,
                    f"{record}: block {item['name']!r} is declared omitted by the "
                    f"native count {item['not_projected']['count']}, but the export "
                    f"declares no omission for {name!r}",
                )
            exported_count = declared_not_projected[name]
            if exported_count == item["not_projected"]["count"]:
                continue
            explained = (
                item.get("bound") is not None
                and item["bound"].get("population") == item["declared"]
                and item["bound"].get("omitted") == exported_count
            )
            if not explained:
                raise Refusal(
                    R_POPULATION,
                    f"{record}: the export declares {exported_count} member(s) "
                    f"omitted for {name!r}; the native record counts "
                    f"{item['not_projected']['count']} and declares no bound that "
                    "reconciles the difference",
                )

        emitted_by_rule: dict[str, int] = {}
        for result in results:
            emitted_by_rule[result["rule"]] = emitted_by_rule.get(result["rule"], 0) + 1
        projection_ok = emitted_by_rule == declared_projected

        finding_blocks = [
            block for block in block_reports if block["role"] == "finding"
        ]
        aggregate_blocks = [
            block
            for block in block_reports
            if block["role"] == "aggregate_only" and block["declared"] > 0
        ]
        native_minus_export = sum(
            block["unidentified"] + len(block["unaccounted"])
            for block in finding_blocks
        )
        export_minus_native = sum(len(block["fabricated"]) for block in block_reports)
        declared_scope_not_emitted = sum(
            block["declared"] - block["exported_members"]
            for block in block_reports
            if block["role"] in {"census", "declared_scope"}
        )

        covers_population = (
            bool(finding_blocks)
            and all(block["covers_population"] for block in finding_blocks)
            and not aggregate_blocks
        )
        if covers_population:
            reason = None
        elif aggregate_blocks:
            reason = (
                "a declared population has no member rows, so the export cannot "
                "cover it: "
                + ", ".join(
                    f"{block['name']} ({block['declared']} members, none recorded)"
                    for block in aggregate_blocks
                )
            )
        else:
            reason = (
                "at least one finding block is not a census of its declared "
                "population: the reconciliation names the unidentified or "
                "unaccounted members in the block rows"
            )

        certification = source["certification"]
        reconciled.append(
            {
                "record": record,
                "export_run_index": run_index,
                "export_run_sha256": run_record.get("sha256"),
                "preserved_sha256": source["raw"]["sha256"],
                "digest_match": run_record.get("sha256") == source["raw"]["sha256"],
                "certified": certification["certified"],
                "certification_refusal": certification["refusal"],
                "emitted_results": len(results),
                "declared_projection": declared_projected,
                "emitted_by_rule": emitted_by_rule,
                "projection_consistent": projection_ok,
                "export_native_population": projection.get("nativePopulation"),
                "export_declares_not_projected": projection.get("notProjected"),
                "blocks": block_reports,
                "difference": {
                    "native_members_outside_export": native_minus_export,
                    "unidentified_finding_members": sum(
                        block["unidentified"] for block in finding_blocks
                    ),
                    "unaccounted_members": sum(
                        len(block["unaccounted"]) for block in block_reports
                    ),
                    "export_members_absent_from_native": export_minus_native,
                    "declared_populations_without_member_rows": [
                        {"name": block["name"], "declared": block["declared"]}
                        for block in aggregate_blocks
                    ],
                    "declared_scope_members_not_emitted": declared_scope_not_emitted,
                },
                "coverage": {
                    "covers_population": covers_population,
                    "claim": "ADMITTED" if covers_population else "REFUSED",
                    "reason": reason,
                },
            }
        )

        totals["runs"] += 1
        totals["results"] += len(results)
        totals["results_reconciled"] += len(results)
        totals["native_members_enumerated"] += sum(
            block["enumerated"] for block in block_reports
        )
        totals["exported_members_matched"] += sum(
            block["exported_members"] for block in block_reports
        )
        totals["unaccounted"] += sum(len(block["unaccounted"]) for block in block_reports)
        totals["fabricated"] += sum(len(block["fabricated"]) for block in block_reports)
        totals["unidentified"] += sum(block["unidentified"] for block in finding_blocks)
        totals["coverage_claims_refused"] += 0 if covers_population else 1
        if certification["certified"]:
            totals["runs_certified"] += 1
        else:
            totals["runs_refused"] += 1

    document = {
        "schema": SCHEMA_RECONCILIATION,
        "tool": tool_identity(),
        "purpose": (
            "for each export run, the native population enumerated from the native "
            "record compared member-by-member with the members the export emitted, "
            "with the difference named in both directions"
        ),
        "preservation": {
            "path": "evidence/a2/PRESERVATION.json",
            "sha256": sha256_bytes(dump_json(preservation).encode("utf-8")),
        },
        "export": {
            "path": SARIF_PATH,
            "sha256": sarif_digest,
            "runs": len(runs),
            "results": sum(len(run.get("results") or []) for run in runs),
        },
        "rules": {
            "member": (
                "a native member is a locator into the native record; the export's "
                "member is the locator carried at properties.a1.native.locator; a "
                "nested locator attaches to its enclosing member and is counted as "
                "an attached result, not as a member"
            ),
            "missing_in_each_direction": (
                "native minus export is `unidentified` (counted, not listed) plus "
                "`unaccounted` (listed, and refused); export minus native is "
                "`fabricated` (listed, and refused)"
            ),
            "coverage": (
                "covers_population is true only when every finding block is a "
                "census of its declared population; a declared bound preserves the "
                "omission as TRUNCATED_BOUNDED and still refuses coverage"
            ),
        },
        "runs": reconciled,
        "summary": totals,
        "not_claims": [
            "Reconciliation is not completeness admission (A5).",
            "Reconciliation is not suppression governance (A6).",
            "A member that is present is not a member that is correct, justified or "
            "current; presence is all the reconciliation establishes.",
        ],
    }
    return document


def assert_covers_population(run_reconciliation: dict) -> None:
    """Refuse a caller that claims the export covers a population it does not."""
    if not run_reconciliation["coverage"]["covers_population"]:
        raise Refusal(
            R_COVERAGE_CLAIM,
            f"{run_reconciliation['record']}: the export does not cover the native "
            f"population ({run_reconciliation['difference']['native_members_outside_export']} "
            "native member(s) outside the export); a coverage claim is refused",
        )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify(
    repo_root: Path | str,
    preservation: dict,
    store_root: Path | str | None = None,
    sarif_path: Path | str | None = None,
) -> dict:
    """Re-derive every address and check every refusal condition.

    Raises :class:`Refusal` on the first condition that fires. Returns a report
    naming every record checked and its certification state.
    """
    repo_root = Path(repo_root)
    store = Path(store_root) if store_root is not None else None
    sarif_file = Path(sarif_path) if sarif_path is not None else repo_root / SARIF_PATH
    current = tool_identity()
    recorded = (preservation.get("tool") or {}).get("sha256")
    if recorded is not None and recorded != current["sha256"]:
        raise Refusal(
            R_TOOL_IDENTITY,
            "the preservation document was produced by a different tool "
            f"({str(recorded)[:16]}… versus {current['sha256'][:16]}…); it must be "
            "re-captured before it is trusted",
        )
    runs = _sarif_runs(repo_root)

    checked = []
    refusals = []
    for source in preservation["sources"]:
        record = source["record"]
        digest = source["raw"]["sha256"]
        path = store_path(repo_root, digest, store)
        data = read_store(path, digest)

        live_path = repo_root / record
        if not live_path.exists():
            raise Refusal(R_RAW_ABSENT, f"{record}: the native record is absent")
        live = sha256_bytes(live_path.read_bytes())
        if live != digest:
            export_digest = (runs.get(record) or {}).get("sha256")
            if export_digest == digest:
                raise Refusal(
                    R_STALE_REEXPORT,
                    f"{record}: the native bytes changed after capture (live "
                    f"{live[:16]}…, preserved {digest[:16]}…) and the export still "
                    "cites the preserved digest",
                )
            raise Refusal(
                R_MANIFEST_STALE,
                f"{record}: the native bytes changed after capture (live "
                f"{live[:16]}…, preserved {digest[:16]}…); the preservation record "
                "no longer describes the export's input and must be re-captured",
            )

        export_digest = (runs.get(record) or {}).get("sha256")
        if export_digest is not None and export_digest != digest:
            raise Refusal(
                R_DIGEST_MISMATCH,
                f"{record}: the export cites {export_digest[:16]}… for a record whose "
                f"preserved bytes hash to {digest[:16]}…",
            )

        document = json.loads(data)
        described = describe_source(record, document)
        for item in described["populations"]:
            if item["role"] in {"finding", "census"} and len(item["members"]) < item["declared"]:
                if item.get("bound") is None:
                    raise Refusal(
                        R_POPULATION,
                        f"{record}: block {item['name']!r} declares {item['declared']} "
                        f"members and lists {len(item['members'])} with no declared bound",
                    )
        for limit in described["bounds"]:
            if not limit.get("what_was_not_examined"):
                raise Refusal(
                    R_BOUND_UNEXPLAINED,
                    f"{record}: bound {limit.get('kind')!r} does not name what was "
                    "not examined",
                )
        for limit in source.get("bounds") or []:
            if not limit.get("what_was_not_examined"):
                raise Refusal(
                    R_BOUND_UNEXPLAINED,
                    f"{record}: the preserved bound {limit.get('kind')!r} recorded "
                    "from "
                    f"{limit.get('source')} does not name what was not examined",
                )

        entry = certification(record, described)
        checked.append(
            {
                "record": record,
                "address": address(digest),
                "bytes_verified": len(data),
                "certified": entry["certified"],
                "refusal": entry["refusal"],
            }
        )
        if not entry["certified"]:
            refusals.append(
                {
                    "record": record,
                    "code": entry["refusal"],
                    "note": entry.get("note"),
                }
            )

    report = {"checked": checked, "refusals": refusals}
    if refusals:
        codes = sorted({item["code"] for item in refusals})
        raise Refusal(
            codes[0],
            f"{len(refusals)} source(s) cannot be certified: "
            + ", ".join(f"{item['record']} ({item['code']})" for item in refusals),
        )
    return report


def check_reconciliation(
    repo_root: Path | str,
    reconciliation: dict,
    preservation: dict,
    sarif_path: Path | str | None = None,
) -> dict:
    """Re-derive the addresses a reconciliation names.

    A reconciliation over changed native or exported bytes that reuses the old
    digest is refused here, because the recorded digest no longer resolves.
    """
    repo_root = Path(repo_root)
    sarif_file = Path(sarif_path) if sarif_path is not None else repo_root / SARIF_PATH
    current = tool_identity()
    recorded = (reconciliation.get("tool") or {}).get("sha256")
    if recorded is not None and recorded != current["sha256"]:
        raise Refusal(
            R_TOOL_IDENTITY,
            "the reconciliation was produced by a different tool "
            f"({str(recorded)[:16]}… versus {current['sha256'][:16]}…)",
        )
    preservation_digest = sha256_bytes(dump_json(preservation).encode("utf-8"))
    if reconciliation["preservation"]["sha256"] != preservation_digest:
        raise Refusal(
            R_DIGEST_MISMATCH,
            "the reconciliation names preservation bytes "
            f"{reconciliation['preservation']['sha256'][:16]}… but the loaded "
            f"preservation document hashes to {preservation_digest[:16]}…",
        )
    export_digest = sha256_bytes(read_bytes(sarif_file))
    if reconciliation["export"]["sha256"] != export_digest:
        raise Refusal(
            R_DIGEST_MISMATCH,
            "the reconciliation names export bytes "
            f"{reconciliation['export']['sha256'][:16]}… but the export hashes to "
            f"{export_digest[:16]}…; a reconciliation is not reusable across exports",
        )
    sources = {source["record"]: source for source in preservation["sources"]}
    for run in reconciliation["runs"]:
        source = sources.get(run["record"])
        if source is None:
            raise Refusal(
                R_DIGEST_MISMATCH,
                f"{run['record']}: the reconciliation names a record the preservation "
                "manifest does not contain",
            )
        if run["preserved_sha256"] != source["raw"]["sha256"]:
            raise Refusal(
                R_DIGEST_MISMATCH,
                f"{run['record']}: the reconciliation and the manifest disagree on "
                "the native digest",
            )
    return {"preservation": "verified", "export": "verified", "runs": len(reconciliation["runs"])}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo-root", default=".", type=Path)
    parser.add_argument("--store-root", default=None, type=Path)
    sub = parser.add_subparsers(dest="command", required=True)

    capture_parser = sub.add_parser("capture", help="preserve bytes and populations")
    capture_parser.add_argument("--out", default=None, type=Path)
    capture_parser.add_argument("--source", action="append", default=None)

    reconcile_parser = sub.add_parser("reconcile", help="reconcile native and exported populations")
    reconcile_parser.add_argument("--preservation", default=None, type=Path)
    reconcile_parser.add_argument("--sarif", default=None, type=Path)
    reconcile_parser.add_argument("--out", default=None, type=Path)

    verify_parser = sub.add_parser("verify", help="re-derive every address and refusal")
    verify_parser.add_argument("--preservation", default=None, type=Path)
    verify_parser.add_argument("--sarif", default=None, type=Path)
    verify_parser.add_argument("--reconciliation", default=None, type=Path)

    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()

    try:
        if args.command == "capture":
            document = capture(repo_root, args.source, args.store_root)
            text = dump_json(document)
            if args.out is not None:
                args.out.write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
            return 0
        if args.command == "reconcile":
            preservation_path = args.preservation or repo_root / "evidence/a2/PRESERVATION.json"
            preservation = load_json(preservation_path)
            document = reconcile(repo_root, preservation, args.sarif)
            text = dump_json(document)
            if args.out is not None:
                args.out.write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
            return 0
        if args.command == "verify":
            preservation_path = args.preservation or repo_root / "evidence/a2/PRESERVATION.json"
            preservation = load_json(preservation_path)
            report = {}
            if args.reconciliation is not None:
                reconciliation = load_json(args.reconciliation)
                report["reconciliation"] = check_reconciliation(
                    repo_root, reconciliation, preservation, args.sarif
                )
            report.update(verify(repo_root, preservation, args.store_root, args.sarif))
            sys.stdout.write(dump_json(report))
            return 0
    except Refusal as refusal:
        sys.stderr.write(f"{refusal.code}: {refusal.detail}\n")
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
