#!/usr/bin/env python3
"""verification_summary.py -- a summary that cannot outlive or replace its evidence.

Why this tool exists
--------------------
A verification summary is written *after* a policy decision. It condenses the
decision -- how many obligations are `MET`, `UNMET`, `UNKNOWN` or
`NOT_APPLICABLE`, which decision was reached, which obligations are unmet -- so a
human can read it. The failure it invites is not that it is wrong on the day it
is written. It is that it **drifts**: the sources change, the summary does not,
and the summary is then cited because it is shorter, signed and easier to read
than the records it condensed. A summary that has outlived its evidence is worse
than no summary, because it carries the appearance of a verification.

This module makes the summary reconstructible:

* every count is **recounted** from the obligation list, never copied from the
  decision's own totals;
* every source the decision read is cited **by path and digest**, and the digest
  is of the bytes, not of a description of them;
* the summary is wrapped as an in-toto Statement v1 (A9's subject machinery) whose
  subject is the decision record by digest, and signed as a DSSE envelope (A10);
* the signature is labelled `SELF_ISSUED` under A12. The only key in this tree is
  A10's test-only HMAC-SHA256 key derived from a fixed public seed. A signature
  proves the summary's bytes are unchanged since signing. It does **not** prove
  who issued the summary, that the decision is correct, or that an independent
  party stands behind either.

The marker ``replacesEvidence: false`` is part of the record, not a comment: a
consumer that cites the summary *instead of* the sources is refused by
`AS_REFUSED_SUMMARY_AS_EVIDENCE`.

What this module does not establish
-----------------------------------
A reconstructible summary is not a verification. It reproduces the decision's
mapping over the cited bytes; it does not establish that the predicates were the
right ones, that the sources are true, that the decision is correct, or that the
release should be admitted. A summary is not an admission. It never replaces the
records a third party needs to reconstruct the decision.

What it cannot do
-----------------
A9's predicate registry is closed (``intoto.PREDICATES``), and this tool may not
edit another item's tool. The A21 predicate type is therefore validated here,
against the same Statement v1 shape, with A9's subject constructor and verifier
(``intoto.subject_for`` / ``intoto.verify_subject``) doing the identity work. That
gap is recorded in ``docs/VERIFICATION-SUMMARIES.md`` as a retained obligation,
not claimed as A9 registration.

Usage
-----
    python3 forensics/tools/verification_summary.py summarise [--decision PATH]
        [--out PATH] [--root DIR]
    python3 forensics/tools/verification_summary.py reconstruct <summary>
        [--decision PATH] [--policy PATH] [--root DIR] [--json]
    python3 forensics/tools/verification_summary.py verify <summary> <envelope>
        [--decision PATH] [--policy PATH] [--root DIR] [--json]

Exit status: 0 for a success, 1 for a refusal (the stable code is always
printed), 2 for a usage error (``AS_USAGE`` is printed).

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

TOOLS = Path(__file__).resolve().parent
REPO_ROOT = TOOLS.parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402
import intoto  # noqa: E402
import policy_engine as pe  # noqa: E402

TOOL_PATH = "forensics/tools/verification_summary.py"
MODEL_ID = "a21/v1"
SUMMARY_SCHEMA = "openssl-rs/a21/summary/1"
CONTROLS_SCHEMA = "openssl-rs/a21/controls/1"
RECONSTRUCTION_SCHEMA = "openssl-rs/a21/reconstruction/1"

DEFAULT_DECISION = REPO_ROOT / "evidence/a20/DECISION.json"
DEFAULT_POLICY = REPO_ROOT / "evidence/a20/POLICY.json"
DECISION_PATH = "evidence/a20/DECISION.json"
POLICY_PATH = "evidence/a20/POLICY.json"

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://openssl-rs.invalid/attestation/verification-summary/v1"
SIGNATURE_LABEL = "SELF_ISSUED"
AUTHENTICATION = "NOT_CLAIMED"

TOP_LEVEL = "summary"
REPLACES_EVIDENCE = False
COUNT_KEYS = ("met", "unmet", "unknown", "notApplicable")
STATE_TO_COUNT = {
    pe.STATE_MET: "met",
    pe.STATE_UNMET: "unmet",
    pe.STATE_UNKNOWN: "unknown",
    pe.STATE_NOT_APPLICABLE: "notApplicable",
}

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
CODE_OK = "AS_OK"
CODE_USAGE = "AS_USAGE"

# ---------------------------------------------------------------------------
# Refusal codes. Each is stable and names the wrong conclusion it prevents.
# The document (docs/VERIFICATION-SUMMARIES.md) must name every code here, and
# the test suite refuses a code that appears in one and not the other.
# ---------------------------------------------------------------------------

AS_REFUSED_SUMMARY_AS_EVIDENCE = "AS_REFUSED_SUMMARY_AS_EVIDENCE"
AS_REFUSED_COUNTS_MISMATCH = "AS_REFUSED_COUNTS_MISMATCH"
AS_REFUSED_EVIDENCE_ABSENT = "AS_REFUSED_EVIDENCE_ABSENT"
AS_REFUSED_SOURCE_DIGEST_MISMATCH = "AS_REFUSED_SOURCE_DIGEST_MISMATCH"
AS_REFUSED_NO_SOURCE_DIGEST = "AS_REFUSED_NO_SOURCE_DIGEST"
AS_REFUSED_COVERAGE_GAP = "AS_REFUSED_COVERAGE_GAP"
AS_REFUSED_DUPLICATE_OBLIGATION = "AS_REFUSED_DUPLICATE_OBLIGATION"
AS_REFUSED_DECISION_UPGRADED = "AS_REFUSED_DECISION_UPGRADED"
AS_REFUSED_OVERCLAIM = "AS_REFUSED_OVERCLAIM"
AS_REFUSED_NON_RECONSTRUCTIBLE = "AS_REFUSED_NON_RECONSTRUCTIBLE"
AS_REFUSED_SUMMARY_UNSIGNED = "AS_REFUSED_SUMMARY_UNSIGNED"
AS_REFUSED_SUMMARY_MUTATED = "AS_REFUSED_SUMMARY_MUTATED"

REFUSALS: dict[str, dict[str, str]] = {
    AS_REFUSED_SUMMARY_AS_EVIDENCE: {
        "condition": (
            "a consumer cites the summary in place of the sources it condensed, "
            "the summary declares `replacesEvidence` other than false, or the "
            "consumer omits one of the cited sources"
        ),
        "prevents": (
            "that a short, signed document is read as the verification, so the "
            "sources may change and the summary still stands in their place"
        ),
    },
    AS_REFUSED_COUNTS_MISMATCH: {
        "condition": (
            "a count in the summary differs from the recount of its obligation "
            "list, from the recount over the cited sources, or from the decision's "
            "own totals"
        ),
        "prevents": (
            "that a count is copied, rounded or corrected by hand, so a summary "
            "reports a state its obligations and sources do not support"
        ),
    },
    AS_REFUSED_EVIDENCE_ABSENT: {
        "condition": (
            "a cited source, the decision record, the policy record or the "
            "envelope is not present or is unreadable"
        ),
        "prevents": (
            "that absence is read as agreement, and that a summary is reconstructed "
            "from the records that happen to remain"
        ),
    },
    AS_REFUSED_SOURCE_DIGEST_MISMATCH: {
        "condition": (
            "the bytes at a cited source path hash to something other than the "
            "digest the summary, the decision or the source manifest records"
        ),
        "prevents": (
            "that a source changed after the decision and the summary is still "
            "read as a summary of the decision over the new bytes"
        ),
    },
    AS_REFUSED_NO_SOURCE_DIGEST: {
        "condition": "an obligation in the summary carries no well-formed source digest",
        "prevents": (
            "that a source is named without an identity, so any bytes at that path "
            "would satisfy the citation"
        ),
    },
    AS_REFUSED_COVERAGE_GAP: {
        "condition": "an obligation declared by the decision's policy is absent from the summary",
        "prevents": (
            "that a summary omits the obligation that failed, and the remaining "
            "obligations are read as the decision's whole coverage"
        ),
    },
    AS_REFUSED_DUPLICATE_OBLIGATION: {
        "condition": "two entries in the summary share an obligation id",
        "prevents": (
            "that one obligation is counted twice, or that a duplicate silently "
            "overwrites the entry beside it"
        ),
    },
    AS_REFUSED_DECISION_UPGRADED: {
        "condition": "the summary records `ADMIT` where the decision records `DENY`",
        "prevents": (
            "that a denial is published as an admission by editing the one word a "
            "human is most likely to read"
        ),
    },
    AS_REFUSED_OVERCLAIM: {
        "condition": (
            "the summary states an obligation, a source, a state, a field or a "
            "decision the decision record does not contain, or its signature "
            "claims an authentication A12 does not establish"
        ),
        "prevents": (
            "that a summary asserts more than the decision it condenses, so the "
            "summary becomes a second, unaudited decision"
        ),
    },
    AS_REFUSED_NON_RECONSTRUCTIBLE: {
        "condition": (
            "a count has no obligation list or source manifest to derive it from, "
            "or the policy that supplies the mapping cannot be read or validated"
        ),
        "prevents": (
            "that a summary is trusted because it is internally tidy, while nothing "
            "ties its counts to a source a third party can re-read"
        ),
    },
    AS_REFUSED_SUMMARY_UNSIGNED: {
        "condition": "verification is asked for and the summary has no envelope or no signature",
        "prevents": "that an unsigned summary is read as a signed attestation",
    },
    AS_REFUSED_SUMMARY_MUTATED: {
        "condition": (
            "the summary bytes are not the envelope's payload, no signature "
            "verifies over the received payload, or the statement is not the "
            "emitted Statement v1 shape"
        ),
        "prevents": (
            "that a summary edited after signing is read as the summary that was "
            "signed, or that a re-serialised document is accepted as those bytes"
        ),
    },
}

REFUSAL_CODES = tuple(REFUSALS)

SUMMARY_FIELDS = {
    "schema",
    "topLevel",
    "replacesEvidence",
    "decision",
    "decisionDigest",
    "obligations",
    "counts",
    "unmet",
    "reconstructedFrom",
}
OBLIGATION_FIELDS = {"id", "state", "sourcePath", "sourceDigest"}
MANIFEST_FIELDS = {"path", "sha256"}
PREDICATE_FIELDS = {"summary", "signature"}
SIGNATURE_FIELDS = {"label", "authentication", "keyid", "note"}

DIGEST_LENGTH = 64


class Refusal(Exception):
    """A stable refusal code and the conclusion it prevents."""

    def __init__(self, code: str, message: str, codes: Sequence[str] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.codes = sorted(set(codes or (code,)))

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class ToolError(Exception):
    """A usage error, reported with exit status 2."""


def _fail(code: str, message: str) -> None:
    raise Refusal(code, message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == DIGEST_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


# ---------------------------------------------------------------------------
# Canonical forms.
# ---------------------------------------------------------------------------
def encode_summary(summary: Mapping[str, Any]) -> bytes:
    """The bytes a summary record is written as: sorted, indented, one newline."""
    return (
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def encode_statement(statement: Mapping[str, Any]) -> bytes:
    """A9's canonical Statement v1 bytes: compact, sorted, one trailing newline."""
    return (
        json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def decision_digest(decision: Mapping[str, Any]) -> str:
    """The digest of the decision record, which is the in-toto subject.

    It is the digest of `policy_engine.decision_bytes`, the form A20 writes. The
    committed `evidence/a20/DECISION.json` is exactly those bytes, so the digest
    is also the digest of the file a third party checks out.
    """
    return sha256_bytes(pe.decision_bytes(decision))


def summary_digest(summary: Mapping[str, Any]) -> str:
    return sha256_bytes(encode_summary(summary))


# ---------------------------------------------------------------------------
# Recomputation and source reading.
# ---------------------------------------------------------------------------
def recount(states: Sequence[str]) -> dict[str, int]:
    """Recount the four states from the obligation list itself.

    The decision's `met`/`unmet`/`unknown`/`notApplicable` arrays are never read
    here. They are the field that drifts; the obligation states are the fact.
    """
    counts = {key: 0 for key in COUNT_KEYS}
    for state in states:
        key = STATE_TO_COUNT.get(state)
        if key is None:
            _fail(
                AS_REFUSED_COUNTS_MISMATCH,
                f"an obligation records state {state!r}, which is not one of "
                f"{', '.join(pe.STATES)}; it cannot be counted",
            )
        counts[key] += 1
    return counts


def _read(source: Any, path: str) -> bytes:
    """Read one record through a caller-supplied reader or an in-memory map."""
    if callable(source):
        raw, error = source(path)
        if raw is None:
            _fail(
                AS_REFUSED_EVIDENCE_ABSENT,
                f"the source {path!r} is not readable: {error or 'absent'}",
            )
        return bytes(raw)
    if isinstance(source, Mapping):
        if path not in source:
            _fail(AS_REFUSED_EVIDENCE_ABSENT, f"the source {path!r} is not supplied")
        value = source[path]
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)
        if isinstance(value, str):
            return value.encode("utf-8")
        return pe.canonical(value).encode("utf-8")
    raise TypeError("sources is a reader callable or a mapping of path to bytes")


def _manifest_entry(manifest: Sequence[Mapping[str, Any]], path: str) -> Mapping[str, Any] | None:
    for entry in manifest:
        if entry.get("path") == path:
            return entry
    return None



# ---------------------------------------------------------------------------
# summarise
# ---------------------------------------------------------------------------
def _check_decision(decision: Any) -> None:
    if not isinstance(decision, Mapping):
        _fail(AS_REFUSED_NON_RECONSTRUCTIBLE, "the decision is not an object")
    if decision.get("decision") not in (pe.DECISION_ADMIT, pe.DECISION_DENY):
        _fail(
            AS_REFUSED_NON_RECONSTRUCTIBLE,
            f"the decision records {decision.get('decision')!r}, not "
            f"{pe.DECISION_ADMIT} or {pe.DECISION_DENY}",
        )
    obligations = decision.get("obligations")
    if not isinstance(obligations, list) or not obligations:
        _fail(
            AS_REFUSED_NON_RECONSTRUCTIBLE,
            "the decision lists no obligations, so there is no count to derive",
        )
    seen: set[str] = set()
    for entry in obligations:
        if not isinstance(entry, Mapping):
            _fail(AS_REFUSED_NON_RECONSTRUCTIBLE, "an obligation is not an object")
        identifier = entry.get("id")
        if not _is_text(identifier):
            _fail(AS_REFUSED_NON_RECONSTRUCTIBLE, "an obligation has no id")
        if identifier in seen:
            _fail(
                AS_REFUSED_DUPLICATE_OBLIGATION,
                f"the decision records obligation {identifier!r} twice; a duplicate is "
                "counted twice or silently overwrites its twin",
            )
        seen.add(identifier)
        if entry.get("state") not in pe.STATES:
            _fail(
                AS_REFUSED_COUNTS_MISMATCH,
                f"obligation {identifier!r} records state {entry.get('state')!r}, which "
                f"is not one of {', '.join(pe.STATES)}",
            )


def summarise(decision: Mapping[str, Any], sources: Any) -> dict[str, Any]:
    """Condense a decision into a summary with recounted counts and cited sources.

    ``sources`` is a reader ``path -> (bytes | None, error | None)`` (for example
    `policy_engine.filesystem_reader`) or a mapping of path to bytes.

    The obligation states are the decision's own recorded states. The counts are
    **recounted** here, and every record the decision cites -- primary and
    corroborating -- is re-read and recorded by digest. A citation whose bytes do
    not hash to the digest the decision recorded is a refusal, not a summary.
    """
    _check_decision(decision)

    obligations: list[dict[str, Any]] = []
    manifest: dict[str, str] = {}
    for entry in sorted(decision["obligations"], key=lambda item: item["id"]):
        identifier = entry["id"]
        source = entry.get("source")
        if not isinstance(source, Mapping) or not _is_text(source.get("record")):
            _fail(
                AS_REFUSED_NON_RECONSTRUCTIBLE,
                f"obligation {identifier!r} names no source record",
            )
        path = source["record"]
        raw = _read(sources, path)
        digest = sha256_bytes(raw)
        recorded = entry.get("recordSha256")
        if not _is_digest(recorded):
            _fail(
                AS_REFUSED_NO_SOURCE_DIGEST,
                f"the decision records no source digest for obligation {identifier!r}",
            )
        if digest != recorded:
            _fail(
                AS_REFUSED_SOURCE_DIGEST_MISMATCH,
                f"the bytes at {path!r} hash to {digest}, not the decision's recorded "
                f"{recorded}; the decision is stale and is not summarised",
            )
        manifest[path] = digest
        for corroborating in entry.get("corroboration") or []:
            corroborating_source = corroborating.get("source") or {}
            corroborating_path = corroborating_source.get("record")
            if not _is_text(corroborating_path):
                _fail(AS_REFUSED_NON_RECONSTRUCTIBLE, "a corroborating source has no record")
            corroborating_raw = _read(sources, corroborating_path)
            corroborating_digest = sha256_bytes(corroborating_raw)
            corroborating_recorded = corroborating.get("recordSha256")
            if not _is_digest(corroborating_recorded):
                _fail(
                    AS_REFUSED_NO_SOURCE_DIGEST,
                    f"the decision records no digest for corroborating record "
                    f"{corroborating_path!r}",
                )
            if corroborating_digest != corroborating_recorded:
                _fail(
                    AS_REFUSED_SOURCE_DIGEST_MISMATCH,
                    f"the bytes at {corroborating_path!r} hash to {corroborating_digest}, "
                    f"not the decision's recorded {corroborating_recorded}",
                )
            manifest[corroborating_path] = corroborating_digest
        obligations.append(
            {
                "id": identifier,
                "state": entry["state"],
                "sourcePath": path,
                "sourceDigest": digest,
            }
        )

    counts = recount([entry["state"] for entry in obligations])
    summary: dict[str, Any] = {
        "schema": SUMMARY_SCHEMA,
        "topLevel": TOP_LEVEL,
        "replacesEvidence": REPLACES_EVIDENCE,
        "decision": decision["decision"],
        "decisionDigest": decision_digest(decision),
        "obligations": obligations,
        "counts": counts,
        "unmet": sorted(
            entry["id"] for entry in obligations if entry["state"] == pe.STATE_UNMET
        ),
        "reconstructedFrom": [
            {"path": path, "sha256": manifest[path]} for path in sorted(manifest)
        ],
    }
    return summary


# ---------------------------------------------------------------------------
# Summary validation.
# ---------------------------------------------------------------------------
def _check_summary_shape(summary: Any) -> dict[str, Any]:
    if not isinstance(summary, Mapping):
        _fail(AS_REFUSED_NON_RECONSTRUCTIBLE, "a summary is an object")
    unknown = sorted(set(summary) - SUMMARY_FIELDS)
    if unknown:
        _fail(
            AS_REFUSED_OVERCLAIM,
            f"the summary carries field(s) the contract does not admit: {unknown}",
        )
    missing = sorted(SUMMARY_FIELDS - set(summary))
    if missing:
        _fail(
            AS_REFUSED_NON_RECONSTRUCTIBLE,
            f"the summary is missing {missing}, so its counts have no source list",
        )
    if summary.get("schema") != SUMMARY_SCHEMA:
        _fail(
            AS_REFUSED_NON_RECONSTRUCTIBLE,
            f"the summary schema is {summary.get('schema')!r}, not {SUMMARY_SCHEMA!r}",
        )
    if summary.get("topLevel") != TOP_LEVEL:
        _fail(
            AS_REFUSED_OVERCLAIM,
            f"the summary declares topLevel {summary.get('topLevel')!r}; a summary "
            "that is not labelled a summary is not read as one",
        )
    if summary.get("replacesEvidence") is not REPLACES_EVIDENCE:
        _fail(
            AS_REFUSED_SUMMARY_AS_EVIDENCE,
            "the summary declares `replacesEvidence` other than false; no summary "
            "replaces the sources it condensed",
        )
    if summary.get("decision") not in (pe.DECISION_ADMIT, pe.DECISION_DENY):
        _fail(
            AS_REFUSED_OVERCLAIM,
            f"the summary records decision {summary.get('decision')!r}, which is not "
            f"{pe.DECISION_ADMIT} or {pe.DECISION_DENY}",
        )
    if not _is_digest(summary.get("decisionDigest")):
        _fail(
            AS_REFUSED_NO_SOURCE_DIGEST,
            "the summary cites no well-formed digest for the decision record",
        )
    counts = summary.get("counts")
    if not isinstance(counts, Mapping) or set(counts) != set(COUNT_KEYS):
        _fail(
            AS_REFUSED_NON_RECONSTRUCTIBLE,
            f"the summary's counts are not the four keys {list(COUNT_KEYS)}",
        )
    for key in COUNT_KEYS:
        value = counts[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            _fail(
                AS_REFUSED_NON_RECONSTRUCTIBLE,
                f"the summary's {key} count is {value!r}, not a non-negative integer",
            )
    obligations = summary.get("obligations")
    if not isinstance(obligations, list) or not obligations:
        _fail(
            AS_REFUSED_NON_RECONSTRUCTIBLE,
            "the summary lists no obligations, so its counts cannot be derived",
        )
    seen: set[str] = set()
    for entry in obligations:
        if not isinstance(entry, Mapping):
            _fail(AS_REFUSED_NON_RECONSTRUCTIBLE, "a summary obligation is not an object")
        extra = sorted(set(entry) - OBLIGATION_FIELDS)
        if extra:
            _fail(
                AS_REFUSED_OVERCLAIM,
                f"a summary obligation carries field(s) the contract does not admit: {extra}",
            )
        if set(entry) != OBLIGATION_FIELDS:
            _fail(
                AS_REFUSED_NON_RECONSTRUCTIBLE,
                "a summary obligation does not carry exactly "
                f"{sorted(OBLIGATION_FIELDS)}",
            )
        identifier = entry.get("id")
        if not _is_text(identifier):
            _fail(AS_REFUSED_NON_RECONSTRUCTIBLE, "a summary obligation has no id")
        if identifier in seen:
            _fail(
                AS_REFUSED_DUPLICATE_OBLIGATION,
                f"the summary records obligation {identifier!r} twice; a duplicate is "
                "counted twice or silently overwrites its twin",
            )
        seen.add(identifier)
        if entry.get("state") not in pe.STATES:
            _fail(
                AS_REFUSED_COUNTS_MISMATCH,
                f"summary obligation {identifier!r} records state {entry.get('state')!r}, "
                f"which is not one of {', '.join(pe.STATES)}",
            )
        if not _is_text(entry.get("sourcePath")):
            _fail(
                AS_REFUSED_NO_SOURCE_DIGEST,
                f"summary obligation {identifier!r} names no source path",
            )
        if not _is_digest(entry.get("sourceDigest")):
            _fail(
                AS_REFUSED_NO_SOURCE_DIGEST,
                f"summary obligation {identifier!r} carries no well-formed source digest; "
                "a path without a digest identifies no bytes",
            )
    unmet = summary.get("unmet")
    if not isinstance(unmet, list) or not all(isinstance(item, str) for item in unmet):
        _fail(
            AS_REFUSED_COUNTS_MISMATCH,
            "the summary's unmet set is not a list of obligation ids",
        )
    manifest = summary.get("reconstructedFrom")
    if not isinstance(manifest, list) or not manifest:
        _fail(
            AS_REFUSED_NON_RECONSTRUCTIBLE,
            "the summary cites no source manifest, so a count has no source list to "
            "be derived from",
        )
    seen_paths: set[str] = set()
    for entry in manifest:
        if not isinstance(entry, Mapping) or set(entry) != MANIFEST_FIELDS:
            _fail(
                AS_REFUSED_NON_RECONSTRUCTIBLE,
                f"a source manifest entry is not exactly {sorted(MANIFEST_FIELDS)}",
            )
        if not _is_text(entry.get("path")):
            _fail(AS_REFUSED_NON_RECONSTRUCTIBLE, "a source manifest entry has no path")
        if not _is_digest(entry.get("sha256")):
            _fail(
                AS_REFUSED_NO_SOURCE_DIGEST,
                f"source manifest entry {entry.get('path')!r} carries no digest",
            )
        if entry["path"] in seen_paths:
            _fail(
                AS_REFUSED_NON_RECONSTRUCTIBLE,
                f"the source manifest records {entry['path']!r} twice",
            )
        seen_paths.add(entry["path"])
    return dict(summary)


# ---------------------------------------------------------------------------
# reconstruct
# ---------------------------------------------------------------------------
def _load_record(repo: Path, relative: str, what: str) -> tuple[bytes, Any]:
    reader = pe.filesystem_reader(repo)
    raw, error = reader(relative)
    if raw is None:
        _fail(
            AS_REFUSED_EVIDENCE_ABSENT,
            f"the {what} {relative!r} is not present: {error or 'absent'}",
        )
    try:
        parsed = pe.parse_json(raw)
    except (UnicodeDecodeError, ValueError) as parse_error:
        _fail(
            AS_REFUSED_EVIDENCE_ABSENT,
            f"the {what} {relative!r} is not strict JSON: {parse_error}",
        )
    return raw, parsed


def reconstruct(
    summary: Mapping[str, Any],
    repo: Path,
    *,
    decision_path: str = DECISION_PATH,
    policy_path: str = POLICY_PATH,
) -> dict[str, Any]:
    """Recompute a summary from its cited sources and refuse any disagreement.

    The obligation mapping is the policy's, not a copy of it: each obligation is
    evaluated with `policy_engine._evaluate_obligation`, the same function A20's
    `evaluate` uses, over the bytes whose digests were just checked.
    """
    repo = Path(repo)
    summary = _check_summary_shape(summary)
    states = [entry["state"] for entry in summary["obligations"]]
    recounted = recount(states)
    if recounted != dict(summary["counts"]):
        _fail(
            AS_REFUSED_COUNTS_MISMATCH,
            f"the summary's counts are {dict(summary['counts'])}, but its obligation "
            f"list recounts to {recounted}",
        )
    derived_unmet = sorted(
        entry["id"] for entry in summary["obligations"] if entry["state"] == pe.STATE_UNMET
    )
    if derived_unmet != list(summary["unmet"]):
        _fail(
            AS_REFUSED_COUNTS_MISMATCH,
            f"the summary's unmet set is {summary['unmet']}, but its obligations record "
            f"{derived_unmet}",
        )

    decision_raw, decision = _load_record(repo, decision_path, "decision record")
    if not isinstance(decision, Mapping):
        _fail(AS_REFUSED_NON_RECONSTRUCTIBLE, "the decision record is not an object")
    if decision_raw != pe.decision_bytes(decision):
        _fail(
            AS_REFUSED_SOURCE_DIGEST_MISMATCH,
            f"the decision record {decision_path!r} is not in the canonical form A20 "
            "writes; its file digest is not the digest of the decision it parses to",
        )
    live_decision_digest = sha256_bytes(decision_raw)
    if live_decision_digest != summary["decisionDigest"]:
        _fail(
            AS_REFUSED_SOURCE_DIGEST_MISMATCH,
            f"the decision record hashes to {live_decision_digest}, not the summary's "
            f"cited {summary['decisionDigest']}",
        )

    if summary["decision"] != decision.get("decision"):
        if (
            summary["decision"] == pe.DECISION_ADMIT
            and decision.get("decision") == pe.DECISION_DENY
        ):
            _fail(
                AS_REFUSED_DECISION_UPGRADED,
                "the summary records ADMIT where the decision records DENY",
            )
        _fail(
            AS_REFUSED_OVERCLAIM,
            f"the summary records decision {summary['decision']!r}, but the decision "
            f"records {decision.get('decision')!r}",
        )

    policy_raw, policy = _load_record(repo, policy_path, "policy record")
    if not isinstance(policy, Mapping):
        _fail(AS_REFUSED_NON_RECONSTRUCTIBLE, "the policy record is not an object")
    if decision.get("policyDigest") != pe.policy_digest(policy):
        _fail(
            AS_REFUSED_SOURCE_DIGEST_MISMATCH,
            f"the policy at {policy_path!r} hashes to {pe.policy_digest(policy)}, not the "
            f"decision's cited {decision.get('policyDigest')}",
        )
    if policy.get("digest") != pe.policy_digest(policy):
        _fail(
            AS_REFUSED_SOURCE_DIGEST_MISMATCH,
            "the policy's recorded digest does not match its bytes",
        )
    policy_problems = pe.validate_policy(policy)
    if policy_problems:
        _fail(
            AS_REFUSED_NON_RECONSTRUCTIBLE,
            f"the policy that supplies the mapping is not valid: {policy_problems}",
        )

    policy_obligations = sorted(policy["obligations"], key=lambda item: item["id"])
    policy_ids = [item["id"] for item in policy_obligations]
    summary_ids = [entry["id"] for entry in summary["obligations"]]
    missing = sorted(set(policy_ids) - set(summary_ids))
    if missing:
        _fail(
            AS_REFUSED_COVERAGE_GAP,
            f"obligation(s) {missing} are declared by the policy but absent from the "
            "summary; the remaining obligations are not the decision's coverage",
        )
    extra = sorted(set(summary_ids) - set(policy_ids))
    if extra:
        _fail(
            AS_REFUSED_OVERCLAIM,
            f"the summary records obligation(s) {extra} that the policy does not "
            "declare",
        )

    decision_entries = {
        entry.get("id"): entry
        for entry in decision.get("obligations") or []
        if isinstance(entry, Mapping)
    }
    manifest = summary["reconstructedFrom"]
    cited_paths: set[str] = set()
    per_obligation: list[dict[str, Any]] = []
    verified_bytes: dict[str, bytes] = {}

    for obligation in policy_obligations:
        identifier = obligation["id"]
        entry = next(item for item in summary["obligations"] if item["id"] == identifier)
        decision_entry = decision_entries.get(identifier)
        if not isinstance(decision_entry, Mapping):
            _fail(
                AS_REFUSED_NON_RECONSTRUCTIBLE,
                f"the decision does not record obligation {identifier!r}, so the "
                "summary cannot be a summary of it",
            )
        source_path = (decision_entry.get("source") or {}).get("record")
        if entry["sourcePath"] != source_path:
            _fail(
                AS_REFUSED_OVERCLAIM,
                f"summary obligation {identifier!r} cites {entry['sourcePath']!r}, but "
                f"the decision cites {source_path!r}",
            )
        cited_paths.add(source_path)
        raw = _read(pe.filesystem_reader(repo), source_path)
        live_digest = sha256_bytes(raw)
        verified_bytes[source_path] = raw
        recorded_digest = decision_entry.get("recordSha256")
        if live_digest != recorded_digest:
            _fail(
                AS_REFUSED_SOURCE_DIGEST_MISMATCH,
                f"{source_path!r} hashes to {live_digest}, not the decision's recorded "
                f"{recorded_digest}",
            )
        if entry["sourceDigest"] != live_digest:
            _fail(
                AS_REFUSED_SOURCE_DIGEST_MISMATCH,
                f"summary obligation {identifier!r} cites {entry['sourceDigest']}, but "
                f"{source_path!r} hashes to {live_digest}",
            )
        manifest_entry = _manifest_entry(manifest, source_path)
        if manifest_entry is None:
            _fail(
                AS_REFUSED_NON_RECONSTRUCTIBLE,
                f"the source manifest omits {source_path!r}, so the count for "
                f"{identifier!r} has no cited source",
            )
        if manifest_entry["sha256"] != live_digest:
            _fail(
                AS_REFUSED_SOURCE_DIGEST_MISMATCH,
                f"the source manifest cites {manifest_entry['sha256']} for "
                f"{source_path!r}, but its bytes hash to {live_digest}",
            )

        for corroborating in obligation.get("corroboration") or []:
            # The policy spells a source at the top level; the decision nests it
            # under `source`. The two forms come from the same declaration.
            corroborating_path = corroborating.get("record") or (
                corroborating.get("source") or {}
            ).get("record")
            if not _is_text(corroborating_path):
                _fail(
                    AS_REFUSED_NON_RECONSTRUCTIBLE,
                    f"the policy gives obligation {identifier!r} a corroborating source "
                    "with no record",
                )
            cited_paths.add(corroborating_path)
            corroborating_raw = _read(pe.filesystem_reader(repo), corroborating_path)
            corroborating_digest = sha256_bytes(corroborating_raw)
            verified_bytes[corroborating_path] = corroborating_raw
            decision_corroboration = None
            for candidate in decision_entry.get("corroboration") or []:
                if (candidate.get("source") or {}).get("record") == corroborating_path:
                    decision_corroboration = candidate
                    break
            if decision_corroboration is None:
                _fail(
                    AS_REFUSED_NON_RECONSTRUCTIBLE,
                    f"the decision records no corroborating entry for "
                    f"{corroborating_path!r}",
                )
            if corroborating_digest != decision_corroboration.get("recordSha256"):
                _fail(
                    AS_REFUSED_SOURCE_DIGEST_MISMATCH,
                    f"{corroborating_path!r} hashes to {corroborating_digest}, not the "
                    f"decision's recorded {decision_corroboration.get('recordSha256')}",
                )
            manifest_entry = _manifest_entry(manifest, corroborating_path)
            if manifest_entry is None:
                _fail(
                    AS_REFUSED_NON_RECONSTRUCTIBLE,
                    f"the source manifest omits the corroborating record "
                    f"{corroborating_path!r}",
                )
            if manifest_entry["sha256"] != corroborating_digest:
                _fail(
                    AS_REFUSED_SOURCE_DIGEST_MISMATCH,
                    f"the source manifest cites {manifest_entry['sha256']} for "
                    f"{corroborating_path!r}, but its bytes hash to {corroborating_digest}",
                )

        def reader(relative: str, _bytes: Mapping[str, bytes] = verified_bytes):
            if relative not in _bytes:
                return None, f"{relative!r} is absent"
            return _bytes[relative], None

        cache = pe._RecordCache(reader)
        recomputed = pe._evaluate_obligation(obligation, cache, repo)
        recomputed_state = recomputed["state"]
        if recomputed_state != decision_entry["state"]:
            _fail(
                AS_REFUSED_COUNTS_MISMATCH,
                f"obligation {identifier!r} is recorded {decision_entry['state']} by the "
                f"decision, but its cited sources recompute to {recomputed_state}",
            )
        if entry["state"] != decision_entry["state"]:
            _fail(
                AS_REFUSED_OVERCLAIM,
                f"summary obligation {identifier!r} records {entry['state']}, but the "
                f"decision records {decision_entry['state']}",
            )
        if entry["state"] != recomputed_state:
            _fail(
                AS_REFUSED_COUNTS_MISMATCH,
                f"summary obligation {identifier!r} records {entry['state']}, but its "
                f"cited sources recompute to {recomputed_state}",
            )
        per_obligation.append(
            {
                "id": identifier,
                "summaryState": entry["state"],
                "decisionState": decision_entry["state"],
                "recomputedState": recomputed_state,
                "sourcePath": source_path,
                "sourceDigest": live_digest,
                "matches": entry["state"] == decision_entry["state"] == recomputed_state,
            }
        )

    manifest_paths = {entry["path"] for entry in manifest}
    uncited = sorted(manifest_paths - cited_paths)
    if uncited:
        _fail(
            AS_REFUSED_OVERCLAIM,
            f"the source manifest cites record(s) {uncited} that neither the decision "
            "nor its corroboration names",
        )
    uncited_citations = sorted(cited_paths - manifest_paths)
    if uncited_citations:
        _fail(
            AS_REFUSED_NON_RECONSTRUCTIBLE,
            f"the decision cites record(s) {uncited_citations} that the source manifest "
            "does not cite",
        )

    recomputed_counts = recount(
        [entry["recomputedState"] for entry in per_obligation]
    )
    if recomputed_counts != dict(summary["counts"]):
        _fail(
            AS_REFUSED_COUNTS_MISMATCH,
            f"the summary's counts are {dict(summary['counts'])}, but its cited sources "
            f"recompute to {recomputed_counts}",
        )
    decision_totals = {
        "met": len(decision.get("met") or []),
        "unmet": len(decision.get("unmet") or []),
        "unknown": len(decision.get("unknown") or []),
        "notApplicable": len(decision.get("notApplicable") or []),
    }
    if dict(summary["counts"]) != decision_totals:
        _fail(
            AS_REFUSED_COUNTS_MISMATCH,
            f"the summary's counts are {dict(summary['counts'])}, but the decision's own "
            f"totals are {decision_totals}",
        )
    if list(summary["unmet"]) != list(decision.get("unmet") or []):
        _fail(
            AS_REFUSED_COUNTS_MISMATCH,
            f"the summary's unmet set is {summary['unmet']}, but the decision records "
            f"{decision.get('unmet')}",
        )

    recomputed_unmet = sorted(
        entry["id"] for entry in per_obligation if entry["recomputedState"] == pe.STATE_UNMET
    )
    return {
        "schema": RECONSTRUCTION_SCHEMA,
        "summaryDigest": summary_digest(summary),
        "decision": decision.get("decision"),
        "decisionDigest": live_decision_digest,
        "policyDigest": policy.get("digest"),
        "sources": [
            {"path": entry["path"], "sha256": entry["sha256"]}
            for entry in sorted(manifest, key=lambda item: item["path"])
        ],
        "obligations": per_obligation,
        "counts": recomputed_counts,
        "summaryCounts": dict(summary["counts"]),
        "decisionCounts": decision_totals,
        "unmet": recomputed_unmet,
        "equal": (
            recomputed_counts == dict(summary["counts"])
            and recomputed_counts == decision_totals
            and all(entry["matches"] for entry in per_obligation)
        ),
    }


# ---------------------------------------------------------------------------
# Statement and envelope (A9 shape, A10 framing, A12 label).
# ---------------------------------------------------------------------------
def statement_for(
    summary: Mapping[str, Any], *, repo: Path = REPO_ROOT, decision_path: str = DECISION_PATH
) -> dict[str, Any]:
    """Wrap a summary in a Statement v1 whose subject is the decision record."""
    subject = intoto.subject_for(decision_path, repo_root=Path(repo))
    if subject["digest"]["sha256"] != summary.get("decisionDigest"):
        _fail(
            AS_REFUSED_SOURCE_DIGEST_MISMATCH,
            f"the decision record hashes to {subject['digest']['sha256']}, not the "
            f"summary's cited {summary.get('decisionDigest')}",
        )
    return {
        "_type": STATEMENT_TYPE,
        "subject": [subject],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "summary": dict(summary),
            "signature": {
                "label": SIGNATURE_LABEL,
                "authentication": AUTHENTICATION,
                "keyid": dsse.test_only_keyid(),
                "note": (
                    "A12: self-issued. The key is A10's test-only HMAC-SHA256 key "
                    "derived from a fixed public seed. The signature proves the "
                    "summary's bytes are unchanged since signing; it proves nothing "
                    "about who issued it or whether the decision is correct."
                ),
            },
        },
    }


def sign_summary(
    summary: Mapping[str, Any], *, repo: Path = REPO_ROOT, decision_path: str = DECISION_PATH
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return the statement and its DSSE envelope over the exact statement bytes."""
    statement = statement_for(summary, repo=repo, decision_path=decision_path)
    payload = encode_statement(statement)
    envelope = dsse.envelope(
        dsse.IN_TOTO_PAYLOAD_TYPE, payload, dsse.test_only_signer()
    )
    return statement, envelope


def _check_statement(statement: Any, summary: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(statement, Mapping):
        _fail(AS_REFUSED_SUMMARY_MUTATED, "the payload is not a JSON object")
    if set(statement) != {"_type", "subject", "predicateType", "predicate"}:
        _fail(
            AS_REFUSED_SUMMARY_MUTATED,
            f"the statement carries field(s) this tool does not emit: "
            f"{sorted(map(str, statement))}",
        )
    if statement.get("_type") != STATEMENT_TYPE:
        _fail(
            AS_REFUSED_SUMMARY_MUTATED,
            f"the statement type is {statement.get('_type')!r}, not {STATEMENT_TYPE!r}",
        )
    if statement.get("predicateType") != PREDICATE_TYPE:
        _fail(
            AS_REFUSED_SUMMARY_MUTATED,
            f"the predicate type is {statement.get('predicateType')!r}, not "
            f"{PREDICATE_TYPE!r}",
        )
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        _fail(
            AS_REFUSED_SUMMARY_MUTATED,
            "the statement must name exactly the decision record as its subject",
        )
    subject = subjects[0]
    if not isinstance(subject, Mapping) or set(subject) != {"name", "digest"}:
        _fail(AS_REFUSED_SUMMARY_MUTATED, "the subject is not an in-toto subject")
    digest = subject.get("digest")
    if not isinstance(digest, Mapping) or set(digest) != {"sha256"}:
        _fail(AS_REFUSED_SUMMARY_MUTATED, "the subject digest is not a sha256 digest")
    if digest["sha256"] != summary.get("decisionDigest"):
        _fail(
            AS_REFUSED_SUMMARY_MUTATED,
            "the statement's subject is not the decision record the summary cites",
        )
    predicate = statement.get("predicate")
    if not isinstance(predicate, Mapping) or set(predicate) != PREDICATE_FIELDS:
        _fail(
            AS_REFUSED_SUMMARY_MUTATED,
            f"the predicate is not exactly {sorted(PREDICATE_FIELDS)}",
        )
    signature = predicate.get("signature")
    if not isinstance(signature, Mapping) or set(signature) != SIGNATURE_FIELDS:
        _fail(
            AS_REFUSED_SUMMARY_MUTATED,
            f"the signature block is not exactly {sorted(SIGNATURE_FIELDS)}",
        )
    if signature.get("label") != SIGNATURE_LABEL:
        _fail(
            AS_REFUSED_OVERCLAIM,
            f"the signature label is {signature.get('label')!r}; only "
            f"{SIGNATURE_LABEL!r} is established by this tool",
        )
    if signature.get("authentication") != AUTHENTICATION:
        _fail(
            AS_REFUSED_OVERCLAIM,
            f"the statement claims authentication {signature.get('authentication')!r}; "
            "A12 records the signature SELF_ISSUED and no authentication is established",
        )
    if predicate.get("summary") != summary:
        _fail(
            AS_REFUSED_SUMMARY_MUTATED,
            "the statement's predicate does not carry the summary bytes it is checked "
            "against",
        )
    return dict(statement)


def verify_summary(
    summary_bytes: bytes,
    envelope_bytes: bytes | None,
    repo: Path = REPO_ROOT,
    *,
    decision_path: str = DECISION_PATH,
    policy_path: str = POLICY_PATH,
) -> dict[str, Any]:
    """Verify the envelope, then reconstruct the summary from its sources."""
    repo = Path(repo)
    if envelope_bytes is None:
        _fail(AS_REFUSED_SUMMARY_UNSIGNED, "no envelope accompanies the summary")
    try:
        received = dsse.verify_pae(
            envelope_bytes,
            dsse.test_only_verifier(),
            expected_payload_type=dsse.IN_TOTO_PAYLOAD_TYPE,
            require_statement=False,
        )
    except dsse.Refusal as refusal:
        if refusal.code == dsse.DS_REFUSED_SIGNATURES_ABSENT:
            _fail(AS_REFUSED_SUMMARY_UNSIGNED, f"the envelope has no signature ({refusal})")
        _fail(AS_REFUSED_SUMMARY_MUTATED, f"the envelope is not verifiable ({refusal})")
    try:
        statement = pe.parse_json(received["payload"])
    except (UnicodeDecodeError, ValueError) as parse_error:
        _fail(
            AS_REFUSED_SUMMARY_MUTATED,
            f"the verified payload is not strict JSON: {parse_error}",
        )
    if encode_statement(statement) != received["payload"]:
        _fail(
            AS_REFUSED_SUMMARY_MUTATED,
            "the verified payload is not the canonical Statement v1 bytes this tool emits",
        )
    try:
        summary = pe.parse_json(summary_bytes)
    except (UnicodeDecodeError, ValueError) as parse_error:
        _fail(
            AS_REFUSED_SUMMARY_MUTATED,
            f"the summary file is not strict JSON: {parse_error}",
        )
    summary = _check_summary_shape(summary)
    if encode_summary(summary) != summary_bytes:
        _fail(
            AS_REFUSED_SUMMARY_MUTATED,
            "the summary file is not the canonical summary record this tool writes; "
            "a re-spaced or re-serialised document is not the document that was signed",
        )
    _check_statement(statement, summary)
    try:
        intoto.verify_subject(statement["subject"][0], repo_root=repo)
    except intoto.Refusal as refusal:
        if refusal.code == intoto.IT_REFUSED_SUBJECT_ABSENT:
            _fail(AS_REFUSED_EVIDENCE_ABSENT, f"the decision record is absent ({refusal})")
        _fail(AS_REFUSED_SOURCE_DIGEST_MISMATCH, f"the decision record moved ({refusal})")
    report = reconstruct(
        summary, repo, decision_path=decision_path, policy_path=policy_path
    )
    return {
        "code": CODE_OK,
        "summaryDigest": summary_digest(summary),
        "decision": report["decision"],
        "decisionDigest": report["decisionDigest"],
        "policyDigest": report["policyDigest"],
        "keyid": received["keyid"],
        "signatureLabel": SIGNATURE_LABEL,
        "counts": report["counts"],
        "equal": report["equal"],
    }


# ---------------------------------------------------------------------------
# The consumer contract: a summary is never the evidence.
# ---------------------------------------------------------------------------
def consume(
    summary: Mapping[str, Any],
    cited_paths: Sequence[str],
    *,
    summary_path: str | None = None,
) -> list[str]:
    """The source paths a consumer may stand on, or a refusal.

    A consumer that cites the summary in place of the sources is refused. If it
    cites the sources, every cited source is returned; a consumer that cites only
    some of them is refused, because the remaining counts have no evidence in its
    citation list.
    """
    if summary.get("replacesEvidence") is not REPLACES_EVIDENCE:
        _fail(
            AS_REFUSED_SUMMARY_AS_EVIDENCE,
            "the summary declares that it replaces evidence",
        )
    cited = list(cited_paths)
    if summary_path is not None and summary_path in cited:
        _fail(
            AS_REFUSED_SUMMARY_AS_EVIDENCE,
            f"the consumer cites {summary_path!r}, the summary, as its evidence",
        )
    sources = {
        entry["sourcePath"] for entry in summary.get("obligations") or []
    } | {
        entry["path"] for entry in summary.get("reconstructedFrom") or []
    }
    uncovered = sorted(sources - set(cited))
    if uncovered:
        _fail(
            AS_REFUSED_SUMMARY_AS_EVIDENCE,
            f"the consumer cites no evidence for {uncovered}; a summary is not a "
            "substitute for the sources it condensed",
        )
    return sorted(sources & set(cited))


# ---------------------------------------------------------------------------
# Controls (control-only fixtures; never part of the real summary).
# ---------------------------------------------------------------------------
CONTROL_RECORDS = {
    "control/met.json": {"state": "CLOSED"},
    "control/unmet.json": {"state": "OPEN"},
}


def _write_control_record(root: Path, relative: str, value: Any) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pe.canonical(value).encode("utf-8"))


def _control_fixture() -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """A synthetic decision, policy and summary in a temporary repository.

    The decision is produced by the real A20 evaluator over the synthetic records,
    so its obligation entries, digests and totals are the real shapes. It is a
    control: it says nothing about any tracked record.
    """
    import tempfile

    root = Path(tempfile.mkdtemp(prefix="a21-control-"))
    for relative, value in CONTROL_RECORDS.items():
        _write_control_record(root, relative, value)
    tool = root / pe.TOOL_PATH
    tool.parent.mkdir(parents=True, exist_ok=True)
    tool.write_bytes(b"# control-only stand-in for the declared producing tool\n")

    obligations = [
        {
            "id": "C01.met",
            "description": "control obligation C01.met",
            "required": True,
            "source": {
                "tool": pe.TOOL_PATH,
                "record": "control/met.json",
                "locator": "/state",
            },
            "predicate": {"op": "eq", "path": "", "value": "CLOSED"},
        },
        {
            "id": "C02.unmet",
            "description": "control obligation C02.unmet",
            "required": True,
            "source": {
                "tool": pe.TOOL_PATH,
                "record": "control/unmet.json",
                "locator": "/state",
            },
            "predicate": {"op": "eq", "path": "", "value": "CLOSED"},
        },
    ]
    policy = pe.control_policy(obligations)
    policy_path = root / POLICY_PATH
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_bytes(pe.canonical(policy).encode("utf-8"))
    pin = pe.control_pin(policy, policyPath=POLICY_PATH)
    candidate, problems = pe.resolve_candidate(root, commit=pe.CONTROL_COMMIT)
    if problems:
        # The control candidate's producer record is the control's own; a missing
        # record is a decision problem, not a fixture failure.
        candidate = pe.control_candidate()
    decision = pe.evaluate(
        policy,
        pin,
        candidate,
        reader=pe.filesystem_reader(root),
        root=root,
        policy_path=POLICY_PATH,
        runs=1,
    )
    (root / DECISION_PATH).write_bytes(pe.decision_bytes(decision))
    summary = summarise(decision, pe.filesystem_reader(root))
    return root, decision, summary


def _copy(summary: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(summary))


def _codes(action: Callable[[], Any]) -> list[str]:
    try:
        action()
    except Refusal as refusal:
        return list(refusal.codes)
    return []


def controls() -> list[dict[str, Any]]:
    """One control per refusal code. Each is synthetic and labelled control-only."""
    fixtures: list[dict[str, Any]] = []

    def add(
        identifier: str,
        code: str,
        description: str,
        observed: Sequence[str],
        detail: Any = None,
    ) -> None:
        fixtures.append(
            {
                "id": identifier,
                "kind": "control-only",
                "code": code,
                "description": description,
                "observed": {"codes": sorted(set(observed))},
                "established": code in observed,
                "detail": detail,
            }
        )

    root, decision, summary = _control_fixture()

    # AS_REFUSED_SUMMARY_AS_EVIDENCE: a consumer cites the summary as its evidence.
    add(
        "consumer-cites-summary",
        AS_REFUSED_SUMMARY_AS_EVIDENCE,
        "a consumer cites the summary in place of the sources it condensed",
        _codes(lambda: consume(
            summary,
            ["evidence/a21/SUMMARY.json"],
            summary_path="evidence/a21/SUMMARY.json",
        )),
        {"cited": ["evidence/a21/SUMMARY.json"]},
    )

    # AS_REFUSED_COUNTS_MISMATCH: counts disagree with the obligation list.
    bad_counts = _copy(summary)
    bad_counts["counts"] = {"met": 2, "unmet": 0, "unknown": 0, "notApplicable": 0}
    add(
        "counts-disagree-with-list",
        AS_REFUSED_COUNTS_MISMATCH,
        "the summary's counts are copied rather than recounted from its obligations",
        _codes(lambda: reconstruct(bad_counts, root)),
        {"counts": bad_counts["counts"]},
    )

    # AS_REFUSED_EVIDENCE_ABSENT: a cited source is removed.
    absent_root, _absent_decision, absent_summary = _control_fixture()
    (absent_root / "control/unmet.json").unlink()
    add(
        "source-removed",
        AS_REFUSED_EVIDENCE_ABSENT,
        "a source the summary cites is removed from the tree",
        _codes(lambda: reconstruct(absent_summary, absent_root)),
        {"removed": "control/unmet.json"},
    )

    # AS_REFUSED_SOURCE_DIGEST_MISMATCH: a source's bytes change.
    changed_root, _changed_decision, changed_summary = _control_fixture()
    (changed_root / "control/met.json").write_bytes(b'{"state":"OPEN"}')
    add(
        "source-bytes-changed",
        AS_REFUSED_SOURCE_DIGEST_MISMATCH,
        "a source's bytes change after the decision and the summary",
        _codes(lambda: reconstruct(changed_summary, changed_root)),
        {"changed": "control/met.json"},
    )

    # AS_REFUSED_NO_SOURCE_DIGEST: an obligation carries no digest.
    no_digest = _copy(summary)
    no_digest["obligations"][0]["sourceDigest"] = None
    add(
        "obligation-without-digest",
        AS_REFUSED_NO_SOURCE_DIGEST,
        "an obligation names a source path with no digest",
        _codes(lambda: reconstruct(no_digest, root)),
        {"obligation": no_digest["obligations"][0]["id"]},
    )

    # AS_REFUSED_COVERAGE_GAP: a policy obligation is absent from the summary.
    gap = _copy(summary)
    gap["obligations"] = [
        entry for entry in gap["obligations"] if entry["id"] != "C02.unmet"
    ]
    gap["counts"] = {"met": 1, "unmet": 0, "unknown": 0, "notApplicable": 0}
    gap["unmet"] = []
    add(
        "obligation-removed",
        AS_REFUSED_COVERAGE_GAP,
        "an obligation declared by the policy is removed from the summary",
        _codes(lambda: reconstruct(gap, root)),
        {"removed": "C02.unmet"},
    )

    # AS_REFUSED_DUPLICATE_OBLIGATION: one obligation is recorded twice.
    duplicated = _copy(summary)
    duplicated["obligations"].append(_copy(duplicated["obligations"][0]))
    duplicated["counts"] = {"met": 2, "unmet": 1, "unknown": 0, "notApplicable": 0}
    add(
        "obligation-duplicated",
        AS_REFUSED_DUPLICATE_OBLIGATION,
        "the summary records one obligation twice",
        _codes(lambda: reconstruct(duplicated, root)),
        {"obligation": duplicated["obligations"][0]["id"]},
    )

    # AS_REFUSED_DECISION_UPGRADED: DENY published as ADMIT.
    upgraded = _copy(summary)
    upgraded["decision"] = pe.DECISION_ADMIT
    add(
        "decision-upgraded",
        AS_REFUSED_DECISION_UPGRADED,
        "the summary records ADMIT where the decision records DENY",
        _codes(lambda: reconstruct(upgraded, root)),
        {"summary": "ADMIT", "decision": "DENY"},
    )

    # AS_REFUSED_OVERCLAIM: an obligation the policy does not declare.
    overclaim = _copy(summary)
    overclaim["obligations"].append(
        {
            "id": "C03.extra",
            "state": pe.STATE_MET,
            "sourcePath": "control/met.json",
            "sourceDigest": summary["obligations"][0]["sourceDigest"],
        }
    )
    overclaim["counts"] = {"met": 2, "unmet": 1, "unknown": 0, "notApplicable": 0}
    add(
        "obligation-added",
        AS_REFUSED_OVERCLAIM,
        "the summary adds an obligation the policy does not declare",
        _codes(lambda: reconstruct(overclaim, root)),
        {"added": "C03.extra"},
    )

    # AS_REFUSED_NON_RECONSTRUCTIBLE: no source manifest.
    empty_manifest = _copy(summary)
    empty_manifest["reconstructedFrom"] = []
    add(
        "no-source-manifest",
        AS_REFUSED_NON_RECONSTRUCTIBLE,
        "a count is published with no source list to derive it from",
        _codes(lambda: reconstruct(empty_manifest, root)),
        {"reconstructedFrom": []},
    )

    # AS_REFUSED_SUMMARY_UNSIGNED: a summary without a signature.
    _statement, signed = sign_summary(summary, repo=root)
    unsigned = _copy(signed)
    unsigned["signatures"] = []
    summary_bytes = encode_summary(summary)
    add(
        "summary-unsigned",
        AS_REFUSED_SUMMARY_UNSIGNED,
        "verification is asked for and the envelope carries no signature",
        _codes(lambda: verify_summary(
            summary_bytes, dsse.encode_envelope(unsigned), root
        )),
        {"signatures": []},
    )

    # AS_REFUSED_SUMMARY_MUTATED: the signed summary is edited afterwards.
    mutated = encode_summary({**_copy(summary), "unmet": []})
    add(
        "signed-summary-mutated",
        AS_REFUSED_SUMMARY_MUTATED,
        "the summary's bytes are changed after the envelope was signed",
        _codes(lambda: verify_summary(
            mutated, dsse.encode_envelope(signed), root
        )),
        {"mutation": "unmet removed after signing"},
    )

    return fixtures


def controls_document() -> dict[str, Any]:
    fixtures = controls()
    by_code = {fixture["code"]: fixture for fixture in fixtures if fixture["code"]}
    missing = sorted(set(REFUSAL_CODES) - set(by_code))
    unestablished = [fixture["id"] for fixture in fixtures if not fixture["established"]]
    if missing:
        raise SystemExit(f"a21: no control for refusal code(s) {missing}")
    if unestablished:
        raise SystemExit(f"a21: control(s) did not establish their code: {unestablished}")
    return {
        "schema": CONTROLS_SCHEMA,
        "item": "A21",
        "summary": "evidence/a21/SUMMARY.json",
        "controls": fixtures,
        "totals": {
            "controls": len(fixtures),
            "refusalCodes": len(REFUSAL_CODES),
            "coveredCodes": len(by_code),
            "positives": 0,
        },
    }


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------
class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        print(f"code={CODE_USAGE} detail={message}")
        raise SystemExit(EXIT_USAGE)


def _load_json(path: Path, what: str) -> Any:
    if not path.is_file():
        raise ToolError(f"the {what} {str(path)!r} is absent")
    try:
        return pe.parse_json(path.read_bytes())
    except (UnicodeDecodeError, ValueError) as error:
        raise ToolError(f"the {what} {str(path)!r} is not strict JSON: {error}") from error


def _command_summarise(arguments: argparse.Namespace) -> int:
    decision = _load_json(Path(arguments.decision), "decision record")
    summary = summarise(decision, pe.filesystem_reader(Path(arguments.root)))
    if arguments.out:
        Path(arguments.out).write_bytes(encode_summary(summary))
    counts = summary["counts"]
    print(
        f"summary: code={CODE_OK} decision={summary['decision']} "
        f"obligations={len(summary['obligations'])} "
        f"met={counts['met']} unmet={counts['unmet']} unknown={counts['unknown']} "
        f"notApplicable={counts['notApplicable']} "
        f"sources={len(summary['reconstructedFrom'])} "
        f"decisionDigest={summary['decisionDigest'][:16]} "
        f"summaryDigest={summary_digest(summary)[:16]} "
        f"replacesEvidence={str(summary['replacesEvidence']).lower()}"
    )
    print(f"summary: unmet = {','.join(summary['unmet']) if summary['unmet'] else 'NONE'}")
    return EXIT_OK


def _command_reconstruct(arguments: argparse.Namespace) -> int:
    summary = _load_json(Path(arguments.summary), "summary")
    report = reconstruct(
        summary,
        Path(arguments.root),
        decision_path=arguments.decision,
        policy_path=arguments.policy,
    )
    if arguments.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return EXIT_OK if report["equal"] else EXIT_REFUSED
    counts = report["counts"]
    print(
        f"reconstruct: code={CODE_OK} decision={report['decision']} "
        f"obligations={len(report['obligations'])} "
        f"met={counts['met']} unmet={counts['unmet']} unknown={counts['unknown']} "
        f"notApplicable={counts['notApplicable']} equal={str(report['equal']).lower()} "
        f"summaryDigest={report['summaryDigest'][:16]}"
    )
    print(
        f"reconstruct: unmet = {','.join(report['unmet']) if report['unmet'] else 'NONE'}"
    )
    return EXIT_OK if report["equal"] else EXIT_REFUSED


def _command_verify(arguments: argparse.Namespace) -> int:
    summary_bytes = Path(arguments.summary).read_bytes() if Path(arguments.summary).is_file() else None
    if summary_bytes is None:
        raise ToolError(f"the summary {arguments.summary!r} is absent")
    envelope_path = Path(arguments.envelope)
    envelope_bytes = envelope_path.read_bytes() if envelope_path.is_file() else None
    report = verify_summary(
        summary_bytes,
        envelope_bytes,
        Path(arguments.root),
        decision_path=arguments.decision,
        policy_path=arguments.policy,
    )
    if arguments.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return EXIT_OK
    counts = report["counts"]
    print(
        f"verify: code={CODE_OK} label={report['signatureLabel']} "
        f"keyid={report['keyid']} decision={report['decision']} "
        f"met={counts['met']} unmet={counts['unmet']} unknown={counts['unknown']} "
        f"notApplicable={counts['notApplicable']} equal={str(report['equal']).lower()} "
        f"summaryDigest={report['summaryDigest'][:16]} "
        f"decisionDigest={report['decisionDigest'][:16]}"
    )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = _Parser(prog="verification_summary.py", add_help=True)
    subparsers = parser.add_subparsers(dest="command")

    summarise_parser = subparsers.add_parser("summarise")
    summarise_parser.add_argument("--decision", default=str(DEFAULT_DECISION))
    summarise_parser.add_argument("--out")
    summarise_parser.add_argument("--root", default=str(REPO_ROOT))

    reconstruct_parser = subparsers.add_parser("reconstruct")
    reconstruct_parser.add_argument("summary")
    reconstruct_parser.add_argument("--decision", default=DECISION_PATH)
    reconstruct_parser.add_argument("--policy", default=POLICY_PATH)
    reconstruct_parser.add_argument("--root", default=str(REPO_ROOT))
    reconstruct_parser.add_argument("--json", action="store_true")

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("summary")
    verify_parser.add_argument("envelope")
    verify_parser.add_argument("--decision", default=DECISION_PATH)
    verify_parser.add_argument("--policy", default=POLICY_PATH)
    verify_parser.add_argument("--root", default=str(REPO_ROOT))
    verify_parser.add_argument("--json", action="store_true")

    parsed = parser.parse_args(arguments)
    if parsed.command is None:
        parser.error("a command is required: summarise, reconstruct or verify")

    try:
        if parsed.command == "summarise":
            return _command_summarise(parsed)
        if parsed.command == "reconstruct":
            return _command_reconstruct(parsed)
        return _command_verify(parsed)
    except Refusal as refusal:
        print(f"code={refusal.code} detail={refusal.message}")
        return EXIT_REFUSED
    except ToolError as error:
        print(f"code={CODE_USAGE} detail={error}")
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
