#!/usr/bin/env python3
"""code_scanning_export.py -- a local, GitHub-free shard export of the A1 SARIF population.

Why this tool exists
--------------------
An upload to a code-scanning service is a lossy, third-party step: the service
decides what it keeps, it may truncate a population, it may drop results that
share a fingerprint, and it may reject a file for reasons this project cannot
observe. The project must not depend on that step to state what it found. This
tool performs the whole transformation locally: it reads the A1 emission
(`evidence/a1/SARIF.json`), partitions its results into shards under a stated
limit, emits each shard as a self-contained SARIF 2.1.0 log, and writes a
manifest that is the only object stating the whole population.

There is no network client, no token, no credential and no upload here. A test
parses this module and refuses a network import or a credential read; the
refusal code exists for that structural check, not as prose.

The rule
--------
A shard is a **subset**, not a census. It carries the runs that contribute its
results, with `tool` complete (minus the `rules` table, which is restricted),
`artifacts` restricted to the URIs its results reference, and `rules` restricted
to the `ruleId`s they use. It never carries a completeness or census property.
Only the manifest states the whole population, and `verify` refuses unless the
union of the shards' exact identities equals the parent population exactly once
each, in the parent's order.

Why 5,000
---------
Reported GitHub code-scanning ingestion accepts at most 5,000 results per SARIF
file. That is the only ingestion limit this tool models; a shard may not exceed
it. A file-size ceiling is **not** modelled and is recorded as `NOT_RUN` in
`docs/CODE-SCANNING-EXPORT.md`; the emitted shard is under the reported 10 MiB
ceiling only by observation, not by a check.

Usage
-----
    python3 forensics/tools/code_scanning_export.py plan [--parent PATH] [--limit N] [--json]
    python3 forensics/tools/code_scanning_export.py emit OUTDIR [--parent PATH] [--limit N] [--force]
    python3 forensics/tools/code_scanning_export.py verify OUTDIR [--parent PATH]

Exit status: 0 for a completed plan/emit/verified export, 1 for a refusal (the
stable code is always printed), 2 for a usage error.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]

SCHEMA = "openssl-rs/a8/code-scanning-export/1"
PLAN_SCHEMA = "openssl-rs/a8/code-scanning-plan/1"
CONTROLS_SCHEMA = "openssl-rs/a8/code-scanning-controls/1"

TOOL_NAME = "openssl-rs-code-scanning-export"
TOOL_VERSION = "1.0.0"
TOOL_PATH = "forensics/tools/code_scanning_export.py"

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)

MAX_RESULTS = 5000
DEFAULT_PARENT = "evidence/a1/SARIF.json"
MANIFEST_NAME = "MANIFEST.json"
SHARD_NAME = "SHARD-{index:03d}.sarif"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

# ---------------------------------------------------------------------------
# Refusal codes. Each is stable, and each names the wrong conclusion it
# prevents. The document's table is generated from the same intent; a test
# refuses a code present in one and absent from the other.
# ---------------------------------------------------------------------------

EX_REFUSED_OVERSIZE_SHARD = "EX_REFUSED_OVERSIZE_SHARD"
EX_REFUSED_SHARD_AS_CENSUS = "EX_REFUSED_SHARD_AS_CENSUS"
EX_REFUSED_MANIFEST_ABSENT = "EX_REFUSED_MANIFEST_ABSENT"
EX_REFUSED_MANIFEST_SHARD_MISSING = "EX_REFUSED_MANIFEST_SHARD_MISSING"
EX_REFUSED_UNION_INCOMPLETE = "EX_REFUSED_UNION_INCOMPLETE"
EX_REFUSED_UNION_DUPLICATE = "EX_REFUSED_UNION_DUPLICATE"
EX_REFUSED_ORDER_CHANGED = "EX_REFUSED_ORDER_CHANGED"
EX_REFUSED_DIGEST_MISMATCH = "EX_REFUSED_DIGEST_MISMATCH"
EX_REFUSED_TOOL_DROPPED = "EX_REFUSED_TOOL_DROPPED"
EX_REFUSED_RULE_DROPPED = "EX_REFUSED_RULE_DROPPED"
EX_REFUSED_ARTIFACT_DROPPED = "EX_REFUSED_ARTIFACT_DROPPED"
EX_REFUSED_CANDIDATE_UNRECORDED = "EX_REFUSED_CANDIDATE_UNRECORDED"
EX_REFUSED_ABSOLUTE_PATH = "EX_REFUSED_ABSOLUTE_PATH"
EX_REFUSED_UNSUPPORTED_VERSION = "EX_REFUSED_UNSUPPORTED_VERSION"
EX_REFUSED_NETWORK_OR_CREDENTIAL = "EX_REFUSED_NETWORK_OR_CREDENTIAL"
EX_REFUSED_PARENT_SHAPE = "EX_REFUSED_PARENT_SHAPE"
EX_REFUSED_OUTPUT_NOT_EMPTY = "EX_REFUSED_OUTPUT_NOT_EMPTY"

REFUSALS: dict[str, dict[str, str]] = {
    EX_REFUSED_OVERSIZE_SHARD: {
        "condition": "a shard holds more results than the export limit (5,000)",
        "prevents": (
            "that a file the service would truncate is a complete shard, so an "
            "ingestion-side cut is read as a shard that held nothing more"
        ),
    },
    EX_REFUSED_SHARD_AS_CENSUS: {
        "condition": "a shard carries a completeness or census property",
        "prevents": (
            "that one shard is the population, which would make every other "
            "shard and the manifest look like duplicates or noise"
        ),
    },
    EX_REFUSED_MANIFEST_ABSENT: {
        "condition": "no manifest was supplied or it cannot be read",
        "prevents": (
            "that a set of shard files is an export: without the manifest there "
            "is no statement of the population and no union check"
        ),
    },
    EX_REFUSED_MANIFEST_SHARD_MISSING: {
        "condition": "the manifest and the shard set disagree about which shards exist",
        "prevents": (
            "that the files on disk and the results the manifest accounts for "
            "are the same set"
        ),
    },
    EX_REFUSED_UNION_INCOMPLETE: {
        "condition": "a parent result identity is missing from the union of the shards",
        "prevents": (
            "that the shards together hold the parent population when a result "
            "was dropped or never emitted"
        ),
    },
    EX_REFUSED_UNION_DUPLICATE: {
        "condition": "the union holds an exact identity more than once",
        "prevents": (
            "that a repeated result is two results, which would inflate the "
            "population and hide a missing one"
        ),
    },
    EX_REFUSED_ORDER_CHANGED: {
        "condition": "a shard's result order is not the parent order restricted to it",
        "prevents": (
            "that a reordered shard is a faithful subset; order is the only "
            "positional check against the parent's own emission order"
        ),
    },
    EX_REFUSED_DIGEST_MISMATCH: {
        "condition": "a shard's bytes do not hash to the digest the manifest records",
        "prevents": (
            "that the analysed shard is the emitted shard, so evidence from one "
            "file is not reused for another"
        ),
    },
    EX_REFUSED_TOOL_DROPPED: {
        "condition": "a shard run's tool identity is not the parent run's",
        "prevents": (
            "that a result produced by a different producer is evidence from "
            "this parent"
        ),
    },
    EX_REFUSED_RULE_DROPPED: {
        "condition": "a result names a rule the shard's `rules` table omits or changed",
        "prevents": (
            "that a self-contained log exists when its rule descriptions are "
            "absent, which leaves `ruleId` readable but its meaning unstated"
        ),
    },
    EX_REFUSED_ARTIFACT_DROPPED: {
        "condition": "a result names an artifact URI the shard's `artifacts` table omits or changed",
        "prevents": (
            "that a location is resolvable when its artifact entry is absent, "
            "and that an index still points at the artifact it claims"
        ),
    },
    EX_REFUSED_CANDIDATE_UNRECORDED: {
        "condition": "the parent, a shard or the manifest records no candidate, or a different one",
        "prevents": (
            "that a result is bound to the candidate it was emitted at when the "
            "identity is absent or has moved"
        ),
    },
    EX_REFUSED_ABSOLUTE_PATH: {
        "condition": "a parent URI, a shard URI, a shard file name or a manifest parent path is absolute",
        "prevents": (
            "that a host path is read as a portable artefact reference, and "
            "that a shard file is taken from outside the export directory"
        ),
    },
    EX_REFUSED_UNSUPPORTED_VERSION: {
        "condition": "the parent, a shard or the manifest is not the supported version",
        "prevents": (
            "that a different format is read with this export's rules; a 2.2 "
            "or a later manifest is not this manifest"
        ),
    },
    EX_REFUSED_NETWORK_OR_CREDENTIAL: {
        "condition": "the export module imports a network client, reads a credential, or uploads",
        "prevents": (
            "that the export depends on a service, a token or a network call; "
            "the export is a local transformation and must remain one"
        ),
    },
    EX_REFUSED_PARENT_SHAPE: {
        "condition": "the parent is unreadable, malformed, or internally inconsistent",
        "prevents": (
            "that a shape this tool does not understand is exported as if it "
            "were the A1 profile"
        ),
    },
    EX_REFUSED_OUTPUT_NOT_EMPTY: {
        "condition": "the output directory is not empty and `--force` was not given",
        "prevents": (
            "that an unrelated directory is overwritten in the belief that it "
            "is this export's output"
        ),
    },
}

# ---------------------------------------------------------------------------
# Small utilities.
# ---------------------------------------------------------------------------

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ABSOLUTE_URI = re.compile(r"^(?:[A-Za-z]:[\\/]|[\\/])|^[A-Za-z][A-Za-z0-9+.\-]*:")
_CENSUS_KEY = re.compile(r"(?:^|[_.-])(?:census|complete|completeness)(?:$|[_.-])", re.I)


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


def serialize_sarif(document: dict[str, Any]) -> str:
    """Canonical shard bytes: sorted keys, no insignificant whitespace, one newline.

    The shard is the large object; compacting it keeps the real 4,245-result
    emission under the reported ingestion size ceiling. Determinism is preserved
    because the ordering and separators are fixed, not because the file is small.
    """
    return json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"


def dump_document(document: dict[str, Any]) -> str:
    """Canonical JSON for a recorded manifest/plan/control document."""
    return json.dumps(document, indent=1, sort_keys=True) + "\n"


def is_absolute_uri(uri: Any) -> bool:
    return isinstance(uri, str) and bool(_ABSOLUTE_URI.match(uri))


def _runs(document: dict[str, Any]) -> list[dict[str, Any]]:
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise Refusal(EX_REFUSED_PARENT_SHAPE, "the document has no runs array")
    return runs


def _results(run: dict[str, Any]) -> list[dict[str, Any]]:
    results = run.get("results")
    if not isinstance(results, list):
        raise Refusal(EX_REFUSED_PARENT_SHAPE, "a run has no results array")
    return results


def flatten(document: dict[str, Any]) -> list[tuple[int, int]]:
    """(run index, result index) in input order: runs as emitted, results as emitted."""
    positions: list[tuple[int, int]] = []
    for run_index, run in enumerate(_runs(document)):
        for result_index in range(len(_results(run))):
            positions.append((run_index, result_index))
    return positions


def _a1(result: dict[str, Any]) -> dict[str, Any]:
    properties = result.get("properties")
    block = properties.get("a1") if isinstance(properties, dict) else None
    return block if isinstance(block, dict) else {}


def _result_uri(result: dict[str, Any]) -> str | None:
    artifact = _a1(result).get("artifact")
    if isinstance(artifact, dict) and isinstance(artifact.get("uri"), str):
        return artifact["uri"]
    return None


def referenced_uris(result: dict[str, Any]) -> list[str]:
    """Every artifact URI a result references, in first-seen order."""
    uris: list[str] = []
    for key in ("locations", "relatedLocations"):
        for location in result.get(key) or []:
            physical = location.get("physicalLocation") or {}
            artifact = physical.get("artifactLocation") or {}
            uri = artifact.get("uri")
            if isinstance(uri, str) and uri not in uris:
                uris.append(uri)
    uri = _result_uri(result)
    if uri is not None and uri not in uris:
        uris.append(uri)
    return uris


def _artifact_locations(result: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for key in ("locations", "relatedLocations"):
        for location in result.get(key) or []:
            physical = location.get("physicalLocation") or {}
            artifact = physical.get("artifactLocation")
            if isinstance(artifact, dict):
                yield artifact


def tool_projection(run: dict[str, Any]) -> dict[str, Any]:
    """A run's tool identity with the per-shard `rules` table removed.

    `rules` is deliberately restricted per shard ($4.3 of the SARIF profile makes
    `ruleIndex` per-run), so it is checked separately. Everything else in `tool`
    must be byte-identical to the parent run's.
    """
    tool = copy.deepcopy(run.get("tool") or {})
    driver = tool.get("driver")
    if isinstance(driver, dict):
        driver.pop("rules", None)
    return tool


def tool_identity(document: dict[str, Any]) -> dict[str, Any]:
    """The producer identity shared by the document's runs, or a recorded refusal."""
    runs = _runs(document)
    identities = []
    for run in runs:
        driver = (run.get("tool") or {}).get("driver") or {}
        identities.append(
            {
                "name": driver.get("name"),
                "version": driver.get("version"),
                "semanticVersion": driver.get("semanticVersion"),
            }
        )
    uniform = all(identity == identities[0] for identity in identities)
    return {"runs": identities, "uniform": uniform}


# ---------------------------------------------------------------------------
# Candidate identity.
# ---------------------------------------------------------------------------


def candidate_identity(document: dict[str, Any]) -> dict[str, Any]:
    """The candidate each run was emitted at, and one token over the set.

    A document may hold several per-run candidates (the A1 emission holds six),
    so the export never invents one candidate for the file. The token is a
    SHA-256 over the ordered per-run candidate blocks; every shard and the
    manifest carry the same token, and `verify` compares it with the parent.
    """
    runs = _runs(document)
    per_run: list[dict[str, Any]] = []
    for run_index, run in enumerate(runs):
        properties = run.get("properties")
        block = properties.get("a1") if isinstance(properties, dict) else None
        candidate = block.get("candidate") if isinstance(block, dict) else None
        if not isinstance(candidate, dict) or not candidate:
            raise Refusal(
                EX_REFUSED_CANDIDATE_UNRECORDED,
                f"run {run_index} records no candidate identity",
            )
        per_run.append({"run": run_index, "candidate": candidate})
    distinct = {canonical_json(entry["candidate"]) for entry in per_run}
    return {
        "token": digest_bytes(canonical_json(per_run).encode("utf-8")),
        "mixed": len(distinct) > 1,
        "runCount": len(per_run),
        "distinctCount": len(distinct),
        "perRun": per_run,
    }


# ---------------------------------------------------------------------------
# Exact identity.
# ---------------------------------------------------------------------------

_EXACT_DOMAIN = "a8-exact/v1"


def _raw_exact(result: dict[str, Any], where: str) -> str:
    fingerprints = result.get("partialFingerprints")
    if not isinstance(fingerprints, dict):
        raise Refusal(
            EX_REFUSED_UNION_INCOMPLETE, f"{where} has no partialFingerprints"
        )
    exact = fingerprints.get("a1Exact/v1")
    if not isinstance(exact, str) or not _HEX64.fullmatch(exact):
        raise Refusal(
            EX_REFUSED_UNION_INCOMPLETE,
            f"{where} has no 64-hex `a1Exact/v1`; a result without an exact "
            "identity cannot be counted once in a union",
        )
    return exact


def exact_identities(document: dict[str, Any]) -> list[str]:
    """The exact identity of every result, in input order, collision-refined.

    `a1Exact/v1` is the identity. The SARIF profile permits two results in one
    run to share it and requires a second discriminator rather than a merge
    ($6.4), so a colliding value is refined with the native record, locator and
    message. The refinement is deterministic and is applied only to a colliding
    value. A repeated identity is returned as a repeat -- never dropped -- and
    `verify` refuses it, because a union that holds one result twice is not the
    parent population once each.
    """
    raw: list[tuple[str, dict[str, Any], str]] = []
    positions = flatten(document)
    for global_index, (run_index, result_index) in enumerate(positions):
        result = _results(_runs(document)[run_index])[result_index]
        where = f"run {run_index} result {result_index}"
        raw.append((_raw_exact(result, where), result, where))

    counts = Counter(exact for exact, _result, _where in raw)
    identities: list[str] = []
    for exact, result, where in raw:
        if counts[exact] == 1:
            identities.append(exact)
            continue
        native = _a1(result).get("native") or {}
        record = native.get("record") if isinstance(native, dict) else ""
        locator = native.get("locator") if isinstance(native, dict) else ""
        message = (result.get("message") or {}).get("text", "")
        payload = "\x00".join(
            (_EXACT_DOMAIN, exact, str(record), str(locator), str(message))
        )
        identities.append(digest_bytes(payload.encode("utf-8")))

    return identities


def identity_digest(identities: list[str]) -> str:
    return digest_bytes(canonical_json(sorted(identities)).encode("utf-8"))


# ---------------------------------------------------------------------------
# Parent validation.
# ---------------------------------------------------------------------------


def validate_parent(document: dict[str, Any]) -> None:
    """Refuse a parent this tool would export as something it is not.

    This is a structural check of the fields the sharding depends on, not a
    schema validation and not a claim that a finding is true.
    """
    if not isinstance(document, dict):
        raise Refusal(EX_REFUSED_PARENT_SHAPE, "the parent is not a JSON object")
    if document.get("version") != SARIF_VERSION:
        raise Refusal(
            EX_REFUSED_UNSUPPORTED_VERSION,
            f"parent version is {document.get('version')!r}, not {SARIF_VERSION!r}",
        )
    runs = _runs(document)
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise Refusal(
                EX_REFUSED_PARENT_SHAPE, f"run {run_index} is not an object"
            )
        driver = ((run.get("tool") or {}).get("driver")) or {}
        if not isinstance(driver.get("name"), str) or not driver.get("name"):
            raise Refusal(
                EX_REFUSED_TOOL_DROPPED, f"run {run_index} names no tool driver"
            )
        rules = driver.get("rules")
        if not isinstance(rules, list):
            raise Refusal(
                EX_REFUSED_RULE_DROPPED, f"run {run_index} has no rules table"
            )
        rule_positions: dict[str, int] = {}
        for rule_index, rule in enumerate(rules):
            rule_id = rule.get("id") if isinstance(rule, dict) else None
            if not isinstance(rule_id, str) or not rule_id:
                raise Refusal(
                    EX_REFUSED_RULE_DROPPED,
                    f"run {run_index} rule {rule_index} has no id",
                )
            if rule_id in rule_positions:
                raise Refusal(
                    EX_REFUSED_PARENT_SHAPE,
                    f"run {run_index} repeats rule id {rule_id!r}",
                )
            rule_positions[rule_id] = rule_index

        artifacts = run.get("artifacts")
        if not isinstance(artifacts, list):
            raise Refusal(
                EX_REFUSED_ARTIFACT_DROPPED, f"run {run_index} has no artifacts table"
            )
        artifact_positions: dict[str, int] = {}
        for artifact_index, artifact in enumerate(artifacts):
            location = artifact.get("location") if isinstance(artifact, dict) else None
            uri = location.get("uri") if isinstance(location, dict) else None
            if not isinstance(uri, str) or not uri:
                raise Refusal(
                    EX_REFUSED_ARTIFACT_DROPPED,
                    f"run {run_index} artifact {artifact_index} has no location.uri",
                )
            if is_absolute_uri(uri):
                raise Refusal(
                    EX_REFUSED_ABSOLUTE_PATH,
                    f"run {run_index} artifact {artifact_index} is {uri!r}",
                )
            if uri in artifact_positions:
                raise Refusal(
                    EX_REFUSED_PARENT_SHAPE,
                    f"run {run_index} repeats artifact uri {uri!r}",
                )
            artifact_positions[uri] = artifact_index

        results = _results(run)
        run_candidate = (((run.get("properties") or {}).get("a1") or {}).get("candidate"))
        if not isinstance(run_candidate, dict) or not run_candidate:
            raise Refusal(
                EX_REFUSED_CANDIDATE_UNRECORDED,
                f"run {run_index} records no candidate identity",
            )
        for result_index, result in enumerate(results):
            where = f"run {run_index} result {result_index}"
            rule_id = result.get("ruleId")
            if rule_id not in rule_positions:
                raise Refusal(
                    EX_REFUSED_RULE_DROPPED,
                    f"{where} names rule {rule_id!r}, which its run does not list",
                )
            if result.get("ruleIndex") != rule_positions[rule_id]:
                raise Refusal(
                    EX_REFUSED_RULE_DROPPED,
                    f"{where} ruleIndex is {result.get('ruleIndex')!r}, "
                    f"which is not the index of {rule_id!r}",
                )
            _raw_exact(result, where)
            candidate = _a1(result).get("candidate")
            if not isinstance(candidate, dict) or candidate != run_candidate:
                raise Refusal(
                    EX_REFUSED_CANDIDATE_UNRECORDED,
                    f"{where} records a candidate that is not its run's",
                )
            for uri in referenced_uris(result):
                if is_absolute_uri(uri):
                    raise Refusal(
                        EX_REFUSED_ABSOLUTE_PATH, f"{where} references {uri!r}"
                    )
                if uri not in artifact_positions:
                    raise Refusal(
                        EX_REFUSED_ARTIFACT_DROPPED,
                        f"{where} references {uri!r}, which its run does not list",
                    )
            for artifact_location in _artifact_locations(result):
                if "index" not in artifact_location:
                    continue
                index = artifact_location["index"]
                uri = artifact_location.get("uri")
                if not isinstance(index, int) or not 0 <= index < len(artifacts):
                    raise Refusal(
                        EX_REFUSED_ARTIFACT_DROPPED,
                        f"{where} artifact index {index!r} is out of range",
                    )
                listed = (artifacts[index].get("location") or {}).get("uri")
                if listed != uri:
                    raise Refusal(
                        EX_REFUSED_ARTIFACT_DROPPED,
                        f"{where} artifact index {index} names {listed!r} but "
                        f"the location says {uri!r}",
                    )


# ---------------------------------------------------------------------------
# Planning.
# ---------------------------------------------------------------------------


def plan(document: dict[str, Any], max_results: int = MAX_RESULTS) -> list[dict[str, Any]]:
    """Partition the results, in input order, into shards of at most `max_results`.

    The boundary is the input order, never a hash order: re-running reproduces
    the plan, and a shard's position in the parent is an index the reader can
    check without recomputing an identity. The plan is a partition of *indices*;
    it states no count that a later emission could contradict.
    """
    if not isinstance(max_results, int) or isinstance(max_results, bool) or max_results < 1:
        raise ValueError("max_results must be a positive integer")
    validate_parent(document)
    positions = flatten(document)
    shards: list[dict[str, Any]] = []
    total = (len(positions) + max_results - 1) // max_results
    for index in range(total):
        start = index * max_results
        stop = min(start + max_results, len(positions))
        indices = list(range(start, stop))
        run_indices = sorted({positions[i][0] for i in indices})
        shards.append(
            {
                "index": index,
                "total": total,
                "results": indices,
                "runIndices": run_indices,
            }
        )
    return shards


def _parent_block(
    document: dict[str, Any],
    parent_bytes: bytes,
    parent_path: str,
    identities: list[str],
) -> dict[str, Any]:
    runs = _runs(document)
    return {
        "path": parent_path,
        "sha256": digest_bytes(parent_bytes),
        "bytes": len(parent_bytes),
        "resultCount": len(identities),
        "runCount": len(runs),
        "runs": [
            {"index": index, "results": len(_results(run))}
            for index, run in enumerate(runs)
        ],
        "identitiesDigest": identity_digest(identities),
        "tool": tool_identity(document),
    }


def _emission_header(
    document: dict[str, Any], parent_bytes: bytes, limit: int, parent_path: str
) -> dict[str, Any]:
    """The part of a manifest `emit` reads: a function of the parent bytes alone.

    Building it separately keeps the manifest and the shards from being
    circular: the shard binds the parent's digest, and the manifest binds the
    shard bytes that digest identifies.
    """
    identities = exact_identities(document)
    return {
        "parent": _parent_block(document, parent_bytes, parent_path, identities),
        "candidate": candidate_identity(document),
        "limit": limit,
    }


# ---------------------------------------------------------------------------
# Emission.
# ---------------------------------------------------------------------------


def _subset_run(
    run: dict[str, Any],
    result_indices: list[int],
    run_index: int,
) -> dict[str, Any]:
    """Copy one run with only `result_indices`, and the tables those results use."""
    driver = run["tool"]["driver"]
    rule_by_id = {rule["id"]: rule for rule in driver.get("rules") or []}
    used_rules = sorted({run["results"][i]["ruleId"] for i in result_indices})
    missing_rules = [rule for rule in used_rules if rule not in rule_by_id]
    if missing_rules:
        raise Refusal(
            EX_REFUSED_RULE_DROPPED,
            f"run {run_index} result names {missing_rules[0]!r}, which the parent "
            "rules table does not define",
        )
    new_rule_index = {rule: position for position, rule in enumerate(used_rules)}

    artifacts = run.get("artifacts") or []
    artifact_by_uri = {
        (artifact.get("location") or {}).get("uri"): artifact for artifact in artifacts
    }
    used_uris: set[str] = set()
    for index in result_indices:
        for uri in referenced_uris(run["results"][index]):
            if uri not in artifact_by_uri:
                raise Refusal(
                    EX_REFUSED_ARTIFACT_DROPPED,
                    f"run {run_index} result {index} references {uri!r}, which "
                    "the parent artifacts table does not define",
                )
            used_uris.add(uri)
    ordered_uris = sorted(used_uris)
    new_artifact_index = {uri: position for position, uri in enumerate(ordered_uris)}

    new_results: list[dict[str, Any]] = []
    for index in result_indices:
        result = copy.deepcopy(run["results"][index])
        result["ruleIndex"] = new_rule_index[result["ruleId"]]
        for artifact_location in _artifact_locations(result):
            if "index" not in artifact_location:
                continue
            uri = artifact_location.get("uri")
            artifact_location["index"] = new_artifact_index[uri]
        new_results.append(result)

    new_run = {
        key: copy.deepcopy(value)
        for key, value in run.items()
        if key not in ("results", "artifacts", "tool")
    }
    new_run["tool"] = copy.deepcopy(run["tool"])
    new_run["tool"]["driver"]["rules"] = [
        copy.deepcopy(rule_by_id[rule]) for rule in used_rules
    ]
    new_run["artifacts"] = [
        copy.deepcopy(artifact_by_uri[uri]) for uri in ordered_uris
    ]
    new_run["results"] = new_results
    return new_run


def emit(
    document: dict[str, Any],
    shard: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Build one self-contained SARIF 2.1.0 log for `shard`.

    The log holds a copy of every run that contributes a result, with `tool`
    complete except the restricted `rules` table, `artifacts` restricted to the
    URIs its results reference, and `rules` restricted to the ids they use;
    `ruleIndex` and every `artifactLocation.index` are relabelled for the
    restricted tables. It carries no completeness property: `properties.shard`
    states the shard's own count against the parent count, nothing more.
    """
    if not isinstance(manifest, dict) or "parent" not in manifest:
        raise Refusal(EX_REFUSED_MANIFEST_ABSENT, "no manifest to bind the shard to")
    limit = manifest.get("limit", MAX_RESULTS)
    if not isinstance(limit, int) or limit < 1:
        raise Refusal(EX_REFUSED_PARENT_SHAPE, "the manifest limit is not an integer")
    result_indices = shard.get("results")
    if not isinstance(result_indices, list) or not all(
        isinstance(index, int) for index in result_indices
    ):
        raise Refusal(EX_REFUSED_PARENT_SHAPE, "the shard's results are not indices")
    if len(result_indices) > limit:
        raise Refusal(
            EX_REFUSED_OVERSIZE_SHARD,
            f"{len(result_indices)} results exceed the {limit}-result limit",
        )

    positions = flatten(document)
    by_run: dict[int, list[int]] = {}
    for index in result_indices:
        if not 0 <= index < len(positions):
            raise Refusal(
                EX_REFUSED_PARENT_SHAPE,
                f"result index {index} is outside the parent population",
            )
        run_index, result_index = positions[index]
        by_run.setdefault(run_index, []).append(result_index)

    shard_result_count = len(result_indices)
    runs = _runs(document)
    new_runs = [
        _subset_run(runs[run_index], sorted(indices), run_index)
        for run_index, indices in sorted(by_run.items())
    ]

    return {
        "$schema": document.get("$schema", SARIF_SCHEMA),
        "version": SARIF_VERSION,
        "runs": new_runs,
        "properties": {
            "shard": {
                "index": shard["index"],
                "total": shard["total"],
                "parentDigest": manifest["parent"]["sha256"],
                "parentResultCount": manifest["parent"]["resultCount"],
                "resultCount": shard_result_count,
                "candidate": manifest["candidate"],
            }
        },
    }


def _shard_documents(
    document: dict[str, Any],
    shards: list[dict[str, Any]],
    header: dict[str, Any],
) -> list[dict[str, Any]]:
    return [emit(document, shard, header) for shard in shards]


def _shard_identities(document: dict[str, Any]) -> list[str]:
    """Identities of the results a shard document actually holds, in document order."""
    return exact_identities(document)


# ---------------------------------------------------------------------------
# Manifest.
# ---------------------------------------------------------------------------


def manifest(
    document: dict[str, Any],
    shards: list[dict[str, Any]],
    *,
    parent_bytes: bytes,
    parent_path: str = "parent.sarif",
    limit: int = MAX_RESULTS,
    shard_documents: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The only object that states the export's whole population.

    It binds the exact parent bytes, the candidate identity, every shard's
    bytes and result count, and a union check derived from the shard contents
    themselves. It deliberately records the observed union result rather than
    asserting it: `verify` is what refuses a manifest whose own union check
    reads false.
    """
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer")
    if shard_documents is None:
        header = _emission_header(document, parent_bytes, limit, parent_path)
        shard_documents = _shard_documents(document, shards, header)
    if len(shard_documents) != len(shards):
        raise Refusal(
            EX_REFUSED_MANIFEST_SHARD_MISSING,
            f"{len(shards)} planned shard(s) but {len(shard_documents)} shard(s)",
        )

    parent_identities = exact_identities(document)
    parent_block = _parent_block(document, parent_bytes, parent_path, parent_identities)
    candidate = candidate_identity(document)

    entries: list[dict[str, Any]] = []
    union_identities: list[str] = []
    for shard, shard_document in zip(shards, shard_documents):
        text = serialize_sarif(shard_document).encode("utf-8")
        identities = _shard_identities(shard_document)
        union_identities.extend(identities)
        entries.append(
            {
                "index": shard["index"],
                "file": SHARD_NAME.format(index=shard["index"]),
                "sha256": digest_bytes(text),
                "bytes": len(text),
                "resultCount": len(identities),
                "runIndices": shard["runIndices"],
                "firstResult": shard["results"][0] if shard["results"] else None,
                "lastResult": shard["results"][-1] if shard["results"] else None,
            }
        )

    parent_counter = Counter(parent_identities)
    union_counter = Counter(union_identities)
    missing = sum((parent_counter - union_counter).values())
    extra = sum((union_counter - parent_counter).values())
    duplicates = sum(count - 1 for count in union_counter.values() if count > 1)
    union_block = {
        "parentResultCount": len(parent_identities),
        "shardResultCount": len(union_identities),
        "distinctIdentities": len(union_counter),
        "missing": missing,
        "extra": extra,
        "duplicates": duplicates,
        "equalsParent": (
            missing == 0
            and extra == 0
            and duplicates == 0
            and len(union_identities) == len(parent_identities)
        ),
        "identitiesDigest": identity_digest(union_identities),
    }

    shard_directory = sorted({entry["file"] for entry in entries})
    return {
        "schema": SCHEMA,
        "kind": "code-scanning-export-manifest",
        "tool": {
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
            "path": TOOL_PATH,
            "sha256": digest_file(REPO_ROOT / TOOL_PATH),
            "dependency": "none: no API client, no network call, no token, no upload",
        },
        "parent": parent_block,
        "candidate": candidate,
        "limit": limit,
        "shardCount": len(entries),
        "shards": entries,
        "shardFiles": shard_directory,
        "union": union_block,
        "nonClaims": [
            "a shard is a subset, not a census; only this manifest states the population",
            "an upload to any code-scanning service is not performed here and is not evidence",
            "a result's presence is not a verdict on the code; A1 owns the projection",
            "the copied run.properties.a1 projection describes the parent run, not the shard",
        ],
    }


# ---------------------------------------------------------------------------
# Verification.
# ---------------------------------------------------------------------------

_COMPLETENESS_KEYS = {
    "census",
    "complete",
    "completeness",
    "isCensus",
    "isComplete",
    "populationComplete",
    "allResults",
    "entirePopulation",
}


def _census_properties(properties: Any) -> list[str]:
    """Property names on a shard that claim it is the whole population."""
    found: list[str] = []
    if not isinstance(properties, dict):
        return found
    for key, value in properties.items():
        if key in _COMPLETENESS_KEYS or _CENSUS_KEY.search(key):
            found.append(key)
        elif isinstance(value, dict):
            found.extend(
                f"{key}.{nested}" for nested in _census_properties(value)
            )
    return sorted(found)


def _shard_results(document: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for run in _runs(document):
        results.extend(_results(run))
    return results


def _parent_run_for(
    shard_run: dict[str, Any],
    identity_run: dict[str, int],
) -> int:
    """Find the parent run a shard run was copied from, by its first identity."""
    for result in _results(shard_run):
        identity = exact_identities({"runs": [{"results": [result]}]})[0]
        if identity in identity_run:
            return identity_run[identity]
    raise Refusal(
        EX_REFUSED_MANIFEST_SHARD_MISSING,
        "a shard run holds no result that occurs in the parent",
    )


def verify(
    manifest_document: dict[str, Any] | None,
    shards: list[dict[str, Any]],
    parent: dict[str, Any],
) -> dict[str, Any]:
    """Refuse unless the shard set is a faithful, ordered partition of the parent.

    `shards` is a list of `{"bytes": <file bytes>, "document": <parsed log>}`;
    `parent` is `{"path": <relative>, "bytes": <file bytes>, "document": <parsed>}`.
    On success it returns the measured figures. It never repairs: a refusal is
    the result.
    """
    if not isinstance(manifest_document, dict):
        raise Refusal(EX_REFUSED_MANIFEST_ABSENT, "no manifest document")
    if manifest_document.get("schema") != SCHEMA:
        raise Refusal(
            EX_REFUSED_UNSUPPORTED_VERSION,
            f"manifest schema is {manifest_document.get('schema')!r}",
        )

    parent_document = parent.get("document")
    parent_bytes = parent.get("bytes")
    if not isinstance(parent_document, dict) or not isinstance(parent_bytes, bytes):
        raise Refusal(EX_REFUSED_MANIFEST_ABSENT, "no readable parent to verify against")

    if is_absolute_uri(manifest_document.get("parent", {}).get("path")):
        raise Refusal(
            EX_REFUSED_ABSOLUTE_PATH,
            f"manifest parent path is {manifest_document['parent']['path']!r}",
        )
    if manifest_document["parent"].get("sha256") != digest_bytes(parent_bytes):
        raise Refusal(
            EX_REFUSED_DIGEST_MISMATCH,
            "the manifest names a parent digest that is not the parent bytes",
        )
    if parent_document.get("version") != SARIF_VERSION:
        raise Refusal(
            EX_REFUSED_UNSUPPORTED_VERSION,
            f"parent version is {parent_document.get('version')!r}",
        )
    validate_parent(parent_document)

    parent_candidate = candidate_identity(parent_document)
    if manifest_document.get("candidate") != parent_candidate:
        raise Refusal(
            EX_REFUSED_CANDIDATE_UNRECORDED,
            "the manifest's candidate is not the parent's candidate identity",
        )

    entries = manifest_document.get("shards")
    if not isinstance(entries, list):
        raise Refusal(EX_REFUSED_MANIFEST_SHARD_MISSING, "the manifest lists no shards")
    by_index: dict[int, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("index"), int):
            raise Refusal(
                EX_REFUSED_MANIFEST_SHARD_MISSING, "a manifest shard entry has no index"
            )
        by_index[entry["index"]] = entry
    if manifest_document.get("shardCount") != len(entries):
        raise Refusal(
            EX_REFUSED_MANIFEST_SHARD_MISSING,
            "the manifest shard count is not its shard list",
        )

    provided: dict[int, dict[str, Any]] = {}
    for shard in shards:
        document = shard.get("document") if isinstance(shard, dict) else None
        if not isinstance(document, dict):
            raise Refusal(EX_REFUSED_MANIFEST_SHARD_MISSING, "a shard is not a log")
        properties = document.get("properties") or {}
        block = properties.get("shard") if isinstance(properties, dict) else None
        if not isinstance(block, dict) or not isinstance(block.get("index"), int):
            raise Refusal(
                EX_REFUSED_MANIFEST_SHARD_MISSING,
                "a shard carries no `properties.shard.index` to identify it",
            )
        if block["index"] in provided:
            raise Refusal(
                EX_REFUSED_MANIFEST_SHARD_MISSING,
                f"shard index {block['index']} is present twice",
            )
        provided[block["index"]] = shard

    if set(provided) != set(by_index):
        missing = sorted(set(by_index) - set(provided))
        extra = sorted(set(provided) - set(by_index))
        raise Refusal(
            EX_REFUSED_MANIFEST_SHARD_MISSING,
            f"manifest-only {missing}, directory-only {extra}",
        )

    limit = manifest_document.get("limit")
    if not isinstance(limit, int) or limit < 1:
        raise Refusal(EX_REFUSED_PARENT_SHAPE, "the manifest limit is not an integer")
    effective_limit = min(limit, MAX_RESULTS)

    parent_identities = exact_identities(parent_document)
    identity_run = {
        identity: run_index
        for identity, (run_index, _result) in zip(
            parent_identities, flatten(parent_document)
        )
    }
    union_identities: list[str] = []
    shard_identity_order: dict[int, list[str]] = {}
    total_results = 0

    for index in sorted(by_index):
        entry = by_index[index]
        shard = provided[index]
        document = shard["document"]
        raw_bytes = shard.get("bytes")
        if not isinstance(raw_bytes, bytes):
            raise Refusal(
                EX_REFUSED_DIGEST_MISMATCH, f"shard {index} has no bytes to hash"
            )
        block = document["properties"]["shard"]

        if document.get("version") != SARIF_VERSION:
            raise Refusal(
                EX_REFUSED_UNSUPPORTED_VERSION,
                f"shard {index} version is {document.get('version')!r}",
            )
        name = entry.get("file")
        if not isinstance(name, str) or Path(name).name != name or is_absolute_uri(name):
            raise Refusal(
                EX_REFUSED_ABSOLUTE_PATH,
                f"shard {index} file name is {name!r}",
            )
        if block.get("total") != manifest_document.get("shardCount"):
            raise Refusal(
                EX_REFUSED_MANIFEST_SHARD_MISSING,
                f"shard {index} total is {block.get('total')!r}, not the manifest count",
            )
        if block.get("total") != len(entries) or entry.get("index") != index:
            raise Refusal(
                EX_REFUSED_MANIFEST_SHARD_MISSING,
                f"shard {index} does not agree with its manifest entry",
            )
        if block.get("parentDigest") != manifest_document["parent"]["sha256"]:
            raise Refusal(
                EX_REFUSED_DIGEST_MISMATCH,
                f"shard {index} binds a different parent digest",
            )
        if digest_bytes(raw_bytes) != entry.get("sha256"):
            raise Refusal(
                EX_REFUSED_DIGEST_MISMATCH,
                f"shard {index} bytes do not match the manifest digest",
            )
        if block.get("candidate") != parent_candidate:
            raise Refusal(
                EX_REFUSED_CANDIDATE_UNRECORDED,
                f"shard {index} records a candidate that is not the parent's",
            )
        if block.get("parentResultCount") != len(parent_identities):
            raise Refusal(
                EX_REFUSED_UNION_INCOMPLETE,
                f"shard {index} states parent count "
                f"{block.get('parentResultCount')!r}, not {len(parent_identities)}",
            )
        census = _census_properties(document.get("properties"))
        if census:
            raise Refusal(
                EX_REFUSED_SHARD_AS_CENSUS,
                f"shard {index} carries census property {census[0]!r}",
            )

        shard_results = _shard_results(document)
        if (
            entry.get("resultCount") != len(shard_results)
            or block.get("resultCount") != len(shard_results)
        ):
            raise Refusal(
                EX_REFUSED_UNION_INCOMPLETE,
                f"shard {index} holds {len(shard_results)} results, which is not "
                "the count it or the manifest states",
            )
        if len(shard_results) > effective_limit:
            raise Refusal(
                EX_REFUSED_OVERSIZE_SHARD,
                f"shard {index} holds {len(shard_results)} results, over "
                f"{effective_limit}",
            )
        total_results += len(shard_results)

        for shard_run in document["runs"]:
            for uri in _run_uris(shard_run):
                if is_absolute_uri(uri):
                    raise Refusal(
                        EX_REFUSED_ABSOLUTE_PATH,
                        f"shard {index} references {uri!r}",
                    )
            run_index = _parent_run_for(shard_run, identity_run)
            parent_run = _runs(parent_document)[run_index]
            if tool_projection(shard_run) != tool_projection(parent_run):
                raise Refusal(
                    EX_REFUSED_TOOL_DROPPED,
                    f"shard {index} run {run_index} has a different tool identity",
                )
            parent_rules = {
                rule["id"]: rule for rule in parent_run["tool"]["driver"]["rules"]
            }
            shard_rules = {
                rule["id"]: rule for rule in shard_run["tool"]["driver"].get("rules") or []
            }
            for result in _results(shard_run):
                rule_id = result.get("ruleId")
                if rule_id not in shard_rules:
                    raise Refusal(
                        EX_REFUSED_RULE_DROPPED,
                        f"shard {index} result names {rule_id!r}, which its table omits",
                    )
                if shard_rules[rule_id] != parent_rules.get(rule_id):
                    raise Refusal(
                        EX_REFUSED_RULE_DROPPED,
                        f"shard {index} rule {rule_id!r} is not the parent's",
                    )
                rule_index = result.get("ruleIndex")
                if (
                    not isinstance(rule_index, int)
                    or not 0 <= rule_index < len(shard_run["tool"]["driver"]["rules"])
                    or shard_run["tool"]["driver"]["rules"][rule_index]["id"] != rule_id
                ):
                    raise Refusal(
                        EX_REFUSED_RULE_DROPPED,
                        f"shard {index} result {rule_id!r} has a stale ruleIndex",
                    )

            parent_artifacts = {
                (artifact.get("location") or {}).get("uri"): artifact
                for artifact in parent_run.get("artifacts") or []
            }
            shard_artifacts = shard_run.get("artifacts") or []
            shard_artifact_by_uri = {
                (artifact.get("location") or {}).get("uri"): artifact
                for artifact in shard_artifacts
            }
            for result in _results(shard_run):
                for uri in referenced_uris(result):
                    if uri not in shard_artifact_by_uri:
                        raise Refusal(
                            EX_REFUSED_ARTIFACT_DROPPED,
                            f"shard {index} references {uri!r}, which its table omits",
                        )
                    if shard_artifact_by_uri[uri] != parent_artifacts.get(uri):
                        raise Refusal(
                            EX_REFUSED_ARTIFACT_DROPPED,
                            f"shard {index} artifact {uri!r} is not the parent's",
                        )
                for artifact_location in _artifact_locations(result):
                    if "index" not in artifact_location:
                        continue
                    artifact_index = artifact_location["index"]
                    uri = artifact_location.get("uri")
                    if (
                        not isinstance(artifact_index, int)
                        or not 0 <= artifact_index < len(shard_artifacts)
                        or (shard_artifacts[artifact_index].get("location") or {}).get("uri")
                        != uri
                    ):
                        raise Refusal(
                            EX_REFUSED_ARTIFACT_DROPPED,
                            f"shard {index} artifact index for {uri!r} is stale",
                        )

        shard_identity_order[index] = [
            identity
            for identity in (exact_identities(document))
        ]
        union_identities.extend(shard_identity_order[index])

    union_counter = Counter(union_identities)
    duplicate_identities = [
        identity for identity, count in union_counter.items() if count > 1
    ]
    if duplicate_identities:
        raise Refusal(
            EX_REFUSED_UNION_DUPLICATE,
            f"{len(duplicate_identities)} exact identity value(s) occur more than "
            f"once, beginning {duplicate_identities[0]}",
        )
    parent_counter = Counter(parent_identities)
    missing = sum((parent_counter - union_counter).values())
    extra = sum((union_counter - parent_counter).values())
    if missing or extra or len(union_identities) != len(parent_identities):
        raise Refusal(
            EX_REFUSED_UNION_INCOMPLETE,
            f"{missing} parent result(s) missing, {extra} not in the parent",
        )
    stated = manifest_document.get("union")
    if (
        not isinstance(stated, dict)
        or stated.get("equalsParent") is not True
        or stated.get("parentResultCount") != len(parent_identities)
        or stated.get("shardResultCount") != len(union_identities)
        or stated.get("identitiesDigest") != identity_digest(union_identities)
    ):
        raise Refusal(
            EX_REFUSED_UNION_INCOMPLETE,
            "the manifest's union block does not state the union it holds",
        )

    for index, identities in shard_identity_order.items():
        remaining = Counter(identities)
        expected: list[str] = []
        for identity in parent_identities:
            if remaining[identity] > 0:
                expected.append(identity)
                remaining[identity] -= 1
        if identities != expected:
            raise Refusal(
                EX_REFUSED_ORDER_CHANGED,
                f"shard {index} is not the parent order restricted to it",
            )

    return {
        "shards": len(entries),
        "results": total_results,
        "union": "complete",
        "duplicates": 0,
        "order": "preserved",
        "tool": "preserved",
        "rules": "preserved",
        "artifacts": "preserved",
        "candidate": parent_candidate["token"],
    }


def _run_uris(run: dict[str, Any]) -> list[str]:
    uris: list[str] = []
    for artifact in run.get("artifacts") or []:
        uri = (artifact.get("location") or {}).get("uri")
        if isinstance(uri, str):
            uris.append(uri)
    for result in _results(run):
        uris.extend(referenced_uris(result))
    return uris


# ---------------------------------------------------------------------------
# The structural no-dependency check.
# ---------------------------------------------------------------------------

FORBIDDEN_MODULES = {
    "requests",
    "urllib",
    "urllib2",
    "urllib3",
    "http",
    "httpx",
    "aiohttp",
    "socket",
    "ssl",
    "ftplib",
    "telnetlib",
    "smtplib",
    "subprocess",
    "webbrowser",
}
_CREDENTIAL_NAMES = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|API_KEY|AUTH)", re.I
)


def network_dependency_findings(source: str) -> list[dict[str, str]]:
    """Return the structural reasons a module source would be refused.

    This is a source inspection, not a sandbox: it detects an imported network
    client and a credential read from the environment. It cannot detect a
    network call assembled from strings, so the limit is stated rather than
    hidden. The export module itself must return no finding.
    """
    findings: list[dict[str, str]] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        return [
            {
                "code": EX_REFUSED_NETWORK_OR_CREDENTIAL,
                "kind": "unparsable",
                "detail": str(error),
            }
        ]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_MODULES:
                    findings.append(
                        {
                            "code": EX_REFUSED_NETWORK_OR_CREDENTIAL,
                            "kind": "import",
                            "detail": alias.name,
                        }
                    )
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in FORBIDDEN_MODULES:
                findings.append(
                    {
                        "code": EX_REFUSED_NETWORK_OR_CREDENTIAL,
                        "kind": "import",
                        "detail": node.module or "",
                    }
                )
        elif isinstance(node, ast.Attribute):
            if (
                isinstance(node.value, ast.Name)
                and node.value.id == "os"
                and node.attr in ("environ", "getenv")
            ):
                findings.append(
                    {
                        "code": EX_REFUSED_NETWORK_OR_CREDENTIAL,
                        "kind": "credential",
                        "detail": f"os.{node.attr}",
                    }
                )
        elif isinstance(node, ast.Call):
            function = node.func
            if (
                isinstance(function, ast.Attribute)
                and function.attr in ("getenv",)
                and isinstance(function.value, ast.Name)
                and function.value.id == "os"
            ):
                name = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else ""
                if isinstance(name, str) and _CREDENTIAL_NAMES.search(name):
                    findings.append(
                        {
                            "code": EX_REFUSED_NETWORK_OR_CREDENTIAL,
                            "kind": "credential",
                            "detail": f"os.getenv({name!r})",
                        }
                    )
    return findings


def module_source() -> str:
    return Path(__file__).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Output directory handling.
# ---------------------------------------------------------------------------


def ensure_output_directory(path: Path, force: bool = False) -> None:
    """Refuse a non-empty directory unless the caller says it is the export's."""
    if path.exists():
        if not path.is_dir():
            raise Refusal(
                EX_REFUSED_OUTPUT_NOT_EMPTY, f"{path.name!r} is not a directory"
            )
        if any(path.iterdir()) and not force:
            raise Refusal(
                EX_REFUSED_OUTPUT_NOT_EMPTY,
                f"{path.name!r} is not empty; pass --force to replace this export",
            )


# ---------------------------------------------------------------------------
# Control documents and controls.
# ---------------------------------------------------------------------------


def synthetic_document(result_count: int, run_count: int = 1) -> dict[str, Any]:
    """A deterministic control document with the shape the export requires.

    It is a control input only. It is never written as evidence and is never
    substituted for the A1 population.
    """
    if result_count < 0 or run_count < 1:
        raise ValueError("a control population needs a non-negative count and a run")
    runs: list[dict[str, Any]] = []
    for run_index in range(run_count):
        candidate = {"control_candidate": f"run-{run_index}"}
        artifacts = [
            {
                "location": {"uri": f"synthetic/src/control-{run_index}-{i}.rs"},
                "hashes": {"sha-256": digest_bytes(f"artifact/{run_index}/{i}".encode())},
                "properties": {"a1": {"digestScope": "source-tree"}},
                "roles": ["conversionSource"],
            }
            for i in range(2)
        ]
        rules = [
            {
                "id": f"A1-CONTROL-{'A' if run_index == 0 else 'B'}",
                "name": f"Control{'A' if run_index == 0 else 'B'}",
                "shortDescription": {"text": "a synthetic control rule"},
                "fullDescription": {"text": "a synthetic control rule"},
                "defaultConfiguration": {"level": "warning"},
            },
            {
                "id": f"A1-CONTROL-{'B' if run_index == 0 else 'A'}",
                "name": f"Control{'B' if run_index == 0 else 'A'}",
                "shortDescription": {"text": "a second synthetic control rule"},
                "fullDescription": {"text": "a second synthetic control rule"},
                "defaultConfiguration": {"level": "warning"},
            },
        ]
        per_run = result_count // run_count + (
            1 if run_index < result_count % run_count else 0
        )
        results: list[dict[str, Any]] = []
        for i in range(per_run):
            rule_index = i % 2
            rule_id = rules[rule_index]["id"]
            artifact_index = i % 2
            uri = artifacts[artifact_index]["location"]["uri"]
            results.append(
                {
                    "ruleId": rule_id,
                    "ruleIndex": rule_index,
                    "kind": "fail",
                    "level": "warning",
                    "message": {"text": f"control finding {run_index}-{i}"},
                    "partialFingerprints": {
                        "a1Rule/v1": digest_bytes(f"rule/{rule_id}".encode()),
                        "a1Logical/v1": digest_bytes(f"logical/{run_index}/{i}".encode()),
                        "a1Exact/v1": digest_bytes(f"exact/{run_index}/{i}".encode()),
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": artifact_index,
                                    "uri": uri,
                                    "uriBaseId": "SRCROOT",
                                },
                                "region": {"startLine": i + 1},
                            }
                        }
                    ],
                    "properties": {
                        "a1": {
                            "candidate": candidate,
                            "artifact": {
                                "uri": uri,
                                "digestScope": "source-tree",
                                "algorithm": "sha-256",
                                "digest": digest_bytes(f"artifact/{run_index}/{artifact_index}".encode()),
                            },
                            "native": {
                                "record": f"synthetic-control-{run_index}.json",
                                "locator": f"/runs/{run_index}/results/{i}",
                                "fields": {},
                            },
                        }
                    },
                }
            )
        runs.append(
            {
                "tool": {
                    "driver": {
                        "name": "openssl-rs-control-adapter",
                        "version": "1.0.0",
                        "semanticVersion": "1.0.0",
                        "fullDescription": {"text": "a synthetic control emission"},
                        "rules": rules,
                    }
                },
                "invocations": [{"executionSuccessful": True, "exitCode": 0}],
                "columnKind": "unicodeCodePoints",
                "artifacts": artifacts,
                "results": results,
                "properties": {
                    "a1": {
                        "record": {"path": f"synthetic-control-{run_index}.json"},
                        "candidate": candidate,
                        "adapter": {"path": "control", "sha256": "0" * 64},
                    }
                },
            }
        )
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": runs}


def _control_parent(document: dict[str, Any]) -> dict[str, Any]:
    raw = dump_document(document).encode("utf-8")
    return {"path": "control/parent.sarif", "bytes": raw, "document": document}


def _control_entries(
    document: dict[str, Any], limit: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    parent = _control_parent(document)
    shards = plan(document, limit)
    header = _emission_header(document, parent["bytes"], limit, parent["path"])
    documents = _shard_documents(document, shards, header)
    return shards, {
        "parent": parent,
        "header": header,
        "documents": documents,
    }


def _observed_code(action) -> str:
    try:
        action()
    except Refusal as refusal:
        return refusal.code
    raise AssertionError("the control did not refuse")


def build_controls(
    document: dict[str, Any], parent_bytes: bytes
) -> list[dict[str, Any]]:
    """Produce one control per refusal code, each producing its named code.

    The controls mutate copies in memory. A control that fires proves the
    refusal works; it is not a finding about the tree and it writes nothing.
    """
    controls: list[dict[str, Any]] = []

    def add(name: str, code: str, action, note: str = "") -> None:
        observed = _observed_code(action)
        if observed != code:
            raise AssertionError(f"{name}: expected {code}, observed {observed}")
        controls.append(
            {"control": name, "code": code, "observed": observed, "note": note}
        )

    # A valid small export is the base for the mutations.
    small = synthetic_document(6, run_count=2)
    small_parent = _control_parent(small)
    small_shards = plan(small, 4)
    small_header = _emission_header(
        small, small_parent["bytes"], 4, small_parent["path"]
    )
    small_docs = _shard_documents(small, small_shards, small_header)
    small_manifest = manifest(
        small,
        small_shards,
        parent_bytes=small_parent["bytes"],
        parent_path=small_parent["path"],
        limit=4,
        shard_documents=small_docs,
    )
    small_inputs = [
        {"bytes": serialize_sarif(log).encode("utf-8"), "document": log}
        for log in small_docs
    ]
    verify(small_manifest, small_inputs, small_parent)

    # Oversize: a single shard of 5,001 results against a 5,000 limit.
    oversize = synthetic_document(MAX_RESULTS + 1)
    oversize_parent = _control_parent(oversize)
    oversize_shards = plan(oversize, MAX_RESULTS + 1)
    oversize_header = _emission_header(
        oversize, oversize_parent["bytes"], MAX_RESULTS + 1, oversize_parent["path"]
    )
    oversize_docs = _shard_documents(oversize, oversize_shards, oversize_header)
    oversize_manifest = manifest(
        oversize,
        oversize_shards,
        parent_bytes=oversize_parent["bytes"],
        parent_path=oversize_parent["path"],
        limit=MAX_RESULTS,
        shard_documents=oversize_docs,
    )
    oversize_inputs = [
        {"bytes": serialize_sarif(log).encode("utf-8"), "document": log}
        for log in oversize_docs
    ]
    add(
        "oversize-shard",
        EX_REFUSED_OVERSIZE_SHARD,
        lambda: verify(oversize_manifest, oversize_inputs, oversize_parent),
        "5,001 results in one shard against the 5,000 limit",
    )

    # A shard that claims to be the census.
    census_docs = copy.deepcopy(small_docs)
    census_docs[0]["properties"]["shard"]["census"] = True
    census_manifest = manifest(
        small,
        small_shards,
        parent_bytes=small_parent["bytes"],
        parent_path=small_parent["path"],
        limit=4,
        shard_documents=census_docs,
    )
    add(
        "shard-as-census",
        EX_REFUSED_SHARD_AS_CENSUS,
        lambda: verify(
            census_manifest,
            [
                {"bytes": serialize_sarif(log).encode("utf-8"), "document": log}
                for log in census_docs
            ],
            small_parent,
        ),
        "properties.shard.census is present",
    )

    add(
        "manifest-absent",
        EX_REFUSED_MANIFEST_ABSENT,
        lambda: verify(None, small_inputs, small_parent),
        "no manifest object",
    )

    add(
        "manifest-shard-missing",
        EX_REFUSED_MANIFEST_SHARD_MISSING,
        lambda: verify(small_manifest, small_inputs[:1], small_parent),
        "the manifest names two shards; one is supplied",
    )

    # A result dropped from the first shard, with the manifest rebuilt around it.
    dropped_docs = copy.deepcopy(small_docs)
    dropped_docs[0]["runs"][0]["results"].pop(0)
    dropped_docs[0]["properties"]["shard"]["resultCount"] = sum(
        len(run["results"]) for run in dropped_docs[0]["runs"]
    )
    dropped_manifest = manifest(
        small,
        small_shards,
        parent_bytes=small_parent["bytes"],
        parent_path=small_parent["path"],
        limit=4,
        shard_documents=dropped_docs,
    )
    add(
        "union-incomplete",
        EX_REFUSED_UNION_INCOMPLETE,
        lambda: verify(
            dropped_manifest,
            [
                {"bytes": serialize_sarif(log).encode("utf-8"), "document": log}
                for log in dropped_docs
            ],
            small_parent,
        ),
        "one result removed from shard 0",
    )

    duplicate_docs = copy.deepcopy(small_docs)
    duplicate_docs[1]["runs"][0]["results"].append(
        copy.deepcopy(duplicate_docs[1]["runs"][0]["results"][0])
    )
    duplicate_docs[1]["properties"]["shard"]["resultCount"] = sum(
        len(run["results"]) for run in duplicate_docs[1]["runs"]
    )
    duplicate_manifest = manifest(
        small,
        small_shards,
        parent_bytes=small_parent["bytes"],
        parent_path=small_parent["path"],
        limit=4,
        shard_documents=duplicate_docs,
    )
    add(
        "union-duplicate",
        EX_REFUSED_UNION_DUPLICATE,
        lambda: verify(
            duplicate_manifest,
            [
                {"bytes": serialize_sarif(log).encode("utf-8"), "document": log}
                for log in duplicate_docs
            ],
            small_parent,
        ),
        "the first result of shard 1 is present twice",
    )

    reordered_docs = copy.deepcopy(small_docs)
    results = reordered_docs[0]["runs"][0]["results"]
    results[0], results[1] = results[1], results[0]
    reordered_manifest = manifest(
        small,
        small_shards,
        parent_bytes=small_parent["bytes"],
        parent_path=small_parent["path"],
        limit=4,
        shard_documents=reordered_docs,
    )
    add(
        "order-changed",
        EX_REFUSED_ORDER_CHANGED,
        lambda: verify(
            reordered_manifest,
            [
                {"bytes": serialize_sarif(log).encode("utf-8"), "document": log}
                for log in reordered_docs
            ],
            small_parent,
        ),
        "two results in shard 0 swapped",
    )

    stale_digest = copy.deepcopy(small_manifest)
    stale_digest["shards"][0]["sha256"] = "0" * 64
    add(
        "digest-mismatch",
        EX_REFUSED_DIGEST_MISMATCH,
        lambda: verify(stale_digest, small_inputs, small_parent),
        "one manifest digest changed",
    )

    tool_docs = copy.deepcopy(small_docs)
    tool_docs[0]["runs"][0]["tool"]["driver"]["name"] = "another-producer"
    tool_manifest = manifest(
        small,
        small_shards,
        parent_bytes=small_parent["bytes"],
        parent_path=small_parent["path"],
        limit=4,
        shard_documents=tool_docs,
    )
    add(
        "tool-dropped",
        EX_REFUSED_TOOL_DROPPED,
        lambda: verify(
            tool_manifest,
            [
                {"bytes": serialize_sarif(log).encode("utf-8"), "document": log}
                for log in tool_docs
            ],
            small_parent,
        ),
        "shard 0 names a different tool",
    )

    rule_docs = copy.deepcopy(small_docs)
    rule_docs[0]["runs"][0]["tool"]["driver"]["rules"].pop(0)
    rule_manifest = manifest(
        small,
        small_shards,
        parent_bytes=small_parent["bytes"],
        parent_path=small_parent["path"],
        limit=4,
        shard_documents=rule_docs,
    )
    add(
        "rule-dropped",
        EX_REFUSED_RULE_DROPPED,
        lambda: verify(
            rule_manifest,
            [
                {"bytes": serialize_sarif(log).encode("utf-8"), "document": log}
                for log in rule_docs
            ],
            small_parent,
        ),
        "a used rule removed from shard 0",
    )

    artifact_docs = copy.deepcopy(small_docs)
    artifact_docs[0]["runs"][0]["artifacts"].pop(0)
    artifact_manifest = manifest(
        small,
        small_shards,
        parent_bytes=small_parent["bytes"],
        parent_path=small_parent["path"],
        limit=4,
        shard_documents=artifact_docs,
    )
    add(
        "artifact-dropped",
        EX_REFUSED_ARTIFACT_DROPPED,
        lambda: verify(
            artifact_manifest,
            [
                {"bytes": serialize_sarif(log).encode("utf-8"), "document": log}
                for log in artifact_docs
            ],
            small_parent,
        ),
        "a referenced artifact removed from shard 0",
    )

    candidate_docs = copy.deepcopy(small_docs)
    candidate_docs[0]["properties"]["shard"]["candidate"] = {"token": "0" * 64}
    candidate_manifest = manifest(
        small,
        small_shards,
        parent_bytes=small_parent["bytes"],
        parent_path=small_parent["path"],
        limit=4,
        shard_documents=candidate_docs,
    )
    add(
        "candidate-unrecorded",
        EX_REFUSED_CANDIDATE_UNRECORDED,
        lambda: verify(
            candidate_manifest,
            [
                {"bytes": serialize_sarif(log).encode("utf-8"), "document": log}
                for log in candidate_docs
            ],
            small_parent,
        ),
        "shard 0 carries a candidate that is not the parent's",
    )

    absolute_docs = copy.deepcopy(small_docs)
    absolute_docs[0]["runs"][0]["artifacts"][0]["location"]["uri"] = "/abs/control.rs"
    absolute_manifest = manifest(
        small,
        small_shards,
        parent_bytes=small_parent["bytes"],
        parent_path=small_parent["path"],
        limit=4,
        shard_documents=absolute_docs,
    )
    add(
        "absolute-path",
        EX_REFUSED_ABSOLUTE_PATH,
        lambda: verify(
            absolute_manifest,
            [
                {"bytes": serialize_sarif(log).encode("utf-8"), "document": log}
                for log in absolute_docs
            ],
            small_parent,
        ),
        "one artifact URI is a host path",
    )

    unsupported_docs = copy.deepcopy(small_docs)
    unsupported_docs[0]["version"] = "2.2.0"
    unsupported_manifest = manifest(
        small,
        small_shards,
        parent_bytes=small_parent["bytes"],
        parent_path=small_parent["path"],
        limit=4,
        shard_documents=unsupported_docs,
    )
    add(
        "unsupported-version",
        EX_REFUSED_UNSUPPORTED_VERSION,
        lambda: verify(
            unsupported_manifest,
            [
                {"bytes": serialize_sarif(log).encode("utf-8"), "document": log}
                for log in unsupported_docs
            ],
            small_parent,
        ),
        "one shard claims SARIF 2.2.0",
    )

    malformed = copy.deepcopy(small)
    duplicate_rule = copy.deepcopy(malformed["runs"][0]["tool"]["driver"]["rules"][0])
    duplicate_rule["name"] = "ControlDuplicate"
    malformed["runs"][0]["tool"]["driver"]["rules"].append(duplicate_rule)
    malformed_parent = _control_parent(malformed)
    malformed_manifest = manifest(
        malformed,
        small_shards,
        parent_bytes=malformed_parent["bytes"],
        parent_path=malformed_parent["path"],
        limit=4,
        shard_documents=small_docs,
    )
    add(
        "parent-shape",
        EX_REFUSED_PARENT_SHAPE,
        lambda: verify(malformed_manifest, small_inputs, malformed_parent),
        "a run repeats a rule id",
    )

    # The structural no-dependency control: a forbidden source and the real module.
    add(
        "network-or-credential",
        EX_REFUSED_NETWORK_OR_CREDENTIAL,
        lambda: _raise_first(
            network_dependency_findings(
                "import urllib.request\nimport os\nTOKEN = os.environ['GITHUB_TOKEN']\n"
            )
        ),
        "a source that imports a network client and reads a token",
    )
    real_findings = network_dependency_findings(module_source())
    if real_findings:
        raise AssertionError(f"the export module is not dependency-free: {real_findings}")
    controls[-1]["realModule"] = "clean"

    with tempfile.TemporaryDirectory() as directory:
        occupied = Path(directory) / "output"
        occupied.mkdir()
        (occupied / "existing.txt").write_text("not this export\n", encoding="utf-8")
        add(
            "output-not-empty",
            EX_REFUSED_OUTPUT_NOT_EMPTY,
            lambda: ensure_output_directory(occupied, force=False),
            "a non-empty directory without --force",
        )

    covered = {control["code"] for control in controls}
    if covered != set(REFUSALS):
        raise AssertionError(
            "the controls do not cover every refusal code: missing "
            f"{sorted(set(REFUSALS) - covered)}"
        )
    if len(controls) != len(REFUSALS):
        raise AssertionError(
            f"{len(controls)} controls over {len(REFUSALS)} codes; one per code is required"
        )
    return controls


def _raise_first(findings: list[dict[str, str]]) -> None:
    if findings:
        raise Refusal(findings[0]["code"], findings[0]["detail"])
    raise AssertionError("the control source produced no finding")


# ---------------------------------------------------------------------------
# Documents for the evidence directory.
# ---------------------------------------------------------------------------


def plan_document(
    document: dict[str, Any],
    parent_bytes: bytes,
    parent_path: str,
    limit: int,
) -> dict[str, Any]:
    """The recorded plan: the real population and the synthetic 5,000-boundary proof."""
    real = plan(document, limit)
    synthetic_count = 12001
    synthetic = synthetic_document(synthetic_count)
    synthetic_shards = plan(synthetic, limit)
    parent_identities = exact_identities(document)

    def boundaries(shards: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "index": shard["index"],
                "total": shard["total"],
                "count": len(shard["results"]),
                "first": shard["results"][0] if shard["results"] else None,
                "last": shard["results"][-1] if shard["results"] else None,
                "runIndices": shard["runIndices"],
                "results": shard["results"],
            }
            for shard in shards
        ]

    return {
        "schema": PLAN_SCHEMA,
        "kind": "code-scanning-plan",
        "limit": limit,
        "parent": {
            "path": parent_path,
            "sha256": digest_bytes(parent_bytes),
            "bytes": len(parent_bytes),
            "resultCount": len(parent_identities),
            "runCount": len(document.get("runs") or []),
            "identitiesDigest": identity_digest(parent_identities),
        },
        "real": {
            "kind": "real",
            "population": "evidence/a1/SARIF.json",
            "resultCount": len(parent_identities),
            "shardCount": len(real),
            "boundaries": boundaries(real),
        },
        "synthetic": {
            "kind": "synthetic control population; never an evidence population",
            "resultCount": synthetic_count,
            "shardCount": len(synthetic_shards),
            "boundaries": boundaries(synthetic_shards),
            "why": (
                "12,001 results prove the 5,000 boundary: 5,000, 5,000 and 2,001 "
                "at indices 0, 5,000 and 10,000. The tracked A1 population is "
                "4,245 results, so it yields one real shard and cannot produce a "
                "second without a synthetic population."
            ),
        },
    }


def controls_document(controls: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": CONTROLS_SCHEMA,
        "kind": "code-scanning-export-controls",
        "tool": {
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
            "path": TOOL_PATH,
            "sha256": digest_file(REPO_ROOT / TOOL_PATH),
        },
        "codes": {
            code: {
                "condition": entry["condition"],
                "prevents": entry["prevents"],
            }
            for code, entry in REFUSALS.items()
        },
        "controls": controls,
        "realModule": "no network client, no credential read, no upload",
    }


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------


def _read_json_file(path: Path, code: str, what: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise Refusal(code, f"{what} cannot be read: {error.strerror}") from error
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise Refusal(code, f"{what} is not JSON: {error}") from error
    if not isinstance(document, dict):
        raise Refusal(code, f"{what} is not a JSON object")
    return raw, document


def _resolve_parent(path_text: str) -> Path:
    if is_absolute_uri(path_text):
        raise Refusal(
            EX_REFUSED_ABSOLUTE_PATH,
            f"the parent path is {path_text!r}; a relative path is required",
        )
    return REPO_ROOT / path_text


def _command_plan(args: argparse.Namespace) -> int:
    parent_path = _resolve_parent(args.parent)
    raw, document = _read_json_file(parent_path, EX_REFUSED_PARENT_SHAPE, "the parent")
    shards = plan(document, args.limit)
    if args.json:
        print(dump_document({"limit": args.limit, "shards": shards}), end="")
        return EXIT_OK
    print(
        f"plan: results={len(flatten(document))} runs={len(_runs(document))} "
        f"limit={args.limit} shards={len(shards)}"
    )
    for shard in shards:
        print(
            f"shard {shard['index']}: results={len(shard['results'])} "
            f"first={shard['results'][0] if shard['results'] else None} "
            f"last={shard['results'][-1] if shard['results'] else None} "
            f"runs={shard['runIndices']}"
        )
    return EXIT_OK


def _command_emit(args: argparse.Namespace) -> int:
    outdir = Path(args.outdir)
    ensure_output_directory(outdir, force=args.force)
    parent_path = _resolve_parent(args.parent)
    raw, document = _read_json_file(parent_path, EX_REFUSED_PARENT_SHAPE, "the parent")
    shards = plan(document, args.limit)
    built = manifest(
        document,
        shards,
        parent_bytes=raw,
        parent_path=args.parent,
        limit=args.limit,
    )
    logs = [emit(document, shard, built) for shard in shards]
    texts = [serialize_sarif(log) for log in logs]
    report = verify(
        built,
        [
            {"bytes": text.encode("utf-8"), "document": log}
            for text, log in zip(texts, logs)
        ],
        {"path": args.parent, "bytes": raw, "document": document},
    )
    outdir.mkdir(parents=True, exist_ok=True)
    for shard, text in zip(shards, texts):
        (outdir / SHARD_NAME.format(index=shard["index"])).write_text(
            text, encoding="utf-8"
        )
    (outdir / MANIFEST_NAME).write_text(dump_document(built), encoding="utf-8")
    print(
        f"emit: shards={report['shards']} results={report['results']} "
        f"union={report['union']} outdir={outdir.name}"
    )
    return EXIT_OK


def _command_verify(args: argparse.Namespace) -> int:
    outdir = Path(args.outdir)
    manifest_path = outdir / MANIFEST_NAME
    if not manifest_path.is_file():
        raise Refusal(
            EX_REFUSED_MANIFEST_ABSENT, f"{outdir.name!r} holds no {MANIFEST_NAME}"
        )
    manifest_bytes, manifest_document = _read_json_file(
        manifest_path, EX_REFUSED_MANIFEST_ABSENT, "the manifest"
    )
    del manifest_bytes
    parent_text = args.parent or manifest_document.get("parent", {}).get("path")
    if not isinstance(parent_text, str) or not parent_text:
        raise Refusal(EX_REFUSED_MANIFEST_ABSENT, "the manifest names no parent")
    parent_path = _resolve_parent(parent_text)
    parent_bytes, parent_document = _read_json_file(
        parent_path, EX_REFUSED_PARENT_SHAPE, "the parent"
    )
    parent = {"path": parent_text, "bytes": parent_bytes, "document": parent_document}

    listed = {entry.get("file") for entry in manifest_document.get("shards") or []}
    on_disk = {path.name for path in outdir.glob("SHARD-*.sarif")}
    if on_disk != {name for name in listed if isinstance(name, str)}:
        raise Refusal(
            EX_REFUSED_MANIFEST_SHARD_MISSING,
            f"manifest-only {sorted({n for n in listed if isinstance(n, str)} - on_disk)}, "
            f"directory-only {sorted(on_disk - {n for n in listed if isinstance(n, str)})}",
        )

    shards: list[dict[str, Any]] = []
    for entry in manifest_document.get("shards") or []:
        name = entry.get("file")
        if not isinstance(name, str) or Path(name).name != name:
            raise Refusal(
                EX_REFUSED_ABSOLUTE_PATH,
                f"shard file name is {name!r}",
            )
        path = outdir / name
        if not path.is_file():
            raise Refusal(
                EX_REFUSED_MANIFEST_SHARD_MISSING, f"{name!r} is named but absent"
            )
        raw, document = _read_json_file(
            path, EX_REFUSED_MANIFEST_SHARD_MISSING, f"shard {name!r}"
        )
        shards.append({"bytes": raw, "document": document})

    report = verify(manifest_document, shards, parent)
    print(
        f"verify: ok shards={report['shards']} results={report['results']} "
        f"union={report['union']} duplicates={report['duplicates']} "
        f"order={report['order']} tool={report['tool']} rules={report['rules']} "
        f"artifacts={report['artifacts']} candidate={report['candidate']}"
    )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="code_scanning_export.py",
        description="shard the A1 SARIF population for a local, GitHub-free export",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan", help="print the deterministic shard plan")
    plan_parser.add_argument("--parent", default=DEFAULT_PARENT)
    plan_parser.add_argument("--limit", type=int, default=MAX_RESULTS)
    plan_parser.add_argument("--json", action="store_true")
    plan_parser.set_defaults(handler=_command_plan)

    emit_parser = subparsers.add_parser("emit", help="write shards and the manifest")
    emit_parser.add_argument("outdir")
    emit_parser.add_argument("--parent", default=DEFAULT_PARENT)
    emit_parser.add_argument("--limit", type=int, default=MAX_RESULTS)
    emit_parser.add_argument("--force", action="store_true")
    emit_parser.set_defaults(handler=_command_emit)

    verify_parser = subparsers.add_parser("verify", help="verify an export directory")
    verify_parser.add_argument("outdir")
    verify_parser.add_argument("--parent", default=None)
    verify_parser.set_defaults(handler=_command_verify)

    args = parser.parse_args(argv)
    if getattr(args, "limit", MAX_RESULTS) < 1:
        print("[code-scanning-export] usage: --limit must be a positive integer", file=sys.stderr)
        return EXIT_USAGE
    try:
        return args.handler(args)
    except Refusal as refusal:
        print(f"[code-scanning-export] {refusal.code}: {refusal.detail}", file=sys.stderr)
        return EXIT_REFUSED
    except ValueError as error:
        print(f"[code-scanning-export] usage: {error}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
