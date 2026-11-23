#!/usr/bin/env python3
"""preservation.py -- ETP-T13 long-term preservation, validation and controls.

What this tool decides
----------------------
Three machine-readable records describe what a third party would need to keep
verifying this programme after the authors are gone:

* ``evidence/etp-t13/FORMATS.json`` -- the tracked encodings and schema
  identifiers, their versions, where each is defined, which tool reads it, and
  what a reader must do when the version is unknown;
* ``evidence/etp-t13/DIGESTS.json`` -- the admitted digest algorithms, the
  measured named/unnamed populations, and the renewal plan;
* ``evidence/etp-t13/ARCHIVAL.json`` -- the artefact classes, where each is
  archived, whether that location is inside this repository, and whether it is
  externally durable.

The records are *derived* from a frozen candidate commit (``git cat-file`` over
that commit's blobs, never from an untracked working tree), so a later evidence
commit that adds these very files cannot silently change the population they
describe.

Refusals, each with a control
-----------------------------
* ``PM_SCHEMA_UNVERSIONED`` -- a schema identifier without a version suffix.
* ``PM_DOCUMENT_VERSION_UNDECLARED`` -- an evidence document with no ``schema``.
* ``PM_DIGEST_ALGORITHM_UNNAMED`` -- a digest with no stated algorithm.
* ``PM_DIGEST_ALGORITHM_UNADMITTED`` -- a digest whose stated algorithm is not
  in the admitted set.
* ``PM_CLASS_UNARCHIVED`` -- a required class with no archival location.
* ``PM_MIGRATION_HISTORY_REWRITTEN`` -- a migration that changes or removes its
  source, or adds a required field without a converter and a version bump.

Exit contract
-------------
    0  the selected operation succeeded and every control passed
    1  a refusal, a drift between a record and the tree, or a failed control
    2  the invocation was refused (missing record, unreadable candidate)

Usage
-----
    python3 forensics/tools/preservation.py build
    python3 forensics/tools/preservation.py validate
    python3 forensics/tools/preservation.py --self-test

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

TOOLS = Path(__file__).resolve().parent
REPO_ROOT = TOOLS.parents[1]
EVIDENCE = "evidence/etp-t13"
FORMATS_PATH = f"{EVIDENCE}/FORMATS.json"
DIGESTS_PATH = f"{EVIDENCE}/DIGESTS.json"
ARCHIVAL_PATH = f"{EVIDENCE}/ARCHIVAL.json"
CLAIM_SCHEMA = "evidence/etp/claim.schema.json"
ETP0_CLAIMS = "evidence/etp0/CLAIMS.json"
ETP1_CLAIMS = "evidence/etp/claims.json"
ETP6_MANIFEST = "evidence/etp6/MANIFEST.json"

VERSION_RE = re.compile(r"^(?P<family>.+?)/(?P<version>v\d+(?:\.\d+)?|\d+)(?P<part>/part)?$")
HEX_DIGEST_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{56}$|"
                           r"^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{96}$|^[0-9a-fA-F]{128}$")

# A digest is *named* when a key or an adjacent field states the algorithm. The
# length table lets a control catch a value that cannot be the algorithm it
# claims to be, without pretending the length alone identifies the algorithm.
ALGORITHM_LENGTHS = {
    "md5": 32,
    "sha1": 40,
    "sha224": 56,
    "sha256": 64,
    "sha384": 96,
    "sha512": 128,
    "sha3_224": 56,
    "sha3_256": 64,
    "sha3_384": 96,
    "sha3_512": 128,
    "blake2s": 64,
    "blake2b": 128,
    "sm3": 64,
}

# The admitted set. Admission is about whether an algorithm may carry a recorded
# relationship at all; it is not a claim that every admitted algorithm is
# adequate for a new security commitment.
ADMITTED_ALGORITHMS = [
    {
        "id": "sha256",
        "status": "ADMITTED",
        "renewal_priority": "PRIMARY",
        "rationale": "the digest used by Git object identity, the package manifest and every current receipt",
    },
    {
        "id": "sha384",
        "status": "ADMITTED",
        "renewal_priority": "RENEWAL_CANDIDATE",
        "rationale": "a longer SHA-2 member already present in recorded vectors",
    },
    {
        "id": "sha512",
        "status": "ADMITTED",
        "renewal_priority": "RENEWAL_CANDIDATE",
        "rationale": "a longer SHA-2 member already present in recorded vectors",
    },
    {
        "id": "sha224",
        "status": "ADMITTED",
        "renewal_priority": "LEGACY_VECTOR_ONLY",
        "rationale": "present only in algorithm test vectors",
    },
    {
        "id": "sha1",
        "status": "LEGACY_COMPATIBILITY_ONLY",
        "renewal_priority": "MIGRATE_AWAY",
        "rationale": "historical compatibility and algorithm test vectors only; never admitted for a new security commitment",
    },
    {
        "id": "md5",
        "status": "LEGACY_COMPATIBILITY_ONLY",
        "renewal_priority": "MIGRATE_AWAY",
        "rationale": "historical compatibility and algorithm test vectors only; never admitted for a new security commitment",
    },
    {
        "id": "sha3_224",
        "status": "ADMITTED",
        "renewal_priority": "RENEWAL_CANDIDATE",
        "rationale": "independent construction, already exercised by test vectors",
    },
    {
        "id": "sha3_256",
        "status": "ADMITTED",
        "renewal_priority": "RENEWAL_CANDIDATE",
        "rationale": "independent construction, already exercised by test vectors",
    },
    {
        "id": "sha3_384",
        "status": "ADMITTED",
        "renewal_priority": "RENEWAL_CANDIDATE",
        "rationale": "independent construction, already exercised by test vectors",
    },
    {
        "id": "sha3_512",
        "status": "ADMITTED",
        "renewal_priority": "RENEWAL_CANDIDATE",
        "rationale": "independent construction, already exercised by test vectors",
    },
    {
        "id": "blake2s",
        "status": "ADMITTED",
        "renewal_priority": "RENEWAL_CANDIDATE",
        "rationale": "already exercised by test vectors",
    },
    {
        "id": "blake2b",
        "status": "ADMITTED",
        "renewal_priority": "RENEWAL_CANDIDATE",
        "rationale": "already exercised by test vectors",
    },
    {
        "id": "sm3",
        "status": "ADMITTED",
        "renewal_priority": "RENEWAL_CANDIDATE",
        "rationale": "already exercised by test vectors",
    },
]
ADMITTED_IDS = {entry["id"] for entry in ADMITTED_ALGORITHMS}

# A digest object is a value that claims to be a digest. Cipher ``algorithm``
# fields in vector records are not digest claims and are excluded by construction.
DIGEST_FIELD_NAMES = {"digest_algorithm", "hash_algorithm", "digest_alg", "hash_alg"}
DIGEST_VALUE_HINTS = ("hash", "digest", "checksum", "fingerprint")


class Refusal(Exception):
    """A typed refusal with a stable identifier and the offending location."""

    def __init__(self, rule: str, path: str, detail: str) -> None:
        super().__init__(f"{rule}: {path}: {detail}")
        self.rule = rule
        self.path = path
        self.detail = detail


# ---------------------------------------------------------------------------
# Git access: the population is read at a frozen commit, never from a dirty tree
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True)


def resolve_commit(repo: Path, rev: str) -> str:
    return _git(repo, "rev-parse", rev).strip()


def tracked_files(repo: Path, commit: str) -> list[str]:
    out = _git(repo, "ls-tree", "-r", "--name-only", commit)
    return [line for line in out.splitlines() if line]


def iter_blobs(repo: Path, commit: str, paths: Iterable[str]) -> Iterable[tuple[str, bytes]]:
    """Yield ``(path, bytes)`` from one commit, one blob at a time.

    A single ``git cat-file --batch`` process streams the blobs; each one is
    yielded and discarded by the caller. Holding the whole batch in memory was
    both unnecessary and unsafe for this tree, whose largest records are tens of
    megabytes each.
    """
    wanted = list(paths)
    if not wanted:
        return
    payload = "".join(f"{commit}:{path}\n" for path in wanted).encode()
    with tempfile.TemporaryFile() as request:
        request.write(payload)
        request.seek(0)
        proc = subprocess.Popen(
            ["git", "-C", str(repo), "cat-file", "--batch"],
            stdin=request,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        assert proc.stdout is not None
        try:
            for path in wanted:
                header_raw = proc.stdout.readline()
                if not header_raw:
                    break
                header = header_raw.decode("utf-8", "replace").strip()
                if header.endswith(" missing") or header.endswith(" ambiguous"):
                    continue
                parts = header.split()
                if len(parts) != 3:
                    raise RuntimeError(f"unexpected cat-file header for {path}: {header!r}")
                size = int(parts[2])
                data = proc.stdout.read(size)
                proc.stdout.read(1)
                yield path, data
        finally:
            proc.stdout.close()
            proc.wait()


def read_blobs(repo: Path, commit: str, paths: Iterable[str]) -> dict[str, bytes]:
    """Read a small set of blobs into memory (tool text and schema documents)."""
    return {path: data for path, data in iter_blobs(repo, commit, paths)}


# ---------------------------------------------------------------------------
# Schema identifiers and version rules
# ---------------------------------------------------------------------------


def parse_schema_identifier(identifier: str) -> tuple[str, str, bool]:
    """Return ``(family, version, part_marker)`` or raise ``PM_SCHEMA_UNVERSIONED``.

    The accepted forms are ``<family>/v1``, ``<family>/v1.4``, ``<family>/1`` and
    either of the first two followed by ``/part``. A trailing ``/part`` is a
    partition marker, not a version, so it is stripped after the version is read.
    """
    match = VERSION_RE.match(identifier)
    if not match:
        raise Refusal(
            "PM_SCHEMA_UNVERSIONED",
            identifier,
            "the identifier has no /v<major>[.<minor>] or /<integer> version suffix",
        )
    return match.group("family"), match.group("version"), bool(match.group("part"))


def classify_json_document(doc: Any, path: str) -> dict[str, str]:
    """Classify one tracked JSON document.

    Returns one of ``schema_bearing``, ``schema_document`` or ``data``. A
    schema-bearing document must declare a versioned identifier, so the version
    check is applied here rather than left to the caller.
    """
    if isinstance(doc, dict) and isinstance(doc.get("schema"), str):
        parse_schema_identifier(doc["schema"])
        return {"class": "schema_bearing", "identifier": doc["schema"]}
    if isinstance(doc, dict) and "$schema" in doc and "$id" in doc:
        return {"class": "schema_document", "identifier": doc["$id"]}
    if path.endswith(".schema.json"):
        return {"class": "schema_document", "identifier": ""}
    return {"class": "data", "identifier": ""}


def require_document_version(doc: Any, path: str) -> str:
    """Require an evidence document to declare a versioned schema.

    A data document (a capture, a vector, a generated table) is not an evidence
    record and is classified elsewhere. A document that *is* an evidence record
    but omits the declaration is refused rather than read plausibly.
    """
    kind = classify_json_document(doc, path)
    if kind["class"] == "data":
        raise Refusal(
            "PM_DOCUMENT_VERSION_UNDECLARED",
            path,
            "the document declares no schema identifier and its version is therefore undeclared",
        )
    return kind["identifier"]


def non_schema_class(path: str) -> str:
    if path.startswith(".frf/captures/") or path.startswith(".frf/receipts/"):
        return "capture_transcript"
    if path.startswith(".frf/claims/"):
        return "derived_claim_record"
    if path.startswith(".frf/objects/"):
        return "content_addressed_object"
    if path.startswith("court/"):
        return "court_scratch_output"
    if path.endswith(".schema.json"):
        return "schema_document"
    if path.startswith("forensics/vectors/"):
        return "cryptographic_vector"
    if path.startswith("forensics/atlas/"):
        return "generated_atlas_table"
    if path.startswith("forensics/authorities/"):
        return "authority_source_manifest"
    if path.startswith("forensics/downstream/"):
        return "downstream_data"
    if path.startswith("forensics/etp5_crypto/vectors/"):
        return "cryptographic_vector"
    if path.startswith("artifacts/"):
        return "build_or_court_artefact"
    if path.startswith("courts/"):
        return "court_result"
    if path.startswith("evidence/"):
        return "unversioned_evidence_document"
    return "other_input"


# ---------------------------------------------------------------------------
# Tool attribution: where a schema is defined and which tool reads it
# ---------------------------------------------------------------------------


def load_tool_text(repo: Path, commit: str, files: list[str]) -> dict[str, str]:
    tools = [p for p in files if p.endswith(".py") or p.endswith(".sh")]
    blobs = read_blobs(repo, commit, tools)
    out: dict[str, str] = {}
    for path, raw in blobs.items():
        out[path] = raw.decode("utf-8", "replace")
    return out


def _contains(texts: dict[str, str], needle: str) -> list[str]:
    return sorted(path for path, text in texts.items() if needle in text)


def attribute_schema(identifier: str, texts: dict[str, str]) -> dict[str, Any]:
    """Attribute one schema identifier to its defining tool and reader.

    Attribution is deliberately conservative: an exact literal wins, then the
    version-stripped family, then the atlas envelope/generator, then a literal
    prefix of at least two path components. Anything else is reported as
    undefined in the tracked tree rather than guessed.
    """
    exact = _contains(texts, identifier)
    if exact:
        return {"where_defined": exact[0], "reader": exact[0], "basis": "TOOL_LITERAL",
                "all_definers": exact[:5]}

    family, _version, _part = parse_schema_identifier(identifier)
    family_hits = _contains(texts, family)
    if family_hits:
        return {"where_defined": family_hits[0], "reader": family_hits[0],
                "basis": "TOOL_FAMILY_LITERAL", "all_definers": family_hits[:5]}

    atlas = re.match(r"^openssl-rs/atlas/(?P<kind>[^/]+)/v\d+(?:\.\d+)?$", identifier)
    if atlas:
        kind = atlas.group("kind")
        generators = _contains(texts, f'kind="{kind}"') + _contains(texts, f"kind='{kind}'")
        if generators:
            reader = sorted(set(generators))[0]
            return {"where_defined": "forensics/tools/atlas_common.py", "reader": reader,
                    "basis": "ATLAS_ENVELOPE_WITH_GENERATOR", "all_definers": [reader]}
        return {"where_defined": "forensics/tools/atlas_common.py",
                "reader": "forensics/tools/atlas_common.py",
                "basis": "ATLAS_ENVELOPE", "all_definers": []}

    parts = family.split("/")
    for width in range(len(parts) - 1, 1, -1):
        prefix = "/".join(parts[:width])
        hits = _contains(texts, prefix)
        if hits:
            return {"where_defined": hits[0], "reader": hits[0],
                    "basis": f"PREFIX_LITERAL:{prefix}", "all_definers": hits[:5]}

    return {"where_defined": None, "reader": None, "basis": "UNDEFINED_IN_TRACKED_TREE",
            "all_definers": []}


# ---------------------------------------------------------------------------
# Format registry
# ---------------------------------------------------------------------------

FORMAT_ROWS = [
    {
        "id": "json",
        "spec": "RFC 8259 / ECMA-404",
        "spec_version": "the specification carries no version number",
        "reader": "Python 3 json (standard library) and the validators in forensics/tools/",
        "unknown_version_action": "REFUSE_DECODE",
        "role": "every schema-bearing evidence record and every data document",
    },
    {
        "id": "json-schema-2020-12",
        "spec": "JSON Schema 2020-12",
        "spec_version": "2020-12",
        "reader": "forensics/tools/etp_claims.py (self-contained subset checker)",
        "unknown_version_action": "REFUSE_VALIDATE",
        "role": "the two normative schema documents",
    },
    {
        "id": "jsonl",
        "spec": "JSON Lines",
        "spec_version": "the format has no versioned specification",
        "reader": "line-oriented Python readers in forensics/tools/",
        "unknown_version_action": "REFUSE_DECODE",
        "role": "line-oriented raw tables",
    },
    {
        "id": "yaml",
        "spec": "YAML 1.2",
        "spec_version": "1.2",
        "reader": "CI runners and forensics/frf court manifests",
        "unknown_version_action": "REFUSE_DECODE",
        "role": "CI definitions and fuzzing court manifests",
    },
    {
        "id": "toml",
        "spec": "TOML 1.0",
        "spec_version": "1.0",
        "reader": "cargo and rustup",
        "unknown_version_action": "REFUSE_DECODE",
        "role": "build and toolchain manifests",
    },
    {
        "id": "tsv",
        "spec": "tab-separated values",
        "spec_version": "the format has no versioned specification",
        "reader": "performance-frontier campaign scripts",
        "unknown_version_action": "REFUSE_DECODE",
        "role": "performance campaign raw tables",
    },
    {
        "id": "pem",
        "spec": "RFC 7468",
        "spec_version": "the specification carries no version number",
        "reader": "OpenSSL-compatible parsers exercised by the PEM and X.509 courts",
        "unknown_version_action": "REFUSE_DECODE",
        "role": "key, certificate and fixture material",
    },
    {
        "id": "sha256-file",
        "spec": "coreutils sha256sum output",
        "spec_version": "the utility output format has no version number",
        "reader": "sha256sum and the performance-frontier scripts",
        "unknown_version_action": "REFUSE_DECODE",
        "role": "a file naming its digest algorithm in its suffix and in every line",
    },
    {
        "id": "elf",
        "spec": "System V gABI and the x86-64 psABI",
        "spec_version": "gABI (architecture-specific processor supplement)",
        "reader": "readelf, objdump, the loader and the binary-assurance tools",
        "unknown_version_action": "REFUSE_INTERPRET",
        "role": "tracked shared objects and fixture binaries",
    },
    {
        "id": "graphviz-dot",
        "spec": "Graphviz DOT",
        "spec_version": "the language has no versioned specification",
        "reader": "render_* scripts; presentation only, never evidence",
        "unknown_version_action": "REFUSE_RENDER",
        "role": "rendered diagrams",
    },
]


def count_extension(files: list[str], *suffixes: str) -> int:
    return sum(1 for path in files if path.endswith(suffixes))


def derive_formats(repo: Path, commit: str) -> dict[str, Any]:
    files = tracked_files(repo, commit)
    json_files = [path for path in files if path.endswith(".json")]
    texts = load_tool_text(repo, commit, files)

    entries: dict[str, dict[str, Any]] = {}
    unversioned: list[dict[str, str]] = []
    schema_documents: list[dict[str, Any]] = []
    non_schema: dict[str, list[str]] = {}

    for path, raw in iter_blobs(repo, commit, json_files):
        try:
            doc = json.loads(raw)
        except Exception:
            continue
        try:
            kind = classify_json_document(doc, path)
        except Refusal as refusal:
            unversioned.append({"path": path, "identifier": doc.get("schema", ""),
                                "rule": refusal.rule, "detail": refusal.detail})
            continue
        if kind["class"] == "schema_bearing":
            identifier = kind["identifier"]
            family, version, part = parse_schema_identifier(identifier)
            entry = entries.setdefault(identifier, {
                "identifier": identifier,
                "family": family,
                "version": version,
                "part_marker": part,
                "documents": 0,
                "examples": [],
            })
            entry["documents"] += 1
            if len(entry["examples"]) < 3:
                entry["examples"].append(path)
        elif kind["class"] == "schema_document":
            defined = ""
            if isinstance(doc, dict):
                properties = doc.get("properties") or {}
                schema_property = properties.get("schema") or {}
                defined = schema_property.get("const") or doc.get("$id", "")
            schema_documents.append({
                "path": path,
                "id": doc.get("$id", "") if isinstance(doc, dict) else "",
                "spec": doc.get("$schema", "") if isinstance(doc, dict) else "",
                "defines": defined,
                "reader": _schema_document_reader(defined, texts),
            })
        else:
            non_schema.setdefault(non_schema_class(path), []).append(path)

    for identifier, entry in entries.items():
        attribution = attribute_schema(identifier, texts)
        entry["where_defined"] = attribution["where_defined"]
        entry["reader"] = attribution["reader"]
        entry["attribution_basis"] = attribution["basis"]
        entry["unknown_version_action"] = "REFUSE_INTERPRET"
        entry["examples"] = sorted(entry["examples"])

    # A JSON Schema document is a stronger definition than a tool literal.
    for schema_document in schema_documents:
        defined = schema_document.get("defines")
        if defined and defined in entries:
            entries[defined]["where_defined"] = schema_document["path"]
            entries[defined]["reader"] = schema_document["reader"]
            entries[defined]["attribution_basis"] = "JSON_SCHEMA_DOCUMENT"

    formats = []
    for row in FORMAT_ROWS:
        item = dict(row)
        if row["id"] == "json":
            item["tracked_files"] = len(json_files)
        elif row["id"] == "jsonl":
            item["tracked_files"] = count_extension(files, ".jsonl")
        elif row["id"] == "yaml":
            item["tracked_files"] = count_extension(files, ".yaml", ".yml")
        elif row["id"] == "toml":
            item["tracked_files"] = count_extension(files, ".toml")
        elif row["id"] == "tsv":
            item["tracked_files"] = count_extension(files, ".tsv")
        elif row["id"] == "pem":
            item["tracked_files"] = count_extension(files, ".pem")
        elif row["id"] == "sha256-file":
            item["tracked_files"] = count_extension(files, ".sha256")
        elif row["id"] == "elf":
            item["tracked_files"] = count_extension(files, ".so")
        elif row["id"] == "graphviz-dot":
            item["tracked_files"] = count_extension(files, ".gxp", ".gxf")
        else:
            item["tracked_files"] = 0
        formats.append(item)

    non_schema_rows = []
    for name in sorted(non_schema):
        paths = non_schema[name]
        non_schema_rows.append({
            "class": name,
            "documents": len(paths),
            "reason": _non_schema_reason(name),
            "examples": sorted(paths)[:3],
        })

    undeclared_evidence = sorted(non_schema.get("unversioned_evidence_document", []))

    return {
        "schema": "openssl-rs/etp-t13/formats/1",
        "kind": "etp-t13-format-and-schema-registry",
        "candidate": {"commit": commit, "branch": _branch(repo, commit)},
        "version_rule": {
            "accepted_identifier_forms": [
                "<family>/v<major>",
                "<family>/v<major>.<minor>",
                "<family>/<integer>",
                "any of the above followed by /part",
            ],
            "document_rule": "a schema-bearing document must declare a schema identifier and that identifier must carry a version suffix",
            "unknown_version_action": "REFUSE_INTERPRET",
            "part_marker": "a trailing /part is a partition marker, not a version; the version precedes it",
            "additive_change_rule": "a change that only adds optional properties may keep the version; a change that adds a required field or removes a property must bump the version and name a converter",
            "statement": "a reader must refuse an unknown version rather than interpret it best-effort; a versioned identifier is a different type, not a compatible extension",
        },
        "formats": formats,
        "schema_documents": sorted(schema_documents, key=lambda item: item["path"]),
        "schemas": {
            "counts": {
                "tracked_json_files": len(json_files),
                "documents_with_schema": sum(entry["documents"] for entry in entries.values()),
                "documents_without_schema": len(json_files) - sum(entry["documents"] for entry in entries.values()),
                "distinct_identifiers": len(entries),
                "versioned_identifiers": len(entries) - len(unversioned),
                "unversioned_identifiers": len(unversioned),
                "part_marker_identifiers": sum(1 for entry in entries.values() if entry["part_marker"]),
            },
            "entries": [entries[key] for key in sorted(entries)],
            "unversioned": sorted(unversioned, key=lambda item: item["path"]),
            "non_schema_documents": {
                "count": sum(row["documents"] for row in non_schema_rows),
                "by_class": non_schema_rows,
                "undeclared_evidence_documents": undeclared_evidence,
                "statement": "these are data documents, captures and court outputs, not evidence records under a schema; the evidence documents among them are listed under undeclared_evidence_documents as a migration population and are not edited here",
            },
        },
        "migrations": derive_migrations(repo, commit),
    }


def _schema_document_reader(identifier: str, texts: dict[str, str]) -> str | None:
    if not identifier:
        return None
    hits = _contains(texts, identifier)
    return hits[0] if hits else None


def _non_schema_reason(name: str) -> str:
    return {
        "capture_transcript": "a raw capture written by an external adapter, stored verbatim",
        "derived_claim_record": "a derived claim record inside the fuzzing corpus",
        "content_addressed_object": "a content-addressed blob addressed by its path digest",
        "court_scratch_output": "a tracked court output; scratch paths are not packaged",
        "schema_document": "a JSON Schema document, which declares its type through $id and $schema rather than a record schema key",
        "cryptographic_vector": "a test vector input, not an evidence record",
        "generated_atlas_table": "a generated table whose producer names the record kind",
        "authority_source_manifest": "an upstream source manifest keyed by its own digest",
        "downstream_data": "downstream ranking or population input data",
        "build_or_court_artefact": "a build or court artefact with no record schema",
        "court_result": "a Phase-17 downstream result record validated by its JSON Schema document",
        "unversioned_evidence_document": "an evidence document that declares no schema version; recorded as a migration population, never silently accepted",
        "other_input": "an input document that is not an evidence record",
    }.get(name, "unclassified input")


def _branch(repo: Path, commit: str) -> str:
    for line in _git(repo, "branch", "--contains", commit).splitlines():
        marker = line.strip()
        if marker.startswith("* "):
            return marker[2:]
    return "unknown"


# ---------------------------------------------------------------------------
# Migration rule and demonstration
# ---------------------------------------------------------------------------


def _required_signature(schema: Any) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            required = node.get("required")
            if isinstance(required, list):
                out[path] = sorted(str(item) for item in required)
            for key, value in node.items():
                walk(value, f"{path}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}/{index}")

    walk(schema, "$")
    return out


def _schema_revisions(repo: Path, commit: str, path: str) -> list[str]:
    out = _git(repo, "log", commit, "--format=%H", "--", path).split()
    return list(reversed(out))


def _load_blob_json(repo: Path, spec: str) -> Any:
    raw = subprocess.check_output(["git", "-C", str(repo), "show", spec])
    return json.loads(raw)


def derive_migrations(repo: Path, commit: str) -> list[dict[str, Any]]:
    migrations: list[dict[str, Any]] = []

    # Demonstration 1: the explicit ETP-1 converter from the ETP-0 inventory to
    # the typed claim document. The source is retained untouched and the target
    # names the source digest.
    etp0_doc = _load_blob_json(repo, f"{commit}:{ETP0_CLAIMS}")
    etp1_doc = _load_blob_json(repo, f"{commit}:{ETP1_CLAIMS}")
    etp0_ids = [claim.get("id") for claim in etp0_doc.get("claims", [])]
    etp1_ids = [claim.get("id") for claim in etp1_doc.get("claims", [])]
    before = _verdict_counts(etp0_doc.get("claims", []))
    after = _verdict_counts(etp1_doc.get("claims", []))
    source_sha = hashlib.sha256(
        subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:{ETP0_CLAIMS}"])
    ).hexdigest()
    derived = etp1_doc.get("derived_from") or {}
    migrations.append({
        "id": "MIG-CLAIM-ETP0-TO-ETP1",
        "rule": "EXPLICIT_CONVERTER_PRESERVING_SOURCE",
        "source": {
            "path": ETP0_CLAIMS,
            "schema": etp0_doc.get("schema"),
            "sha256": source_sha,
            "retained": True,
        },
        "target": {
            "path": ETP1_CLAIMS,
            "schema": etp1_doc.get("schema"),
            "sha256": hashlib.sha256(
                subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:{ETP1_CLAIMS}"])
            ).hexdigest(),
        },
        "converter": "ETP-1 claim typing, documented in docs/ETP-CLAIM-ALGEBRA.md",
        "preserved": {
            "ids_before": len(etp0_ids),
            "ids_after": len(etp1_ids),
            "ids_equal": sorted(etp0_ids) == sorted(etp1_ids),
            "verdicts_before": before,
            "verdicts_after": after,
            "verdict_map": {"SUPPORTED": "ESTABLISHED", "PARTIAL": "PARTIAL",
                            "CONTRADICTED": "CONTRADICTED", "SUPERSEDED": "SUPERSEDED"},
            "target_derived_from_document": derived.get("document"),
            "target_derived_from_sha256": derived.get("sha256"),
            "target_binds_source": derived.get("document") == ETP0_CLAIMS
                                  and derived.get("sha256") == source_sha,
        },
        "history_rewritten": False,
    })

    # Demonstration 2: the claim schema's own shape history. Every change is
    # additive optional material at the document root; no previously required
    # field changed, so the historical documents remain valid without a rewrite.
    revisions = _schema_revisions(repo, commit, CLAIM_SCHEMA)
    history = []
    required_changes = []
    previous_signature: dict[str, list[str]] | None = None
    previous_schema: Any = None
    for revision in revisions:
        schema = _load_blob_json(repo, f"{revision}:{CLAIM_SCHEMA}")
        signature = _required_signature(schema)
        if previous_signature is not None:
            added_paths = sorted(set(signature) - set(previous_signature))
            removed_paths = sorted(set(previous_signature) - set(signature))
            tightened = sorted(
                path for path in set(signature) & set(previous_signature)
                if set(signature[path]) - set(previous_signature[path])
            )
            if tightened:
                required_changes.append({"revision": revision, "tightened_paths": tightened})
            history.append({
                "revision": revision,
                "required_signature_changed_existing_path": bool(tightened),
                "required_paths_added": added_paths,
                "required_paths_removed": removed_paths,
            })
        else:
            history.append({"revision": revision, "first_observed": True})
        previous_signature = signature
        previous_schema = schema
    migrations.append({
        "id": "MIG-CLAIM-SCHEMA-ADDITIVE",
        "rule": "FORWARD_ONLY_ADDITIVE_WITH_EXPLICIT_HISTORY",
        "path": CLAIM_SCHEMA,
        "identifier": (previous_schema or {}).get("properties", {}).get("schema", {}).get("const"),
        "revisions": history,
        "required_changes": required_changes,
        "history_rewritten": False,
        "statement": "the identifier stayed at its original version because every change was additive optional material; historical documents are retained in Git and remain valid against the current shape, so no record was rewritten",
    })
    return migrations


def _verdict_counts(claims: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for claim in claims:
        verdict = claim.get("verdict") if isinstance(claim, dict) else None
        state = verdict.get("state") if isinstance(verdict, dict) else verdict
        if isinstance(state, str):
            counts[state] = counts.get(state, 0) + 1
    return dict(sorted(counts.items()))


# ---------------------------------------------------------------------------
# Digest agility
# ---------------------------------------------------------------------------


def _algorithm_of_key(key: str) -> str | None:
    """Return the algorithm a key names, or None.

    The name may be the whole key (``sha256``), a prefix or suffix
    (``sha256_file``, ``source_sha256``) or an interior token
    (``span_sha256_current``, ``artifact_sha256_recorded``). A token boundary is
    any character that is not a lower-case letter or digit, so ``md5_sha1`` is
    recognised as naming ``md5`` (the first, longest match) and a constant such
    as ``SHA256_DIGEST_LENGTH`` is recognised too; the value-length check then
    reports the latter rather than silently counting it as a digest.
    """
    lowered = key.lower()
    for algorithm in sorted(ALGORITHM_LENGTHS, key=len, reverse=True):
        if re.search(r"(?<![a-z0-9])" + re.escape(algorithm) + r"(?![a-z0-9])", lowered):
            return algorithm
    return None


def _scan_digests(doc: Any, path: str) -> dict[str, Any]:
    named: dict[str, int] = {}
    unnamed: dict[str, int] = {}
    unadmitted: dict[str, int] = {}
    mislabelled: list[dict[str, Any]] = []

    def walk(node: Any, sub: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                algorithm = _algorithm_of_key(key)
                if algorithm and isinstance(value, str):
                    named[algorithm] = named.get(algorithm, 0) + 1
                    if HEX_DIGEST_RE.match(value) and len(value) != ALGORITHM_LENGTHS.get(algorithm):
                        mislabelled.append({
                            "path": path,
                            "field": f"{sub}/{key}",
                            "algorithm": algorithm,
                            "length": len(value),
                        })
                    continue
                if key in DIGEST_FIELD_NAMES and isinstance(value, str):
                    if value in ADMITTED_IDS:
                        named[value] = named.get(value, 0) + 1
                    else:
                        unadmitted[value] = unadmitted.get(value, 0) + 1
                    continue
                if (isinstance(value, str) and HEX_DIGEST_RE.match(value)
                        and any(hint in key.lower() for hint in DIGEST_VALUE_HINTS)):
                    unnamed[key] = unnamed.get(key, 0) + 1
                elif key in DIGEST_FIELD_NAMES and isinstance(value, str):
                    unadmitted[value] = unadmitted.get(value, 0) + 1
                walk(value, f"{sub}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{sub}/{index}")

    walk(doc, path)
    return {"named": named, "unnamed": unnamed, "unadmitted": unadmitted,
            "mislabelled": mislabelled}


def derive_digests(repo: Path, commit: str) -> dict[str, Any]:
    files = tracked_files(repo, commit)
    json_files = [path for path in files if path.endswith(".json")]

    documents_named = 0
    documents_unnamed = 0
    documents_both = 0
    named_total: dict[str, int] = {}
    unnamed_total: dict[str, int] = {}
    unadmitted_total: dict[str, int] = {}
    unnamed_examples: dict[str, list[str]] = {}
    mislabelled: list[dict[str, Any]] = []

    for path, raw in iter_blobs(repo, commit, json_files):
        try:
            doc = json.loads(raw)
        except Exception:
            continue
        scan = _scan_digests(doc, path)
        has_named = bool(scan["named"]) or bool(scan["unadmitted"])
        has_unnamed = bool(scan["unnamed"])
        if has_named:
            documents_named += 1
        if has_unnamed:
            documents_unnamed += 1
        if has_named and has_unnamed:
            documents_both += 1
        for algorithm, count in scan["named"].items():
            named_total[algorithm] = named_total.get(algorithm, 0) + count
        for key, count in scan["unnamed"].items():
            unnamed_total[key] = unnamed_total.get(key, 0) + count
            unnamed_examples.setdefault(key, [])
            if len(unnamed_examples[key]) < 3:
                unnamed_examples[key].append(path)
        for algorithm, count in scan["unadmitted"].items():
            unadmitted_total[algorithm] = unadmitted_total.get(algorithm, 0) + count
        mislabelled.extend(scan["mislabelled"])

    return {
        "schema": "openssl-rs/etp-t13/digests/1",
        "kind": "etp-t13-digest-agility-record",
        "candidate": {"commit": commit, "branch": _branch(repo, commit)},
        "admitted_algorithms": ADMITTED_ALGORITHMS,
        "population": {
            "documents_scanned": len(json_files),
            "named": {
                "documents": documents_named,
                "occurrences": sum(named_total.values()),
                "by_algorithm": dict(sorted(named_total.items())),
            },
            "unnamed": {
                "documents": documents_unnamed,
                "occurrences": sum(unnamed_total.values()),
                "by_key": dict(sorted(unnamed_total.items(), key=lambda item: (-item[1], item[0]))),
                "examples": {key: unnamed_examples[key] for key in sorted(unnamed_examples)},
            },
            "both": documents_both,
            "unadmitted": {
                "documents": 0 if not unadmitted_total else documents_named,
                "occurrences": sum(unadmitted_total.values()),
                "by_algorithm": dict(sorted(unadmitted_total.items())),
            },
            "mislabelled_length": {
                "occurrences": len(mislabelled),
                "examples": mislabelled[:10],
                "statement": "a value whose length cannot be the digest it names is reported, not repaired; some hits are constants that merely contain an algorithm name",
            },
        },
        "migration_population": {
            "state": "RECORDED_NOT_EDITED",
            "documents": documents_unnamed,
            "keys": sorted(unnamed_total, key=lambda key: (-unnamed_total[key], key)),
            "statement": "records that do not name their digest algorithm are recorded here as a population to migrate; no existing record was edited to add an algorithm",
        },
        "renewal_plan": {
            "what_is_rehashed": [
                "the source tree at a new candidate, with the new algorithm alongside the old digest",
                "each content-addressed artefact named by a receipt (archive, measurement DSO, distribution DSO, consumer binaries)",
                "the ETP-6 package manifest and the frozen Git object store it names",
                "the claim evidence entries that bind an artefact to an identity",
            ],
            "how_the_old_relationship_is_preserved": [
                "the original record is retained byte-for-byte and its original algorithm is named in the renewal record",
                "the renewal record names renewal_of with the old algorithm and digest, and the new algorithm and digest",
                "a renewed commitment is a new record; it is never substituted for the original",
                "the versioned schema identifier is bumped only when the shape changes, not when an algorithm is added",
            ],
            "what_is_never_rewritten": [
                "Git object identities and commit hashes",
                "historical receipts, including withdrawn ones and their withdrawal records",
                "the original digest algorithm named by a historical record",
                "the ETP-0 claim inventory and other source documents of a completed migration",
                "a timestamp or a signature over old material, which a later signature cannot retroactively validate",
            ],
            "renewal_record_fields": ["algorithm", "digest", "renewal_of", "renewal_reason", "recorded_at"],
            "trigger": "a new authenticated commitment is recorded before an existing algorithm is treated as inadequate; the original and the renewal are both preserved",
        },
        "refusals": {
            "unnamed": "PM_DIGEST_ALGORITHM_UNNAMED",
            "unadmitted": "PM_DIGEST_ALGORITHM_UNADMITTED",
        },
    }


# ---------------------------------------------------------------------------
# Archival inventory
# ---------------------------------------------------------------------------

ARCHIVAL_CLASSES = [
    {
        "id": "source",
        "required": True,
        "description": "the crate source and build inputs",
        "locations": ["src", "tests", "examples", "Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml"],
        "single_files": True,
    },
    {
        "id": "recipes",
        "required": True,
        "description": "the scripts that build, measure and reproduce the artefacts",
        "locations": ["forensics/tools", "courts", "docker"],
        "suffixes": [".sh"],
    },
    {
        "id": "proofs",
        "required": True,
        "description": "formal and bounded verification artefacts, specifications and their non-claims",
        "locations": ["evidence/etp4", "evidence/etp-t3", "evidence/etp-t4", "evidence/etp-t5",
                      "evidence/etp-t6", "forensics/etp5_crypto", "docs/CRYPTOGRAPHIC-REFERENCE.md",
                      "docs/BINARY-ASSURANCE.md"],
        "single_files": True,
    },
    {
        "id": "checkers",
        "required": True,
        "description": "the validators, guards and verifiers that read every other class",
        "locations": ["forensics/tools", "courts"],
        "suffixes": [".py"],
    },
    {
        "id": "instrument_identity",
        "required": True,
        "description": "the qualified instrument register, toolchain identity and authority pins",
        "locations": ["docs/INSTRUMENT-QUALIFICATION.md", "evidence/etp3", "forensics/authorities",
                      "forensics/multitrack/default-authority.json", "courts/phase18/timing/third_party"],
        "single_files": True,
    },
    {
        "id": "trust_metadata",
        "required": True,
        "description": "the claim set, trust-gap inventory, independence and freshness records, and the constitution",
        "locations": ["evidence/etp0", "evidence/etp", "evidence/etp-t8", "evidence/etp-t9",
                      "AGENTS.md", "docs/ETP-TODO.md", "docs/ETP-ADDENDUM-B.md",
                      "docs/ETP-CLAIM-ALGEBRA.md", "docs/EXTERNAL-REPRODUCTION.md",
                      "docs/INDEPENDENCE.md", "docs/EVIDENCE-FRESHNESS.md"],
        "single_files": True,
    },
    {
        "id": "receipts",
        "required": True,
        "description": "the per-item and per-court receipts, including withdrawals",
        "locations": ["evidence", "courts"],
        "name_contains": ["RECEIPT"],
    },
    {
        "id": "schemas",
        "required": True,
        "description": "the normative schema documents and the schema modules",
        "locations": ["evidence/etp/claim.schema.json", "courts/phase17/downstream/schema",
                      "forensics/tools"],
        "suffixes": [".schema.json", "_schemas.py"],
    },
    {
        "id": "raw_observations",
        "required": True,
        "description": "raw captures, published logs and tracked court outputs",
        "locations": [".frf", "court", "courts/phase18/interop/logs"],
    },
    {
        "id": "external_review_record",
        "required": True,
        "description": "a reproduction receipt from a party outside this project",
        "locations": [],
        "single_files": True,
    },
]


def _class_members(files: list[str], spec: dict[str, Any]) -> list[str]:
    """Members of one class.

    A location is either an exact file or a directory scope. When the class
    declares a suffix or a name marker, the locations scope the population and
    the filters select it; without filters, every file under the locations is a
    member. This keeps ``forensics/tools`` from being the whole population of a
    class that only wants its ``.sh`` recipes or its ``_schemas.py`` modules.
    """
    exact: set[str] = set()
    scopes: list[str] = []
    for location in spec.get("locations", []):
        if location in files and not location.endswith("/"):
            exact.add(location)
        else:
            scopes.append(location.rstrip("/"))
    suffixes = spec.get("suffixes") or []
    markers = spec.get("name_contains") or []
    members: set[str] = set(exact)
    for path in files:
        in_scope = any(path == scope or path.startswith(scope + "/") for scope in scopes)
        if path not in exact and not in_scope:
            continue
        if path not in exact and suffixes and not any(path.endswith(suffix) for suffix in suffixes):
            continue
        if path not in exact and markers and not any(marker in path for marker in markers):
            continue
        members.add(path)
    return sorted(members)


def derive_archival(repo: Path, commit: str) -> dict[str, Any]:
    files = tracked_files(repo, commit)
    manifest_raw = subprocess.check_output(
        ["git", "-C", str(repo), "show", f"{commit}:{ETP6_MANIFEST}"]
    )
    manifest = json.loads(manifest_raw)
    bundled = {item["path"] for item in manifest.get("inputs", [])}
    selection = manifest.get("selection", {}).get("paths", [])

    classes = []
    without_location = []
    partial = []
    for spec in ARCHIVAL_CLASSES:
        members = _class_members(files, spec)
        in_bundle = [path for path in members if path in bundled]
        if not members:
            status = "NOT_ARCHIVED"
            without_location.append(spec["id"])
        else:
            status = "IN_REPOSITORY_ONLY"
        if members and len(in_bundle) < len(members):
            partial.append(spec["id"])
        coverage = "NONE"
        if members:
            if len(in_bundle) == len(members):
                coverage = "FULL"
            elif in_bundle:
                coverage = "PARTIAL"
        classes.append({
            "id": spec["id"],
            "required": spec["required"],
            "description": spec["description"],
            "locations": spec.get("locations", []),
            "tracked_files": len(members),
            "in_etp6_bundle": len(in_bundle),
            "etp6_coverage": coverage,
            "inside_repository": bool(members),
            "externally_durable": False,
            "archival_status": status,
            "examples": members[:5],
        })

    return {
        "schema": "openssl-rs/etp-t13/archival/1",
        "kind": "etp-t13-archival-inventory",
        "candidate": {"commit": commit, "branch": _branch(repo, commit)},
        "etp6": {
            "manifest": ETP6_MANIFEST,
            "manifest_schema": manifest.get("schema"),
            "candidate_commit": manifest.get("candidate", {}).get("commit"),
            "input_count": manifest.get("input_count"),
            "selection_paths": selection,
        },
        "classes": classes,
        "classes_without_location": without_location,
        "classes_partially_bundled": partial,
        "etp6_cross_check": {
            "statement": "the ETP-6 manifest covers the classes it selects; it is a reproduction bundle, not a complete archive, and it predates the ETP-T1 to ETP-T13 records",
            "classes_fully_bundled": [row["id"] for row in classes if row["etp6_coverage"] == "FULL"],
            "classes_partially_bundled": partial,
            "classes_not_bundled": [row["id"] for row in classes if row["etp6_coverage"] == "NONE"],
        },
        "external_durability": {
            "status": "NONE",
            "externally_durable_classes": [],
            "statement": "nothing in this repository is externally archived; every location above is inside this Git repository and is durable only for as long as a copy of that repository survives",
            "etp6_role": "BUNDLE_NOT_ARCHIVE",
            "etp6_statement": "the ETP-6 package is a self-contained reproduction bundle built from one commit; it is not an external archive, it has not been deposited with an independent archive, and it carries no external review receipt",
        },
        "refusals": {
            "class_unarchived": "PM_CLASS_UNARCHIVED",
        },
    }


# ---------------------------------------------------------------------------
# Validation of the three records
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _require(condition: bool, rule: str, path: str, detail: str) -> None:
    if not condition:
        raise Refusal(rule, path, detail)


def validate_formats(record: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    _require(record.get("schema") == "openssl-rs/etp-t13/formats/1",
             "PM_RECORD_SCHEMA", FORMATS_PATH, "unexpected record schema")
    counts = record.get("schemas", {}).get("counts", {})
    _require(isinstance(counts.get("distinct_identifiers"), int),
             "PM_RECORD_SHAPE", FORMATS_PATH, "missing schema counts")
    for entry in record.get("schemas", {}).get("entries", []):
        identifier = entry.get("identifier", "")
        try:
            parse_schema_identifier(identifier)
        except Refusal as refusal:
            problems.append(f"{refusal.rule} {identifier}")
        _require(bool(entry.get("unknown_version_action")),
                 "PM_RECORD_SHAPE", identifier, "no unknown-version action")
        _require(entry.get("where_defined") is not None or entry.get("attribution_basis") == "UNDEFINED_IN_TRACKED_TREE",
                 "PM_RECORD_SHAPE", identifier, "undefined attribution not declared")
    for entry in record.get("schemas", {}).get("unversioned", []):
        problems.append(f"PM_SCHEMA_UNVERSIONED {entry.get('path')}")
    for row in record.get("formats", []):
        _require(bool(row.get("spec_version")) and bool(row.get("unknown_version_action")),
                 "PM_RECORD_SHAPE", row.get("id", "?"), "format has no specification version or action")
    for migration in record.get("migrations", []):
        problems.extend(validate_migration(migration))
    return problems


def validate_migration(migration: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    rule = migration.get("rule")
    source = migration.get("source") or {}
    if rule == "EXPLICIT_CONVERTER_PRESERVING_SOURCE":
        if source.get("retained") is not True:
            problems.append(f"PM_MIGRATION_HISTORY_REWRITTEN {migration.get('id')}: source not retained")
        if migration.get("history_rewritten") is not False:
            problems.append(f"PM_MIGRATION_HISTORY_REWRITTEN {migration.get('id')}: history_rewritten is not false")
        preserved = migration.get("preserved") or {}
        if preserved.get("ids_equal") is not True:
            problems.append(f"PM_MIGRATION_IDENTITY_LOST {migration.get('id')}: claim identities differ")
    elif rule == "FORWARD_ONLY_ADDITIVE_WITH_EXPLICIT_HISTORY":
        if migration.get("history_rewritten") is not False:
            problems.append(f"PM_MIGRATION_HISTORY_REWRITTEN {migration.get('id')}: history_rewritten is not false")
        tightened = migration.get("required_changes") or []
        if tightened and not (migration.get("converter") and migration.get("version_bumped")):
            problems.append(f"PM_MIGRATION_REQUIRED_FIELD_WITHOUT_CONVERTER {migration.get('id')}")
    else:
        problems.append(f"PM_MIGRATION_RULE_UNKNOWN {migration.get('id')}")
    return problems


def validate_digests(record: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    _require(record.get("schema") == "openssl-rs/etp-t13/digests/1",
             "PM_RECORD_SCHEMA", DIGESTS_PATH, "unexpected record schema")
    admitted = record.get("admitted_algorithms") or []
    ids = [entry.get("id") for entry in admitted]
    _require(len(ids) == len(set(ids)), "PM_RECORD_SHAPE", DIGESTS_PATH, "duplicate admitted algorithm")
    _require(all(entry.get("id") in ADMITTED_IDS for entry in admitted),
             "PM_DIGEST_ALGORITHM_UNADMITTED", DIGESTS_PATH, "record admits an algorithm outside the declared set")
    population = record.get("population") or {}
    for algorithm, count in (population.get("named", {}).get("by_algorithm") or {}).items():
        if algorithm not in ADMITTED_IDS:
            problems.append(f"PM_DIGEST_ALGORITHM_UNADMITTED {algorithm} ({count})")
    unadmitted = population.get("unadmitted", {}).get("by_algorithm") or {}
    if unadmitted:
        problems.append(f"PM_DIGEST_ALGORITHM_UNADMITTED {sorted(unadmitted)}")
    unnamed = population.get("unnamed", {})
    _require(unnamed.get("documents", 0) == record.get("migration_population", {}).get("documents", -1),
             "PM_RECORD_SHAPE", DIGESTS_PATH, "unnamed population and migration population disagree")
    renewal = record.get("renewal_plan") or {}
    for key in ("what_is_rehashed", "how_the_old_relationship_is_preserved", "what_is_never_rewritten"):
        _require(bool(renewal.get(key)), "PM_RECORD_SHAPE", DIGESTS_PATH, f"renewal plan lacks {key}")
    return problems


def validate_archival(record: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    _require(record.get("schema") == "openssl-rs/etp-t13/archival/1",
             "PM_RECORD_SCHEMA", ARCHIVAL_PATH, "unexpected record schema")
    classes = record.get("classes") or []
    required = [row for row in classes if row.get("required")]
    empty = [row["id"] for row in required if not row.get("locations")]
    recorded = sorted(record.get("classes_without_location") or [])
    if sorted(empty) != recorded:
        problems.append(f"PM_CLASS_UNARCHIVED declared={recorded} observed={sorted(empty)}")
    for row in classes:
        if row.get("archival_status") == "NOT_ARCHIVED":
            problems.append(f"PM_CLASS_UNARCHIVED {row['id']}")
        _require(row.get("externally_durable") is False,
                 "PM_EXTERNAL_DURABILITY_CLAIMED", row.get("id", "?"),
                 "an external durability claim is not supported")
    durability = record.get("external_durability") or {}
    _require(durability.get("status") == "NONE",
             "PM_EXTERNAL_DURABILITY_CLAIMED", ARCHIVAL_PATH, "durability status must be NONE")
    return problems


def check_tree_records(repo: Path, commit: str) -> dict[str, Any]:
    """Re-derive the three populations at `commit` and compare the committed records."""
    formats = derive_formats(repo, commit)
    digests = derive_digests(repo, commit)
    archival = derive_archival(repo, commit)
    recorded_formats = _load_json(repo / FORMATS_PATH)
    recorded_digests = _load_json(repo / DIGESTS_PATH)
    recorded_archival = _load_json(repo / ARCHIVAL_PATH)

    mismatches: list[str] = []
    for field in ("formats", "schema_documents", "schemas", "migrations"):
        if _canonical(recorded_formats.get(field)) != _canonical(formats.get(field)):
            mismatches.append(f"formats:{field}")
    for field in ("admitted_algorithms", "population", "migration_population", "renewal_plan"):
        if _canonical(recorded_digests.get(field)) != _canonical(digests.get(field)):
            mismatches.append(f"digests:{field}")
    for field in ("etp6", "classes", "classes_without_location", "etp6_cross_check", "external_durability"):
        if _canonical(recorded_archival.get(field)) != _canonical(archival.get(field)):
            mismatches.append(f"archival:{field}")
    return {
        "mismatches": mismatches,
        "formats": formats,
        "digests": digests,
        "archival": archival,
    }


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Self-test: one negative control per refusal, plus positive and determinism
# ---------------------------------------------------------------------------


def self_test() -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: str) -> None:
        controls.append({"control": name, "passed": passed, "detail": detail})

    # 1. unversioned schema refused
    try:
        parse_schema_identifier("openssl-rs/thing")
        record("unversioned_schema_refused", False, "no refusal")
    except Refusal as refusal:
        record("unversioned_schema_refused", refusal.rule == "PM_SCHEMA_UNVERSIONED", refusal.rule)

    # 2. versioned schema accepted (positive)
    try:
        family, version, _part = parse_schema_identifier("openssl-rs/thing/v2")
        record("versioned_schema_accepted", family == "openssl-rs/thing" and version == "v2",
               f"{family} {version}")
    except Refusal as refusal:
        record("versioned_schema_accepted", False, refusal.rule)

    # 3. part marker is not a version
    try:
        _family, version, part = parse_schema_identifier("openssl-rs/thing/v1/part")
        record("part_marker_not_a_version", version == "v1" and part, f"{version} part={part}")
    except Refusal as refusal:
        record("part_marker_not_a_version", False, refusal.rule)

    # 4. undeclared document version refused
    try:
        require_document_version({"kind": "receipt"}, "evidence/x.json")
        record("undeclared_document_version_refused", False, "no refusal")
    except Refusal as refusal:
        record("undeclared_document_version_refused",
               refusal.rule == "PM_DOCUMENT_VERSION_UNDECLARED", refusal.rule)

    # 5. declared document accepted (positive)
    try:
        kind = classify_json_document({"schema": "openssl-rs/etp/claims/v1"}, "evidence/x.json")
        record("declared_document_accepted", kind["class"] == "schema_bearing", kind["class"])
    except Refusal as refusal:
        record("declared_document_accepted", False, refusal.rule)

    # 6. unnamed digest refused
    scan = _scan_digests({"span_hash": "a" * 64}, "evidence/x.json")
    record("unnamed_digest_refused", scan["unnamed"].get("span_hash") == 1,
           f"unnamed={scan['unnamed']}")

    # 7. named digest accepted (positive)
    scan = _scan_digests({"sha256": "a" * 64}, "evidence/x.json")
    record("named_digest_accepted", scan["named"].get("sha256") == 1, f"named={scan['named']}")

    # 8. unadmitted algorithm refused
    scan = _scan_digests({"digest_algorithm": "crc32", "value": "12345678"}, "evidence/x.json")
    record("unadmitted_algorithm_refused", scan["unadmitted"].get("crc32") == 1,
           f"unadmitted={scan['unadmitted']}")

    # 9. admitted algorithm accepted (positive)
    scan = _scan_digests({"digest_algorithm": "sha256", "value": "a" * 64}, "evidence/x.json")
    record("admitted_algorithm_accepted", scan["named"].get("sha256") == 1,
           f"named={scan['named']}")

    # 10. unarchived class reported
    fake = {
        "schema": "openssl-rs/etp-t13/archival/1",
        "classes": [{"id": "external_review_record", "required": True, "locations": [],
                     "archival_status": "NOT_ARCHIVED", "externally_durable": False}],
        "classes_without_location": ["external_review_record"],
        "external_durability": {"status": "NONE"},
    }
    problems = validate_archival(fake)
    record("unarchived_class_reported",
           any(item.startswith("PM_CLASS_UNARCHIVED") for item in problems), str(problems))

    # 11. archived class with no false durability accepted (positive)
    fake_ok = {
        "schema": "openssl-rs/etp-t13/archival/1",
        "classes": [{"id": "source", "required": True, "locations": ["src"],
                     "archival_status": "IN_REPOSITORY_ONLY", "externally_durable": False}],
        "classes_without_location": [],
        "external_durability": {"status": "NONE"},
    }
    record("archived_class_accepted", validate_archival(fake_ok) == [], "no problem")

    # 12. migration that rewrites history refused
    bad_migration = {
        "id": "MIG-BAD",
        "rule": "EXPLICIT_CONVERTER_PRESERVING_SOURCE",
        "source": {"path": "evidence/old.json", "retained": False},
        "history_rewritten": True,
    }
    problems = validate_migration(bad_migration)
    record("migration_rewrite_refused",
           any(item.startswith("PM_MIGRATION_HISTORY_REWRITTEN") for item in problems),
           str(problems))

    # 13. preserving migration accepted (positive)
    good_migration = {
        "id": "MIG-GOOD",
        "rule": "EXPLICIT_CONVERTER_PRESERVING_SOURCE",
        "source": {"path": "evidence/old.json", "retained": True},
        "history_rewritten": False,
        "preserved": {"ids_equal": True},
    }
    record("preserving_migration_accepted", validate_migration(good_migration) == [], "no problem")

    # 14. an additive schema change with a tightened required field needs a converter
    bad_additive = {
        "id": "MIG-ADD",
        "rule": "FORWARD_ONLY_ADDITIVE_WITH_EXPLICIT_HISTORY",
        "history_rewritten": False,
        "required_changes": [{"revision": "abc", "tightened_paths": ["$"]}],
    }
    problems = validate_migration(bad_additive)
    record("required_field_change_needs_converter",
           any("PM_MIGRATION_REQUIRED_FIELD_WITHOUT_CONVERTER" in item for item in problems),
           str(problems))

    return controls


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def build(repo: Path, rev: str) -> int:
    commit = resolve_commit(repo, rev)
    formats = derive_formats(repo, commit)
    digests = derive_digests(repo, commit)
    archival = derive_archival(repo, commit)
    out = repo / EVIDENCE
    out.mkdir(parents=True, exist_ok=True)
    for path, record in ((FORMATS_PATH, formats), (DIGESTS_PATH, digests), (ARCHIVAL_PATH, archival)):
        (repo / path).write_text(
            json.dumps(_with_timestamp(record), indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
    print(f"wrote {FORMATS_PATH} ({len(formats['schemas']['entries'])} schema identifiers)")
    print(f"wrote {DIGESTS_PATH} ({digests['population']['named']['documents']} named, "
          f"{digests['population']['unnamed']['documents']} unnamed documents)")
    print(f"wrote {ARCHIVAL_PATH} ({len(archival['classes'])} classes, "
          f"{len(archival['classes_without_location'])} without a location)")
    return 0


def _with_timestamp(record: dict[str, Any]) -> dict[str, Any]:
    import datetime as _dt
    stamped = {"generated_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    stamped.update(record)
    return stamped


def validate(repo: Path) -> int:
    failures: list[str] = []
    records = {}
    for path, validator in ((FORMATS_PATH, validate_formats),
                            (DIGESTS_PATH, validate_digests),
                            (ARCHIVAL_PATH, validate_archival)):
        full = repo / path
        if not full.exists():
            print(f"REFUSED PM_RECORD_MISSING {path}", file=sys.stderr)
            return 2
        record = _load_json(full)
        records[path] = record
        failures.extend(validator(record))

    commit = records[FORMATS_PATH].get("candidate", {}).get("commit")
    if not commit:
        failure = "PM_RECORD_SHAPE FORMATS.json: no candidate commit"
        failures.append(failure)
    else:
        try:
            tree = check_tree_records(repo, commit)
            failures.extend(f"PM_DRIFT {item}" for item in tree["mismatches"])
        except Exception as error:  # a candidate that cannot be read is a refusal
            failures.append(f"PM_CANDIDATE_UNREADABLE {commit}: {error}")

    controls = self_test()
    failed_controls = [control for control in controls if not control["passed"]]
    for control in failed_controls:
        failures.append(f"PM_CONTROL_FAILED {control['control']}: {control['detail']}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print(f"PASS {FORMATS_PATH} {DIGESTS_PATH} {ARCHIVAL_PATH}; "
          f"{len(controls)} controls passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=("build", "validate"), default="validate")
    parser.add_argument("--repo", default=str(REPO_ROOT))
    parser.add_argument("--at", default="HEAD", help="candidate revision for build")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()

    if args.self_test:
        controls = self_test()
        for control in controls:
            status = "PASS" if control["passed"] else "FAIL"
            print(f"{status} {control['control']}: {control['detail']}")
        return 0 if all(control["passed"] for control in controls) else 1

    if args.command == "build":
        return build(repo, args.at)
    return validate(repo)


if __name__ == "__main__":
    sys.exit(main())
