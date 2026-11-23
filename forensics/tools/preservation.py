#!/usr/bin/env python3
"""preservation.py -- ETP-T13 long-term preservation, validation and controls.

What this tool decides
----------------------
Four machine-readable records describe what a third party would need to keep
verifying this programme after the authors are gone:

* ``evidence/etp-t13/IDENTITY-SYSTEMS.json`` -- the four identity systems kept
  apart: repository object identity (read from the repository's object format),
  content digests over bytes, signature and attestation algorithms (absent), and
  digest renewal (a new binding that preserves the old one);
* ``evidence/etp-t13/FORMATS.json`` -- the tracked encodings and schema
  identifiers, their versions, where each is defined, which tool reads it, what
  a reader must do when the version is unknown, and a reader that accepts two
  versions of one schema family and refuses an unknown one;
* ``evidence/etp-t13/DIGESTS.json`` -- the admitted digest algorithms, the
  measured named/unnamed populations, the repository object ids that are *not*
  content digests, and a renewal record whose old and new bindings cover the
  same archived bytes;
* ``evidence/etp-t13/ARCHIVAL.json`` -- the artefact classes, where each is
  archived, whether that location is inside this repository, whether it is
  externally durable, the archive corruption controls, and what a third party
  needs to rebuild the verifier itself.

The records are *derived* from a frozen candidate commit (``git cat-file`` over
that commit's blobs, never from an untracked working tree), so an evidence
commit that adds these very files cannot silently change the population they
describe. ``generated_utc`` is the candidate's committer timestamp, not a
wall-clock reading, so two builds over the same candidate are byte-identical.

Separate identity systems
-------------------------
Git object ids in this repository are 40 hexadecimal characters because the
configured object format is ``sha1``. SHA-256 is used for content, evidence and
package digests. The object id of a blob is computed over the repository's
object header plus the bytes; a SHA-256 content digest is computed over the raw
bytes alone. They identify the same bytes and are never interchangeable, and a
record that names an object format different from the one the repository
reports is refused (``PM_IDENTITY_OBJECT_FORMAT_MISMATCH``).

What passing means
------------------
``validate`` exits 0 when the four committed records match a fresh derivation
at their named candidate and every control fires. It does **not** claim that the
populations are empty or that preservation is achieved: unnamed digests,
undeclared evidence records, unversioned schema definitions and an unarchived
required class are recorded as live populations. ``validate --strict`` converts
those recorded populations into refusals and exits 1; the refusal is the honest
result for anyone who requires a clean population.

Refusals, each with a control
-----------------------------
* ``PM_SCHEMA_UNVERSIONED`` -- a schema identifier without a version suffix.
* ``PM_DOCUMENT_VERSION_UNDECLARED`` -- an evidence document with no ``schema``.
* ``PM_DIGEST_ALGORITHM_UNNAMED`` -- a digest with no stated algorithm.
* ``PM_DIGEST_ALGORITHM_UNADMITTED`` -- a digest whose stated algorithm is not
  in the admitted set.
* ``PM_CLASS_UNARCHIVED`` -- a required class with no archival location.
* ``PM_EXTERNAL_DURABILITY_CLAIMED`` -- an archival record that claims external
  durability this repository cannot evidence.
* ``PM_MIGRATION_HISTORY_REWRITTEN`` -- a migration that does not retain its
  source or that reports rewritten history.
* ``PM_MIGRATION_IDENTITY_LOST`` -- a converter that dropped claim identities.
* ``PM_MIGRATION_REQUIRED_FIELD_WITHOUT_CONVERTER`` -- a required-field addition
  with no converter, no version bump and no demonstration that the retained
  documents are still accepted.
* ``PM_IDENTITY_OBJECT_FORMAT_MISMATCH`` -- a record names a repository object
  format or object-id length that the repository does not report.
* ``PM_IDENTITY_OBJECT_FORMAT_UNKNOWN`` -- the repository reports an object
  format this tool does not know how to interpret.
* ``PM_IDENTITY_CONFLATION`` -- a record presents an object id as a content
  digest, a content digest as an object id, or names one system's algorithm for
  the other.
* ``PM_SIGNATURE_ALGORITHM_CLAIMED`` -- a record claims a signature or
  attestation algorithm where no signature or attestation exists.
* ``PM_RENEWAL_BYTES_CHANGED`` -- a renewal record's old or new digest does not
  cover the archived bytes it names.
* ``PM_SCHEMA_UNKNOWN_VERSION`` -- a reader meets a version of a known schema
  family that it does not know; the version is not reinterpreted as its nearest
  known neighbour.
* ``PM_ARCHIVE_TRUNCATED``, ``PM_ARCHIVE_MEMBER_DIGEST``,
  ``PM_ARCHIVE_MEMBER_MISSING``, ``PM_ARCHIVE_MEMBER_UNLISTED`` -- the archive
  controls: an unreadable archive, a member whose bytes disagree with the
  manifest, a manifest member absent from the archive, and an archived member
  the manifest does not list.

Exit contract
-------------
    0  the selected operation succeeded and every control passed
    1  a refusal, a drift between a record and the tree, or a failed control
    2  the invocation was refused (missing record, unreadable candidate)

Usage
-----
    python3 forensics/tools/preservation.py build [--at REV]
    python3 forensics/tools/preservation.py validate [--strict]
    python3 forensics/tools/preservation.py status CLASS
    python3 forensics/tools/preservation.py archive-check PATH MANIFEST
    python3 forensics/tools/preservation.py --self-test
    python3 forensics/tools/preservation.py --determinism

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import datetime as _dt
import gzip
import hashlib
import io
import json
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path
from typing import Any, Callable, Iterable

TOOLS = Path(__file__).resolve().parent
REPO_ROOT = TOOLS.parents[1]
EVIDENCE = "evidence/etp-t13"
FORMATS_PATH = f"{EVIDENCE}/FORMATS.json"
DIGESTS_PATH = f"{EVIDENCE}/DIGESTS.json"
ARCHIVAL_PATH = f"{EVIDENCE}/ARCHIVAL.json"
IDENTITY_PATH = f"{EVIDENCE}/IDENTITY-SYSTEMS.json"
CLAIM_SCHEMA = "evidence/etp/claim.schema.json"
ETP0_CLAIMS = "evidence/etp0/CLAIMS.json"
ETP1_CLAIMS = "evidence/etp/claims.json"
ETP6_MANIFEST = "evidence/etp6/MANIFEST.json"
CLAIMS_IDENTIFIER = "openssl-rs/etp/claims/v1"
TOOL_PATH = "forensics/tools/preservation.py"
ETP6_VERIFIER = "forensics/tools/etp6_verify.py"
ETP6_ENTRY = "forensics/etp6/verify.sh"

VERSION_RE = re.compile(r"^(?P<family>.+?)/(?P<version>v\d+(?:\.\d+)?|\d+)(?P<part>/part)?$")
HEX_DIGEST_RE = re.compile(
    r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{56}$|"
    r"^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{96}$|^[0-9a-fA-F]{128}$"
)
FILE_EXTENSION_RE = re.compile(r"\.[A-Za-z0-9]{1,8}$")

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
_NORMALISED_ALGORITHM = {
    re.sub(r"[^a-z0-9]", "", name): name for name in ALGORITHM_LENGTHS
}

# One left-to-right alternation, longest name first, reproduces "the longest
# algorithm name present in the key" without running one regular expression per
# algorithm per key. The object-identity system has its own identifiers and is
# deliberately not part of this table.
ALGORITHM_ALTERNATION_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    + "|".join(re.escape(name) for name in
              sorted(ALGORITHM_LENGTHS, key=len, reverse=True))
    + r")(?![a-z0-9])"
)

# Repository object identity is a distinct system. The format is read from the
# repository (``git rev-parse --show-object-format``), never inferred from a
# digest length, and a record that names a different format is refused.
OBJECT_FORMATS = {
    "sha1": {"oid_hex_length": 40},
    "sha256": {"oid_hex_length": 64},
}
OBJECT_IDENTITY_KEYS = {
    "commit", "commit_id", "commit_sha", "tree", "oid", "object_id",
    "git_oid", "parent_commit", "base_commit", "head", "head_sha",
    "source_commit", "candidate_commit", "frozen_source_commit",
    "bound_commit", "revision", "rev",
}
OBJECT_ID_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")

# Hashlib names for the admitted digest algorithms that this interpreter can
# compute. SHA-3 and BLAKE2 names are spelled with an underscore in hashlib.
HASHLIB_NAMES = {
    "md5": "md5",
    "sha1": "sha1",
    "sha224": "sha224",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
    "sha3_224": "sha3_224",
    "sha3_256": "sha3_256",
    "sha3_384": "sha3_384",
    "sha3_512": "sha3_512",
    "blake2s": "blake2s",
    "blake2b": "blake2b",
}

# The admitted set. Admission is about whether an algorithm may carry a recorded
# relationship at all; it is not a claim that every admitted algorithm is
# adequate for a new security commitment.
ADMITTED_ALGORITHMS = [
    {
        "id": "sha256",
        "status": "ADMITTED",
        "renewal_priority": "PRIMARY",
        "rationale": "the content digest used by the package manifest, the receipts and every evidence record that hashes bytes; it is not a repository object id and is not the object-id algorithm",
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
CONSTANT_KEY_RE = re.compile(r"LENGTH|SIZE|COUNT|NID|NAME|BLOCK|OFFSET")
ABSENT_MARKERS = {"UNRESOLVED", "NOT_APPLICABLE", "NOT_RUN", "N/A", "NA", "NONE",
                  "UNKNOWN", "TBD", "ABSENT"}

# The admission rules this tool enforces. Each one has at least one named
# control in ``self_test``; the meta-control refuses a rule with no control.
ADMISSION_RULES = [
    "PM_SCHEMA_UNVERSIONED",
    "PM_DOCUMENT_VERSION_UNDECLARED",
    "PM_DIGEST_ALGORITHM_UNNAMED",
    "PM_DIGEST_ALGORITHM_UNADMITTED",
    "PM_CLASS_UNARCHIVED",
    "PM_EXTERNAL_DURABILITY_CLAIMED",
    "PM_MIGRATION_HISTORY_REWRITTEN",
    "PM_MIGRATION_IDENTITY_LOST",
    "PM_MIGRATION_REQUIRED_FIELD_WITHOUT_CONVERTER",
    "PM_IDENTITY_OBJECT_FORMAT_MISMATCH",
    "PM_IDENTITY_OBJECT_FORMAT_UNKNOWN",
    "PM_IDENTITY_CONFLATION",
    "PM_SIGNATURE_ALGORITHM_CLAIMED",
    "PM_RENEWAL_BYTES_CHANGED",
    "PM_SCHEMA_UNKNOWN_VERSION",
    "PM_ARCHIVE_TRUNCATED",
    "PM_ARCHIVE_MEMBER_DIGEST",
    "PM_ARCHIVE_MEMBER_MISSING",
    "PM_ARCHIVE_MEMBER_UNLISTED",
]

MIGRATION_RULES = {
    "EXPLICIT_CONVERTER_PRESERVING_SOURCE": (
        "a converter produces a new document under a new schema; the source "
        "document is retained byte-for-byte and the target names the source digest"
    ),
    "FORWARD_ONLY_WITH_EXPLICIT_HISTORY": (
        "every revision is retained in Git and reachable; a required-field "
        "addition needs either a converter with a version bump or a demonstration "
        "that every retained document is still accepted by the new schema"
    ),
}


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


def _git_bytes(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def resolve_commit(repo: Path, rev: str) -> str:
    return _git(repo, "rev-parse", rev).strip()


def repository_object_format(repo: Path) -> str:
    """The object-id algorithm the repository is configured to use.

    Read from Git, never inferred from a digest length. An unrecognised format
    is refused rather than assigned a default.
    """
    raw = _git(repo, "rev-parse", "--show-object-format").strip()
    if raw not in OBJECT_FORMATS:
        raise Refusal(
            "PM_IDENTITY_OBJECT_FORMAT_UNKNOWN",
            "repository",
            f"git reports object format {raw!r}; known formats are "
            f"{sorted(OBJECT_FORMATS)}",
        )
    return raw


def commit_metadata(repo: Path, commit: str) -> dict[str, Any]:
    """The identity and the deterministic timestamp a record is built from.

    ``object_format`` and ``object_id_hex_length`` describe the *repository*
    identity system. They are not content-digest fields.
    """
    tree = _git(repo, "rev-parse", f"{commit}^{{tree}}").strip()
    committer = _git(repo, "show", "-s", "--format=%cI", commit).strip()
    stamp = _dt.datetime.fromisoformat(committer).astimezone(_dt.timezone.utc)
    fmt = repository_object_format(repo)
    expected = OBJECT_FORMATS[fmt]["oid_hex_length"]
    if len(commit) != expected:
        raise Refusal(
            "PM_IDENTITY_OBJECT_FORMAT_MISMATCH",
            commit,
            f"the object format is {fmt}, whose ids are {expected} hexadecimal "
            f"characters, but this id is {len(commit)}",
        )
    return {
        "commit": commit,
        "tree": tree,
        "committer_time_utc": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "object_format": fmt,
        "object_id_algorithm": fmt,
        "object_id_hex_length": expected,
        "identity_system": "repository_object_identity",
    }


def require_object_format(record: dict[str, Any], observed: str) -> None:
    """Refuse a record whose object-identity claim disagrees with the repository.

    A record may carry a commit (object identity), a content digest, or both.
    Only the object-identity fields are checked here; a content digest is a
    different system with its own naming rule and is never compared to the
    object format.
    """
    declared = record.get("object_format")
    if declared is None:
        raise Refusal(
            "PM_IDENTITY_OBJECT_FORMAT_MISMATCH",
            str(record.get("commit", "record")),
            "the record states no repository object format and cannot be placed "
            "in the repository-identity system",
        )
    if declared not in OBJECT_FORMATS:
        raise Refusal("PM_IDENTITY_OBJECT_FORMAT_UNKNOWN", str(declared),
                      "the record names an object format this tool does not know")
    if declared != observed:
        raise Refusal(
            "PM_IDENTITY_OBJECT_FORMAT_MISMATCH",
            str(record.get("commit", "record")),
            f"the record names object format {declared!r} but the repository "
            f"reports {observed!r}; an object id from one format does not name "
            f"an object in the other",
        )
    expected = OBJECT_FORMATS[observed]["oid_hex_length"]
    stated = record.get("object_id_hex_length")
    if stated is not None and stated != expected:
        raise Refusal(
            "PM_IDENTITY_OBJECT_FORMAT_MISMATCH",
            str(record.get("commit", "record")),
            f"the record states {stated} hexadecimal object-id characters; "
            f"format {observed!r} uses {expected}",
        )
    commit = record.get("commit")
    if isinstance(commit, str) and len(commit) != expected:
        raise Refusal(
            "PM_IDENTITY_OBJECT_FORMAT_MISMATCH",
            commit,
            f"the object id is {len(commit)} hexadecimal characters; format "
            f"{observed!r} uses {expected}",
        )


def refuse_conflation(record: dict[str, Any],
                      observed_object_format: str | None = None) -> None:
    """Refuse a record that merges the object-identity and content-digest systems.

    A field that names the object-id algorithm while the repository reports a
    different object format is applying a content-digest name to object identity:
    ``sha256`` is both a content-digest name and a possible object format, so the
    name alone cannot be judged, and only the observed format can.
    """
    algorithm = record.get("object_id_algorithm")
    if algorithm is not None:
        if algorithm not in OBJECT_FORMATS:
            raise Refusal(
                "PM_IDENTITY_CONFLATION", str(algorithm),
                "the object-id algorithm is not an object format this tool knows; "
                "it is a content-digest name applied to object identity",
            )
        if observed_object_format and algorithm != observed_object_format:
            raise Refusal(
                "PM_IDENTITY_CONFLATION", str(algorithm),
                f"the record names {algorithm!r} as the object-id algorithm while "
                f"the repository reports {observed_object_format!r}; the object-id "
                f"algorithm is the repository object format, not a chosen digest",
            )
    if record.get("identity_system") == "repository_object_identity" \
            and record.get("digest_algorithm") in ADMITTED_IDS:
        raise Refusal(
            "PM_IDENTITY_CONFLATION", str(record.get("digest_algorithm")),
            "a repository-identity record names a content-digest algorithm as its identity",
        )


def digest_bytes(algorithm: str, raw: bytes) -> str:
    """Compute one admitted content digest over ``raw`` bytes."""
    canonical = require_digest_algorithm(algorithm)
    name = HASHLIB_NAMES.get(canonical)
    if name is None:
        raise Refusal("PM_DIGEST_ALGORITHM_UNADMITTED", canonical,
                      "this interpreter cannot compute the algorithm, so a "
                      "renewal over it is not demonstrated")
    return hashlib.new(name, raw).hexdigest()


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


def blob_sha256(repo: Path, commit: str, path: str) -> str:
    raw = _git_bytes(repo, "show", f"{commit}:{path}")
    return hashlib.sha256(raw).hexdigest()


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

    Returns ``schema_bearing``, ``schema_document`` or ``data``. A schema-bearing
    document must declare a versioned identifier, so the version check is applied
    here rather than left to the caller.
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
    """The tracked tool and shell text, used for literal attribution."""
    tools = [p for p in files if p.endswith(".py") or p.endswith(".sh")]
    blobs = read_blobs(repo, commit, tools)
    return {path: raw.decode("utf-8", "replace") for path, raw in blobs.items()}


def _contains(texts: dict[str, str], needle: str) -> list[str]:
    return sorted(path for path, text in texts.items() if needle in text)


def _prefer_reader(candidates: list[str], texts: dict[str, str]) -> str | None:
    """Prefer a validator over a producer when both contain the literal."""
    validators = [
        path for path in candidates
        if "check_schema" in texts[path] or "validate" in texts[path]
    ]
    return (validators or candidates or [None])[0]


def attribute_schema(identifier: str, texts: dict[str, str]) -> dict[str, Any]:
    """Attribute one schema identifier to its defining tool and its readers.

    Attribution is deliberately conservative: an exact literal wins, then the
    version-stripped family, then the atlas envelope/generator, then a literal
    prefix of at least two path components. Anything else is reported as
    undefined in the tracked tree rather than guessed.
    """
    exact = _contains(texts, identifier)
    if exact:
        return {"where_defined": exact[0], "reader": _prefer_reader(exact, texts),
                "readers": exact[:5], "basis": "TOOL_LITERAL"}

    family, _version, _part = parse_schema_identifier(identifier)
    family_hits = _contains(texts, family)
    if family_hits:
        return {"where_defined": family_hits[0], "reader": _prefer_reader(family_hits, texts),
                "readers": family_hits[:5], "basis": "TOOL_FAMILY_LITERAL"}

    atlas = re.match(r"^openssl-rs/atlas/(?P<kind>[^/]+)/v\d+(?:\.\d+)?$", identifier)
    if atlas:
        kind = atlas.group("kind")
        generators = _contains(texts, f'kind="{kind}"') + _contains(texts, f"kind='{kind}'")
        if generators:
            reader = sorted(set(generators))[0]
            return {"where_defined": "forensics/tools/atlas_common.py", "reader": reader,
                    "readers": [reader], "basis": "ATLAS_ENVELOPE_WITH_GENERATOR"}
        return {"where_defined": "forensics/tools/atlas_common.py",
                "reader": "forensics/tools/atlas_common.py",
                "readers": ["forensics/tools/atlas_common.py"], "basis": "ATLAS_ENVELOPE"}

    parts = family.split("/")
    for width in range(len(parts) - 1, 1, -1):
        prefix = "/".join(parts[:width])
        hits = _contains(texts, prefix)
        if hits:
            return {"where_defined": hits[0], "reader": _prefer_reader(hits, texts),
                    "readers": hits[:5], "basis": f"PREFIX_LITERAL:{prefix}"}

    return {"where_defined": None, "reader": None, "readers": [],
            "basis": "UNDEFINED_IN_TRACKED_TREE"}


def find_code_schema_modules(files: list[str], texts: dict[str, str]) -> list[dict[str, Any]]:
    """Modules that define a schema registry in code.

    The census is bounded by an explicit shape: a tracked ``.py`` file with a
    top-level ``SCHEMAS = {`` dictionary literal. Helper modules that merely
    alias the path to such a module are not registries and are excluded.
    """
    out = []
    for path in sorted(texts):
        if not path.endswith(".py"):
            continue
        if not any(line.startswith("SCHEMAS = {") for line in texts[path].splitlines()):
            continue
        importers = [
            other for other in sorted(texts)
            if other != path
            and re.search(rf"^\s*(?:from|import)\s+{re.escape(Path(path).stem)}\b",
                          texts[other], re.MULTILINE)
        ]
        out.append({
            "path": path,
            "defines": "a SCHEMAS dictionary of record-kind validators",
            "identifier": None,
            "version": None,
            "version_basis": "NO_SCHEMA_VERSION_IDENTIFIER_IN_MODULE",
            "readers": importers[:5],
            "reader": importers[0] if importers else None,
            "unknown_version_action": "REFUSE_VALIDATE",
        })
    return out


# ---------------------------------------------------------------------------
# Cross-version reader: two versions of one family, unknown version refused
# ---------------------------------------------------------------------------

CROSS_VERSION_FAMILY = "openssl-rs/campaign/safe-c33/consumer-closure"


def _read_consumer_closure_v1(doc: dict[str, Any], path: str) -> dict[str, Any]:
    """v1 is the flat closure record: closure, compatibility and verdict."""
    for field in ("family", "source_identity", "verdict"):
        if field not in doc:
            raise Refusal("PM_SCHEMA_VERSION_SHAPE", path,
                          f"a v1 record must carry {field!r}")
    closure = doc.get("closure") or {}
    return {"version": "v1", "family": doc.get("family"),
            "shape": "flat-closure", "verdict": doc.get("verdict"),
            "closure_keys": sorted(closure)[:8] if isinstance(closure, dict) else []}


def _read_consumer_closure_v2(doc: dict[str, Any], path: str) -> dict[str, Any]:
    """v2 is the graph record: graph, precision, refusals and mode."""
    for field in ("family", "graph", "precision", "refusals"):
        if field not in doc:
            raise Refusal("PM_SCHEMA_VERSION_SHAPE", path,
                          f"a v2 record must carry {field!r}")
    graph = doc.get("graph") or {}
    return {"version": "v2", "family": doc.get("family"),
            "shape": "graph", "mode": doc.get("mode"),
            "graph_keys": sorted(graph)[:8] if isinstance(graph, dict) else []}


CROSS_VERSION_READERS: dict[str, dict[str, Any]] = {
    CROSS_VERSION_FAMILY: {
        "versions": {"v1": _read_consumer_closure_v1, "v2": _read_consumer_closure_v2},
        "description": ("one family with two in-tree versions and two shapes; the reader "
                        "dispatches on the exact version"),
        "history": ("v2 replaced v1's flat closure record with a graph record; no v1 "
                    "document was edited and both remain tracked"),
    },
}


def read_versioned_document(doc: Any, path: str) -> dict[str, Any]:
    """Dispatch on an exact known version, or refuse an unknown one.

    An unknown version is never interpreted as its nearest known neighbour: a
    versioned identifier is a different type, and the refusal names the versions
    that are understood.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("schema"), str):
        raise Refusal("PM_DOCUMENT_VERSION_UNDECLARED", path,
                      "the document declares no schema identifier")
    identifier = doc["schema"]
    family, version, _part = parse_schema_identifier(identifier)
    entry = CROSS_VERSION_READERS.get(family)
    if entry is None:
        raise Refusal("PM_SCHEMA_FAMILY_UNKNOWN", identifier,
                      "no cross-version reader is registered for this family")
    reader = entry["versions"].get(version)
    if reader is None:
        raise Refusal(
            "PM_SCHEMA_UNKNOWN_VERSION", identifier,
            f"understood versions are {sorted(entry['versions'])}; an unknown "
            f"version is refused rather than read as the nearest known one",
        )
    result = reader(doc, path)
    result["identifier"] = identifier
    return result


def cross_version_demonstration(repo: Path, commit: str,
                              population: dict[str, int],
                              examples: dict[str, str],
                              accepted: list[dict[str, Any]]) -> dict[str, Any]:
    """Read one tracked document per version and refuse an unknown version.

    ``population``, ``examples`` and ``accepted`` are accumulated during the
    format-registry pass, which keeps the family from being read a second time.
    Only one document per version is retained as a path; the probe re-reads it,
    so a family with hundreds of large records does not sit in memory.
    """
    unknown_refusal: dict[str, Any] = {"rule": "PM_SCHEMA_UNKNOWN_VERSION",
                                        "demonstrated": False}
    if examples:
        first_version = sorted(examples)[0]
        sample = _load_blob_json(repo, f"{commit}:{examples[first_version]}")
        probe = dict(sample)
        probe["schema"] = f"{CROSS_VERSION_FAMILY}/v999"
        try:
            read_versioned_document(probe, examples[first_version])
        except Refusal as refusal:
            unknown_refusal = {"rule": refusal.rule,
                               "demonstrated": refusal.rule == "PM_SCHEMA_UNKNOWN_VERSION",
                               "probe_identifier": probe["schema"]}

    return {
        "family": CROSS_VERSION_FAMILY,
        "known_versions": sorted(CROSS_VERSION_READERS[CROSS_VERSION_FAMILY]["versions"]),
        "version_population": dict(sorted(population.items())),
        "reader_path": "forensics/tools/preservation.py",
        "reader": "read_versioned_document",
        "accepted_examples": accepted,
        "unknown_version_refusal": unknown_refusal,
        "history": CROSS_VERSION_READERS[CROSS_VERSION_FAMILY]["history"],
        "statement": ("both tracked versions are read by a shape-aware reader; a version "
                      "the reader does not know is refused with PM_SCHEMA_UNKNOWN_VERSION "
                      "and is never reinterpreted as v1 or v2"),
    }


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
        "reader": "forensics/tools/etp_claims.py (self-contained subset checker) for the claim schema",
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

UNKNOWN_VERSION_ACTIONS = {
    "REFUSE_DECODE": "stop with an error naming the document and the unrecognised version; do not fall back to a lenient parser",
    "REFUSE_VALIDATE": "stop with an error naming the identifier and version; do not validate against an older or newer revision",
    "REFUSE_INTERPRET": "stop with an error naming the identifier; do not interpret the fields under an assumed shape",
    "REFUSE_RENDER": "do not render; the artefact is presentation and carries no evidence obligation",
}


def count_extension(files: list[str], *suffixes: str) -> int:
    return sum(1 for path in files if path.endswith(suffixes))


def derive_formats(repo: Path, commit: str) -> dict[str, Any]:
    files = tracked_files(repo, commit)
    json_files = [path for path in files if path.endswith(".json")]
    texts = load_tool_text(repo, commit, files)

    entries: dict[str, dict[str, Any]] = {}
    unversioned: list[dict[str, str]] = []
    unversioned_identifiers: set[str] = set()
    schema_documents: list[dict[str, Any]] = []
    unversioned_schema_documents: list[dict[str, Any]] = []
    non_schema: dict[str, list[str]] = {}
    parseable = 0
    unparseable: list[str] = []
    cross_population: dict[str, int] = {}
    cross_examples: dict[str, str] = {}
    cross_accepted: list[dict[str, Any]] = []

    for path, raw in iter_blobs(repo, commit, json_files):
        try:
            doc = json.loads(raw)
        except Exception:
            unparseable.append(path)
            continue
        parseable += 1
        try:
            kind = classify_json_document(doc, path)
        except Refusal as refusal:
            identifier = doc.get("schema", "") if isinstance(doc, dict) else ""
            unversioned.append({"path": path, "identifier": identifier,
                                "rule": refusal.rule, "detail": refusal.detail})
            unversioned_identifiers.add(identifier)
            continue
        if kind["class"] == "schema_bearing":
            identifier = kind["identifier"]
            family, version, part = parse_schema_identifier(identifier)
            if family == CROSS_VERSION_FAMILY:
                cross_population[version] = cross_population.get(version, 0) + 1
                if version not in cross_examples:
                    cross_examples[version] = path
                    try:
                        read = read_versioned_document(doc, path)
                        cross_accepted.append({"path": path,
                                               "version": read["version"],
                                               "shape": read["shape"]})
                    except Refusal as refusal:
                        cross_accepted.append({"path": path, "version": version,
                                               "refusal": refusal.rule})
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
            row = {
                "path": path,
                "id": doc.get("$id", "") if isinstance(doc, dict) else "",
                "spec": doc.get("$schema", "") if isinstance(doc, dict) else "",
                "defines": defined,
                "reader": _schema_document_reader(defined, path, texts),
            }
            try:
                _family, version, _part = parse_schema_identifier(defined)
                row["version"] = version
                row["version_basis"] = "DECLARED_IDENTIFIER"
            except Refusal:
                row["version"] = None
                row["version_basis"] = "NO_VERSIONED_IDENTIFIER"
                row["rule"] = "PM_SCHEMA_UNVERSIONED"
                unversioned_schema_documents.append({"path": path, "identifier": defined,
                                                     "rule": "PM_SCHEMA_UNVERSIONED",
                                                     "detail": "the schema document's $id has no version suffix"})
            schema_documents.append(row)
        else:
            non_schema.setdefault(non_schema_class(path), []).append(path)

    for identifier, entry in entries.items():
        attribution = attribute_schema(identifier, texts)
        entry["where_defined"] = attribution["where_defined"]
        entry["reader"] = attribution["reader"]
        entry["readers"] = attribution["readers"]
        entry["attribution_basis"] = attribution["basis"]
        entry["definition_status"] = ("DEFINED_IN_TOOL" if attribution["where_defined"]
                                      else "UNDEFINED_IN_TRACKED_TREE")
        entry["unknown_version_action"] = "REFUSE_INTERPRET"
        entry["examples"] = sorted(entry["examples"])

    # A JSON Schema document is a stronger definition than a tool literal.
    for schema_document in schema_documents:
        defined = schema_document.get("defines")
        if defined and defined in entries:
            entries[defined]["where_defined"] = schema_document["path"]
            entries[defined]["reader"] = schema_document["reader"]
            entries[defined]["readers"] = [schema_document["reader"]]
            entries[defined]["attribution_basis"] = "JSON_SCHEMA_DOCUMENT"
            entries[defined]["definition_status"] = "DEFINED_IN_SCHEMA_DOCUMENT"

    code_modules = find_code_schema_modules(files, texts)
    cross_version = cross_version_demonstration(
        repo, commit, cross_population, cross_examples, cross_accepted)
    for identifier, entry in entries.items():
        _family, version, _part = parse_schema_identifier(identifier)
        if _family == CROSS_VERSION_FAMILY:
            entry["known_versions"] = cross_version["known_versions"]
            entry["unknown_version_action"] = "REFUSE_INTERPRET"
            entry["unknown_version_rule"] = "PM_SCHEMA_UNKNOWN_VERSION"

    formats = []
    for row in FORMAT_ROWS:
        item = dict(row)
        item["unknown_version_action_semantics"] = UNKNOWN_VERSION_ACTIONS[row["unknown_version_action"]]
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
    with_schema = sum(entry["documents"] for entry in entries.values())
    undefined = sorted(
        entry["identifier"] for entry in entries.values()
        if entry["definition_status"] == "UNDEFINED_IN_TRACKED_TREE"
    )
    no_reader = sorted(
        row["path"] for row in schema_documents if not row.get("reader")
    )

    return {
        "schema": "openssl-rs/etp-t13/formats/1",
        "kind": "etp-t13-format-and-schema-registry",
        "candidate": commit_metadata(repo, commit),
        "version_rule": {
            "accepted_identifier_forms": [
                "<family>/v<major>",
                "<family>/v<major>.<minor>",
                "<family>/<integer>",
                "any of the above followed by /part",
            ],
            "schema_rule": "every schema identifier must carry a version suffix; a schema document's $id and a code schema registry are schema definitions and are subject to the same rule",
            "document_rule": "a schema-bearing document must declare a schema identifier and that identifier must carry a version suffix",
            "unknown_version_action": "REFUSE_INTERPRET",
            "unknown_version_semantics": UNKNOWN_VERSION_ACTIONS["REFUSE_INTERPRET"],
            "part_marker": "a trailing /part is a partition marker, not a version; the version precedes it",
            "additive_change_rule": "a change that only adds optional properties may keep the version; a change that adds a required field must either bump the version and name a converter, or demonstrate that every retained document is still accepted",
            "statement": "a reader must refuse an unknown version rather than interpret it best-effort; a versioned identifier is a different type, not a compatible extension",
        },
        "formats": formats,
        "unknown_version_actions": UNKNOWN_VERSION_ACTIONS,
        "schema_documents": sorted(schema_documents, key=lambda item: item["path"]),
        "code_schema_modules": code_modules,
        "schemas": {
            "census_method": {
                "document_declared": "every tracked .json whose top-level schema field is a string",
                "schema_document": "every tracked *.schema.json carrying $schema and $id",
                "code_schema_module": "every tracked .py with a top-level SCHEMAS = { dictionary literal",
            },
            "counts": {
                "tracked_json_files": len(json_files),
                "parseable_json_documents": parseable,
                "unparseable_json_documents": len(unparseable),
                "documents_declaring_schema": with_schema,
                "parseable_documents_without_schema_key": parseable - with_schema,
                "distinct_versioned_schema_identifiers": len(entries),
                "document_declared_unversioned_documents": len(unversioned),
                "distinct_unversioned_schema_identifiers": len(unversioned_identifiers),
                "schema_documents": len(schema_documents),
                "schema_documents_versioned": sum(1 for row in schema_documents if row.get("version")),
                "schema_documents_unversioned": len(unversioned_schema_documents),
                "code_schema_modules": len(code_modules),
                "code_schema_modules_versioned": sum(1 for row in code_modules if row.get("version")),
                "schema_definitions_total": len(entries) + len(schema_documents) + len(code_modules),
                "schema_definitions_unversioned": (len(unversioned_identifiers)
                                                  + len(unversioned_schema_documents)
                                                  + len(code_modules)),
                "identifiers_undefined_in_tracked_tree": len(undefined),
                "schema_documents_without_reader": len(no_reader),
                "evidence_documents_declaring_no_schema": len(undeclared_evidence),
                "part_marker_identifiers": sum(1 for entry in entries.values() if entry["part_marker"]),
            },
            "entries": [entries[key] for key in sorted(entries)],
            "unversioned": sorted(unversioned, key=lambda item: item["path"]),
            "unversioned_schema_documents": unversioned_schema_documents,
            "undefined_identifiers": undefined,
            "schema_documents_without_reader": no_reader,
            "non_schema_documents": {
                "count": sum(row["documents"] for row in non_schema_rows),
                "by_class": non_schema_rows,
                "evidence_records_declaring_no_schema": undeclared_evidence,
                "migration_population": {
                    "state": "RECORDED_NOT_EDITED",
                    "documents": len(undeclared_evidence),
                    "statement": "these evidence records declare no schema version; they are recorded here as a migration population and are not edited by this item",
                },
                "statement": "these are data documents, captures and court outputs, not evidence records under a schema; the evidence documents among them are listed separately as a migration population",
            },
            "unparseable_documents": sorted(unparseable),
        },
        "cross_version_reader": cross_version,
        "migrations": derive_migrations(repo, commit),
    }


def _schema_document_reader(defined: str, path: str, texts: dict[str, str]) -> str | None:
    """Which tracked tool reads this schema document.

    A tool that opens the document's path is a reader even when it never writes
    the identifier literal; a producer that writes the identifier into its own
    output is not, unless nothing opens the file. Path first, identifier second,
    nothing third.
    """
    for needle in (path, defined):
        if not needle:
            continue
        hits = _contains(texts, needle)
        if hits:
            return _prefer_reader(hits, texts)
    return None


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
        "court_result": "a Phase-17 downstream result record; the schema document that describes it declares no version identifier",
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
    raw = _git_bytes(repo, "show", spec)
    return json.loads(raw)


def _claim_schema_checker() -> Any:
    """The project's own schema checker, or None when it cannot be imported.

    The demonstration that a retained document is still accepted must use a
    real schema implementation. A second, weaker implementation here would let
    the record assert acceptance that the project's validator does not grant.
    """
    try:
        import etp_claims  # noqa: WPS433 (sibling tool in the same directory)
    except Exception:
        return None
    return etp_claims


def _acceptance(checker: Any, document: Any, schema: Any) -> dict[str, Any]:
    if checker is None:
        return {"method": "NOT_RUN", "refusals": None, "examples": [],
                "statement": "the project schema checker could not be imported, so acceptance is not demonstrated"}
    refusals = checker.check_schema(document, schema, schema)
    return {
        "method": "etp_claims.check_schema",
        "refusals": len(refusals),
        "examples": [{"rule": item.rule, "path": item.path} for item in refusals[:5]],
    }


def derive_migrations(repo: Path, commit: str) -> list[dict[str, Any]]:
    migrations: list[dict[str, Any]] = []
    checker = _claim_schema_checker()

    # Demonstration 1: the explicit converter from the ETP-0 inventory to the
    # typed claim document. The source is retained untouched and the target
    # names the source digest.
    etp0_raw = _git_bytes(repo, "show", f"{commit}:{ETP0_CLAIMS}")
    etp0_doc = json.loads(etp0_raw)
    etp1_raw = _git_bytes(repo, "show", f"{commit}:{ETP1_CLAIMS}")
    etp1_doc = json.loads(etp1_raw)
    etp0_ids = [claim.get("id") for claim in etp0_doc.get("claims", [])]
    etp1_ids = [claim.get("id") for claim in etp1_doc.get("claims", [])]
    before = _verdict_counts(etp0_doc.get("claims", []))
    after = _verdict_counts(etp1_doc.get("claims", []))
    source_sha = hashlib.sha256(etp0_raw).hexdigest()
    derived = etp1_doc.get("derived_from") or {}
    source_revisions = _schema_revisions(repo, commit, ETP0_CLAIMS)
    target_revisions = _schema_revisions(repo, commit, ETP1_CLAIMS)
    source_history = [{"commit": rev, "sha256": blob_sha256(repo, rev, ETP0_CLAIMS)}
                      for rev in source_revisions]
    migrations.append({
        "id": "MIG-CLAIM-ETP0-TO-ETP1",
        "rule": "EXPLICIT_CONVERTER_PRESERVING_SOURCE",
        "source": {
            "path": ETP0_CLAIMS,
            "schema": etp0_doc.get("schema"),
            "sha256": source_sha,
            "retained": True,
            "revisions": source_history,
        },
        "target": {
            "path": ETP1_CLAIMS,
            "schema": etp1_doc.get("schema"),
            "sha256": hashlib.sha256(etp1_raw).hexdigest(),
            "revisions": [{"commit": rev, "sha256": blob_sha256(repo, rev, ETP1_CLAIMS)}
                          for rev in target_revisions],
        },
        "converter": "the ETP-1 claim typing, documented in docs/ETP-CLAIM-ALGEBRA.md",
        "preserved": {
            "ids_before": len(etp0_ids),
            "ids_after": len(etp1_ids),
            "ids_equal": sorted(etp0_ids) == sorted(etp1_ids),
            "verdicts_before": before,
            "verdicts_after": after,
            "verdict_map": {"SUPPORTED": "ESTABLISHED", "PARTIAL": "PARTIAL",
                            "CONTRADICTED": "CONTRADICTED", "SUPERSEDED": "SUPERSEDED"},
            "mapped_verdicts_equal": _mapped_counts(before) == after,
            "target_derived_from_document": derived.get("document"),
            "target_derived_from_sha256": derived.get("sha256"),
            "target_binds_source": derived.get("document") == ETP0_CLAIMS
                                  and derived.get("sha256") == source_sha,
            "source_unchanged_since_conversion": (
                len(source_history) == 1
                and source_history[0]["sha256"] == source_sha
            ),
        },
        "history_rewritten": False,
        "statement": "the source inventory is retained byte-for-byte, the target names its digest, all claim identities survive, and the verdict mapping is explicit and checked",
    })

    # Demonstration 2: the claim schema's own shape history. Every revision is
    # retained; the single claim document has never been rewritten, and it is
    # tested for acceptance against each later schema revision. A required-field
    # addition that the retained document did not satisfy would require a
    # converter and a version bump.
    revisions = _schema_revisions(repo, commit, CLAIM_SCHEMA)
    history = []
    required_changes = []
    acceptance_problems = []
    previous_signature: dict[str, list[str]] | None = None
    previous_schema: Any = None
    previous_revision: str | None = None
    for revision in revisions:
        schema = _load_blob_json(repo, f"{revision}:{CLAIM_SCHEMA}")
        signature = _required_signature(schema)
        document = _load_blob_json(repo, f"{revision}:{ETP1_CLAIMS}")
        self_accept = _acceptance(checker, document, schema)
        row: dict[str, Any] = {
            "revision": revision,
            "schema_sha256": blob_sha256(repo, revision, CLAIM_SCHEMA),
            "document_sha256": blob_sha256(repo, revision, ETP1_CLAIMS),
            "self_acceptance": self_accept,
        }
        if previous_signature is None:
            row["first_observed"] = True
        else:
            added_paths = sorted(set(signature) - set(previous_signature))
            removed_paths = sorted(set(previous_signature) - set(signature))
            tightened = sorted(
                path for path in set(signature) & set(previous_signature)
                if set(signature[path]) - set(previous_signature[path])
            )
            row["required_paths_added"] = added_paths
            row["required_paths_removed"] = removed_paths
            row["tightened_paths"] = tightened
            # The load-bearing test: is the document that was retained at the
            # previous revision still accepted by this schema revision?
            retained = _load_blob_json(repo, f"{previous_revision}:{ETP1_CLAIMS}")
            retained_accept = _acceptance(checker, retained, schema)
            row["retained_document_acceptance"] = retained_accept
            if added_paths or tightened or removed_paths:
                required_changes.append({
                    "revision": revision,
                    "previous_revision": previous_revision,
                    "required_paths_added": added_paths,
                    "tightened_paths": tightened,
                    "required_paths_removed": removed_paths,
                    "retained_document_accepted": (
                        retained_accept["refusals"] == 0
                        if retained_accept["refusals"] is not None else None
                    ),
                })
            if retained_accept["refusals"] is None:
                acceptance_problems.append(
                    f"{revision}: acceptance NOT_RUN for the retained document")
            elif retained_accept["refusals"] != 0:
                acceptance_problems.append(
                    f"{revision}: the retained document is refused by the new schema "
                    f"({retained_accept['refusals']} refusals)")
        history.append(row)
        previous_signature = signature
        previous_schema = schema
        previous_revision = revision

    first_document_sha = history[0]["document_sha256"] if history else None
    current_document_sha = history[-1]["document_sha256"] if history else None
    unresolved = [
        change for change in required_changes
        if change["retained_document_accepted"] is not True
    ]
    migrations.append({
        "id": "MIG-CLAIM-SCHEMA-HISTORY",
        "rule": "FORWARD_ONLY_WITH_EXPLICIT_HISTORY",
        "path": CLAIM_SCHEMA,
        "identifier": (previous_schema or {}).get("properties", {}).get("schema", {}).get("const"),
        "revisions": history,
        "required_changes": required_changes,
        "converter": None,
        "version_bumped": False,
        "population_acceptance": {
            "method": "etp_claims.check_schema over the retained document at each revision",
            "demonstrated": bool(history) and not acceptance_problems,
            "problems": acceptance_problems,
            "statement": "the claim document has one recorded revision and is still accepted by the current schema; no retained document is invalidated by a tightening",
        },
        "required_change_resolution": {
            "unresolved_changes": len(unresolved),
            "resolution": ("NO_CONVERTER_REQUIRED_ALL_RETAINED_DOCUMENTS_ACCEPTED"
                           if not unresolved else "CONVERTER_REQUIRED"),
        },
        "document_rewritten": first_document_sha != current_document_sha,
        "history_rewritten": False,
        "statement": "the schema's required sets were tightened in nested definitions, not in a purely additive way; the single retained claim document is still accepted by every later revision, so no converter and no version bump are required, and that fact is demonstrated rather than asserted. A required-field addition that a retained document did not satisfy would require both.",
    })
    return migrations


def _mapped_counts(counts: dict[str, int]) -> dict[str, int]:
    mapping = {"SUPPORTED": "ESTABLISHED", "PARTIAL": "PARTIAL",
               "CONTRADICTED": "CONTRADICTED", "SUPERSEDED": "SUPERSEDED"}
    out: dict[str, int] = {}
    for key, value in counts.items():
        out[mapping.get(key, key)] = out.get(mapping.get(key, key), 0) + value
    return dict(sorted(out.items()))


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


def normalise_algorithm(value: str) -> str | None:
    """Map a stated algorithm name to an admitted identifier, or None."""
    return _NORMALISED_ALGORITHM.get(re.sub(r"[^a-z0-9]", "", value.lower()))


def looks_like_subject_key(key: str) -> bool:
    """True when the key names a subject (a path) rather than a digest field.

    A JSON object may map a file path to its digest. The path is the subject of
    the digest, not the name of the algorithm that produced it, so it must not be
    read as an algorithm claim even when the path contains ``md5`` or ``sha256``.
    """
    return "/" in key or bool(FILE_EXTENSION_RE.search(key))


def looks_like_constant_key(key: str) -> bool:
    """True when the key names an ABI constant rather than a digest field.

    ``SHA256_DIGEST_LENGTH`` and ``NID_sha512`` contain an algorithm name and
    hold a number or a name, not a digest. Counting them as digests would
    inflate the named population and make the algorithm mix meaningless.
    """
    return bool(CONSTANT_KEY_RE.search(key)) or (key.upper() == key and key.lower() != key)


def is_absent_marker(value: str) -> bool:
    """True when a named digest field holds an explicit absence marker."""
    stripped = value.strip()
    if not stripped:
        return True
    if stripped.startswith("<") and stripped.endswith(">"):
        return True
    return stripped.upper() in ABSENT_MARKERS


def _algorithm_of_key(key: str) -> str | None:
    """Return the algorithm a key names, or None.

    The name may be the whole key (``sha256``), a prefix or suffix
    (``sha256_file``, ``source_sha256``) or an interior token
    (``span_sha256_current``). A token boundary is any character that is not a
    lower-case letter or digit, so ``md5_sha1`` names ``sha1`` (the longest name
    present) rather than ``md5``. A key that looks like a path is a subject key
    and never names an algorithm. Repository object ids are not matched here:
    ``sha1`` is a legacy *content* digest name and an object-id algorithm at the
    same time, and only ``git rev-parse --show-object-format`` may say which one
    a 40-character value is.
    """
    if looks_like_subject_key(key):
        return None
    best: str | None = None
    for match in ALGORITHM_ALTERNATION_RE.finditer(key.lower()):
        token = match.group(0)
        if best is None or len(token) > len(best):
            best = token
    return best


def _scan_digests(doc: Any, path: str) -> dict[str, Any]:
    """Attribute every digest-shaped value to an algorithm, or report it unnamed.

    The algorithm may be named by the leaf key (``sha256``, ``source_sha256``),
    by an adjacent ``digest_algorithm``/``hash_algorithm`` field in the same
    object, or by an enclosing field that names it (``files_sha256`` maps paths
    to SHA-256 digests). Only when none of those applies is a digest unnamed.
    A key that names a path is a subject, never an algorithm claim.

    A 40- or 64-character hexadecimal value under an object-identity key is a
    *repository object id*, not a content digest. It is counted in
    ``object_ids`` so the two populations are visibly separate.
    """
    named: dict[str, int] = {}
    unnamed: dict[str, int] = {}
    unadmitted: dict[str, int] = {}
    absent_markers: dict[str, int] = {}
    object_ids: dict[str, int] = {}
    sources = {"key_token": 0, "sibling_field": 0, "parent_field": 0}
    mislabelled: list[dict[str, Any]] = []
    non_digest_values: list[dict[str, Any]] = []
    mislabelled_count = 0
    non_digest_count = 0

    def note_length(algorithm: str, value: str, field: str) -> None:
        nonlocal mislabelled_count
        if HEX_DIGEST_RE.match(value) and len(value) != ALGORITHM_LENGTHS.get(algorithm):
            mislabelled_count += 1
            if len(mislabelled) < 50:
                mislabelled.append({"path": path, "field": field,
                                    "algorithm": algorithm, "length": len(value)})

    def attribute(raw: str, canonical: str | None, value: str, field: str,
                  source: str) -> None:
        if canonical in ADMITTED_IDS:
            named[canonical] = named.get(canonical, 0) + 1
            sources[source] += 1
            note_length(canonical, value, field)
        else:
            unadmitted[raw] = unadmitted.get(raw, 0) + 1

    def walk(node: Any, sub: str, context_raw: str | None,
             context_canonical: str | None) -> None:
        if isinstance(node, dict):
            sibling_raw = None
            for key, value in node.items():
                if key in DIGEST_FIELD_NAMES and isinstance(value, str):
                    sibling_raw = value
                    break
            sibling_canonical = normalise_algorithm(sibling_raw) if sibling_raw else None
            effective_raw = sibling_raw or context_raw
            effective_canonical = sibling_canonical or context_canonical
            for key, value in node.items():
                key_algorithm = _algorithm_of_key(key)
                if key in DIGEST_FIELD_NAMES:
                    # A declaration of the adjacent digest's algorithm, not a digest.
                    continue
                if isinstance(value, str):
                    if looks_like_constant_key(key):
                        # An ABI constant or an identifier that happens to contain
                        # an algorithm name; not a digest claim.
                        continue
                    if key in OBJECT_IDENTITY_KEYS or key.lower() in OBJECT_IDENTITY_KEYS:
                        if OBJECT_ID_RE.match(value):
                            object_ids[key] = object_ids.get(key, 0) + 1
                            continue
                    if HEX_DIGEST_RE.match(value):
                        if key_algorithm:
                            attribute(key_algorithm, key_algorithm, value,
                                      f"{sub}/{key}", "key_token")
                        elif (any(hint in key.lower() for hint in DIGEST_VALUE_HINTS)
                              or looks_like_subject_key(key)):
                            if effective_raw:
                                source = ("sibling_field" if sibling_raw
                                          else "parent_field")
                                attribute(effective_raw, effective_canonical, value,
                                          f"{sub}/{key}", source)
                            else:
                                unnamed[key] = unnamed.get(key, 0) + 1
                    elif key_algorithm and is_absent_marker(value):
                        absent_markers[key_algorithm] = absent_markers.get(
                            key_algorithm, 0) + 1
                    elif key_algorithm:
                        note_non_digest({"path": path, "field": f"{sub}/{key}",
                                         "algorithm": key_algorithm,
                                         "value_kind": "not_hex"})
                    continue
                if looks_like_constant_key(key):
                    continue
                child_raw = key_algorithm or effective_raw
                child_canonical = key_algorithm or effective_canonical
                walk(value, f"{sub}/{key}", child_raw, child_canonical)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{sub}/{index}", context_raw, context_canonical)

    def note_non_digest(entry: dict[str, Any]) -> None:
        nonlocal non_digest_count
        non_digest_count += 1
        if len(non_digest_values) < 50:
            non_digest_values.append(entry)

    walk(doc, path, None, None)
    return {"named": named, "unnamed": unnamed, "unadmitted": unadmitted,
            "absent_markers": absent_markers, "object_ids": object_ids,
            "sources": sources, "mislabelled": mislabelled,
            "mislabelled_count": mislabelled_count,
            "non_digest_values": non_digest_values,
            "non_digest_count": non_digest_count}


# ---------------------------------------------------------------------------
# Digest renewal: a new binding over the same archived bytes
# ---------------------------------------------------------------------------

# The renewal demonstration covers two small archived inputs: an evidence
# document and the ETP-6 entry script. Both are read from the candidate commit,
# so the bytes the renewal binds are the archived bytes, not a working-tree copy.
RENEWAL_SUBJECTS = ["evidence/etp0/CLAIMS.json", "forensics/etp6/verify.sh"]


def make_renewal_record(repo: Path, commit: str, path: str,
                        old: str = "sha256", new: str = "sha384") -> dict[str, Any]:
    """Bind a new digest and the old digest over one identical byte sequence.

    The record names the subject's object id as well, so the archived bytes can
    be located in the repository, but the object id is not one of the digests
    being renewed: it belongs to the repository-identity system.
    """
    raw = _git_bytes(repo, "show", f"{commit}:{path}")
    old_id = require_digest_algorithm(old)
    new_id = require_digest_algorithm(new)
    if old_id == new_id:
        raise Refusal("PM_RENEWAL_BYTES_CHANGED", path,
                      "a renewal must bind a different algorithm")
    object_id = _git(repo, "rev-parse", f"{commit}:{path}").strip()
    return {
        "id": f"RENEW-{path}",
        "subject": path,
        "subject_bytes": len(raw),
        "subject_content_sha256": hashlib.sha256(raw).hexdigest(),
        "subject_object_id": object_id,
        "subject_object_id_algorithm": repository_object_format(repo),
        "old": {"algorithm": old_id, "digest": digest_bytes(old_id, raw)},
        "new": {"algorithm": new_id, "digest": digest_bytes(new_id, raw)},
        "bytes_identical": True,
        "original_at": commit,
        "renewal_reason": "demonstration of a digest-agility binding; no algorithm is being retired by this record",
        "trusted_time_assumption": (
            "the renewal inherits the trust placed in the original record's time "
            "and does not retroactively establish it; the original timestamp and "
            "the renewal time are both recorded"),
        "statement": (
            "old and new digests are computed over the same archived bytes; the "
            "old binding is preserved rather than replaced, and the object id is "
            "recorded separately because it is not a content digest"),
    }


def verify_renewal(record: dict[str, Any], raw: bytes) -> None:
    """Refuse a renewal whose old or new digest does not cover ``raw``.

    Both sides are recomputed over the supplied bytes. A record whose new
    binding was made over different bytes shows a mismatch on that side, and a
    record whose old binding was rewritten shows a mismatch on the other side.
    The verifier cannot tell which side was corrupted; it refuses the pair.
    """
    subject = str(record.get("subject", "renewal"))
    stated = record.get("subject_content_sha256")
    if stated is not None and stated != hashlib.sha256(raw).hexdigest():
        raise Refusal("PM_RENEWAL_BYTES_CHANGED", subject,
                      "the record's subject digest does not cover the supplied bytes")
    for side in ("old", "new"):
        entry = record.get(side) or {}
        algorithm = entry.get("algorithm")
        digest = entry.get("digest")
        if not algorithm or not digest:
            raise Refusal("PM_RENEWAL_BYTES_CHANGED", subject,
                          f"the {side} binding is incomplete")
        expected = digest_bytes(algorithm, raw)
        if digest != expected:
            raise Refusal(
                "PM_RENEWAL_BYTES_CHANGED", subject,
                f"the {side} {algorithm} digest does not cover the supplied bytes; "
                f"recorded {digest[:16]}..., recomputed {expected[:16]}...",
            )
    if record.get("bytes_identical") is not True:
        raise Refusal("PM_RENEWAL_BYTES_CHANGED", subject,
                      "the record does not state that the bindings cover identical bytes")


# ---------------------------------------------------------------------------
# Archive corruption controls
# ---------------------------------------------------------------------------

ARCHIVE_FIXTURE_MEMBERS = {
    "README.txt": b"etp-t13 archival control fixture\n",
    "records/FORMATS.json": b'{"schema": "openssl-rs/etp-t13/formats/1"}\n',
    "records/NOTE.txt": b"a second archived member\n",
}


def build_archive_fixture(members: dict[str, bytes] | None = None) -> bytes:
    """Build a deterministic ``tar.gz`` fixture with fixed metadata.

    Sorted member order, zero mtime, uid/gid 0 and empty owner names make the
    compressed bytes a pure function of the member contents, so the control can
    corrupt exactly one thing and no other byte moves.
    """
    payload = ARCHIVE_FIXTURE_MEMBERS if members is None else members
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w",
                          format=tarfile.PAX_FORMAT) as tar:
            for name in sorted(payload):
                data = payload[name]
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def build_archive_manifest(members: dict[str, bytes] | None = None) -> dict[str, Any]:
    payload = ARCHIVE_FIXTURE_MEMBERS if members is None else members
    return {
        "schema": "openssl-rs/etp-t13/archive-manifest/1",
        "digest_algorithm": "sha256",
        "members": [
            {"path": name, "bytes": len(payload[name]),
             "sha256": hashlib.sha256(payload[name]).hexdigest()}
            for name in sorted(payload)
        ],
    }


def verify_archive_bytes(archive: bytes, manifest: dict[str, Any]) -> dict[str, Any]:
    """Verify an archive against its manifest, refusing every corruption class.

    Order: the manifest's digest algorithm is admitted, the archive decodes, each
    archived member is listed and matches its recorded digest, and every listed
    member is present. A truncated stream, a changed member, a missing member and
    a manifest that disagrees with the bytes each stop at a named rule.
    """
    algorithm = require_digest_algorithm(manifest.get("digest_algorithm"))
    expected = {row["path"]: row for row in manifest.get("members", [])}
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    raise Refusal("PM_ARCHIVE_TRUNCATED", member.name,
                                  "the member cannot be read from the archive")
                data = handle.read()
                seen.add(member.name)
                if member.name not in expected:
                    raise Refusal("PM_ARCHIVE_MEMBER_UNLISTED", member.name,
                                  "the archive carries a member the manifest does not list")
                want = expected[member.name]
                actual = digest_bytes(algorithm, data)
                if len(data) != want.get("bytes") or actual != want.get(algorithm):
                    raise Refusal(
                        "PM_ARCHIVE_MEMBER_DIGEST", member.name,
                        f"the archived member does not match the manifest "
                        f"({algorithm} {actual[:16]}... vs recorded "
                        f"{str(want.get(algorithm))[:16]}...)",
                    )
    except Refusal:
        raise
    except (tarfile.TarError, EOFError, OSError, zlib.error) as error:
        raise Refusal("PM_ARCHIVE_TRUNCATED", "archive",
                      f"the archive cannot be decoded: {error}") from error
    missing = sorted(set(expected) - seen)
    if missing:
        raise Refusal("PM_ARCHIVE_MEMBER_MISSING", ",".join(missing),
                      "the manifest lists members the archive does not carry")
    return {"members": len(seen), "manifest_members": len(expected),
            "digest_algorithm": algorithm}


def archive_controls() -> list[dict[str, Any]]:
    """Four corruption controls, each refused by the archive verifier."""
    controls: list[dict[str, Any]] = []
    manifest = build_archive_manifest()

    def expected_rule(name: str, blob: bytes, man: dict[str, Any],
                      rule: str) -> None:
        try:
            verify_archive_bytes(blob, man)
        except Refusal as refusal:
            controls.append({"control": name, "passed": refusal.rule == rule,
                             "detail": refusal.rule, "rule": rule})
            return
        controls.append({"control": name, "passed": False,
                         "detail": "no refusal", "rule": rule})

    healthy = build_archive_fixture()
    try:
        result = verify_archive_bytes(healthy, manifest)
        controls.append({"control": "archive_roundtrip_accepted",
                         "passed": result["members"] == result["manifest_members"] == 3,
                         "detail": f"{result['members']} members", "rule": None})
    except Refusal as refusal:
        controls.append({"control": "archive_roundtrip_accepted", "passed": False,
                         "detail": refusal.rule, "rule": None})

    expected_rule("truncated_archive_refused", healthy[: len(healthy) // 2],
                  manifest, "PM_ARCHIVE_TRUNCATED")

    flipped = dict(ARCHIVE_FIXTURE_MEMBERS)
    flipped["records/NOTE.txt"] = b"a second archived membeR\n"
    expected_rule("byte_flipped_member_refused", build_archive_fixture(flipped),
                  manifest, "PM_ARCHIVE_MEMBER_DIGEST")

    missing = dict(ARCHIVE_FIXTURE_MEMBERS)
    del missing["records/FORMATS.json"]
    expected_rule("missing_member_refused", build_archive_fixture(missing),
                  manifest, "PM_ARCHIVE_MEMBER_MISSING")

    disagreeing = build_archive_manifest()
    disagreeing["members"][0]["sha256"] = "0" * 64
    expected_rule("manifest_digest_disagreement_refused", healthy,
                  disagreeing, "PM_ARCHIVE_MEMBER_DIGEST")

    unlisted = dict(ARCHIVE_FIXTURE_MEMBERS)
    unlisted["records/EXTRA.txt"] = b"not in the manifest\n"
    expected_rule("unlisted_member_refused", build_archive_fixture(unlisted),
                  manifest, "PM_ARCHIVE_MEMBER_UNLISTED")
    return controls


def derive_digests(repo: Path, commit: str) -> dict[str, Any]:
    files = tracked_files(repo, commit)
    json_files = [path for path in files if path.endswith(".json")]

    documents_named = 0
    documents_unnamed = 0
    documents_unadmitted = 0
    documents_both = 0
    named_total: dict[str, int] = {}
    unnamed_total: dict[str, int] = {}
    unadmitted_total: dict[str, int] = {}
    unnamed_examples: dict[str, list[str]] = {}
    subject_keys: dict[str, int] = {}
    sources = {"key_token": 0, "sibling_field": 0, "parent_field": 0}
    absent_markers: dict[str, int] = {}
    object_ids: dict[str, int] = {}
    object_id_documents = 0
    mislabelled: list[dict[str, Any]] = []
    mislabelled_count = 0
    non_digest_values: list[dict[str, Any]] = []
    non_digest_count = 0

    for path, raw in iter_blobs(repo, commit, json_files):
        try:
            doc = json.loads(raw)
        except Exception:
            continue
        scan = _scan_digests(doc, path)
        has_named = bool(scan["named"])
        has_unadmitted = bool(scan["unadmitted"])
        has_unnamed = bool(scan["unnamed"])
        if has_named:
            documents_named += 1
        if has_unadmitted:
            documents_unadmitted += 1
        if has_unnamed:
            documents_unnamed += 1
        if (has_named or has_unadmitted) and has_unnamed:
            documents_both += 1
        for algorithm, count in scan["named"].items():
            named_total[algorithm] = named_total.get(algorithm, 0) + count
        for key, count in scan["unnamed"].items():
            unnamed_total[key] = unnamed_total.get(key, 0) + count
            if looks_like_subject_key(key):
                subject_keys[key] = subject_keys.get(key, 0) + count
            unnamed_examples.setdefault(key, [])
            if len(unnamed_examples[key]) < 3:
                unnamed_examples[key].append(path)
        for algorithm, count in scan["unadmitted"].items():
            unadmitted_total[algorithm] = unadmitted_total.get(algorithm, 0) + count
        for algorithm, count in scan["absent_markers"].items():
            absent_markers[algorithm] = absent_markers.get(algorithm, 0) + count
        if scan["object_ids"]:
            object_id_documents += 1
        for key, count in scan["object_ids"].items():
            object_ids[key] = object_ids.get(key, 0) + count
        for source, count in scan["sources"].items():
            sources[source] += count
        mislabelled.extend(scan["mislabelled"])
        mislabelled_count += scan["mislabelled_count"]
        non_digest_values.extend(scan["non_digest_values"])
        non_digest_count += scan["non_digest_count"]

    renewals = [make_renewal_record(repo, commit, path) for path in RENEWAL_SUBJECTS]
    for record in renewals:
        raw = _git_bytes(repo, "show", f"{commit}:{record['subject']}")
        verify_renewal(record, raw)

    return {
        "schema": "openssl-rs/etp-t13/digests/1",
        "kind": "etp-t13-digest-agility-record",
        "candidate": commit_metadata(repo, commit),
        "admission_rule": {
            "algorithm_must_be_named": "a recorded digest must state the algorithm that produced it, in the field name or in an adjacent digest_algorithm/hash_algorithm field",
            "algorithm_must_be_admitted": "a stated algorithm must appear in admitted_algorithms before a record may carry it",
            "length_must_match": "a value whose length cannot be the digest it names is reported, not repaired",
            "unnamed_refusal": "PM_DIGEST_ALGORITHM_UNNAMED",
            "unadmitted_refusal": "PM_DIGEST_ALGORITHM_UNADMITTED",
            "existing_records": "existing unnamed records are a migration population; no record was edited to add an algorithm",
        },
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
                "subject_path_keyed": {
                    "keys": dict(sorted(subject_keys.items())),
                    "occurrences": sum(subject_keys.values()),
                    "statement": "these keys are subjects (file paths); the value is a digest of the subject and the algorithm is unnamed",
                },
            },
            "both": documents_both,
            "unadmitted": {
                "documents": documents_unadmitted,
                "occurrences": sum(unadmitted_total.values()),
                "by_algorithm": dict(sorted(unadmitted_total.items())),
            },
            "naming_source": dict(sorted(sources.items())),
            "absent_markers": {
                "occurrences": sum(absent_markers.values()),
                "by_algorithm": dict(sorted(absent_markers.items())),
                "statement": "a field names a digest algorithm but holds an explicit absence marker; the digest was never recorded, which is a gap rather than a migration item",
            },
            "mislabelled_length": {
                "occurrences": mislabelled_count,
                "examples": mislabelled[:10],
                "statement": "a value whose length cannot be the digest it names is reported, not repaired",
            },
            "named_key_with_non_digest_value": {
                "occurrences": non_digest_count,
                "examples": non_digest_values[:10],
                "statement": "a key naming an algorithm whose value is not a hex digest is reported; it may be a constant or a length, not a digest",
            },
            "repository_object_ids": {
                "documents": object_id_documents,
                "occurrences": sum(object_ids.values()),
                "by_key": dict(sorted(object_ids.items(), key=lambda item: (-item[1], item[0]))),
                "statement": ("these values are repository object ids under object-identity keys. "
                              "They belong to the repository-identity system, not the "
                              "content-digest system, and are excluded from every digest "
                              "population above. Their length alone does not identify them: "
                              "a 64-hex value could be either a sha256 object id or a "
                              "SHA-256 content digest, and only the declaring key separates them"),
            },
        },
        "migration_population": {
            "state": "RECORDED_NOT_EDITED",
            "documents": documents_unnamed,
            "occurrences": sum(unnamed_total.values()),
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
            "renewal_record_fields": ["subject", "old", "new", "subject_content_sha256",
                                      "bytes_identical", "renewal_reason", "original_at"],
            "trigger": "a new authenticated commitment is recorded before an existing algorithm is treated as inadequate; the original and the renewal are both preserved",
            "trusted_time_assumption": "a renewal inherits the trust in the old record's time and does not retroactively establish it; the original timestamp and the renewal timestamp are both retained",
            "status": "PLAN_ONLY",
            "statement": "the population is not migrated: this is the stated plan for renewing every record, and it never rewrites the old relationship",
        },
        "renewal_records": renewals,
        "renewal_verification": {
            "method": "verify_renewal recomputes the old and new digest over the archived bytes named by each record",
            "records_verified": len(renewals),
            "rule": "PM_RENEWAL_BYTES_CHANGED",
            "statement": ("each renewal binds two algorithms over one identical archived byte "
                          "sequence. A record whose old or new digest covers different bytes is "
                          "refused; the verifier cannot tell which side was altered, so it "
                          "refuses the pair"),
            "demonstration": "EXECUTED_AT_BUILD_AND_AT_VALIDATE",
            "population_migrated": False,
        },
        "archive_controls": archive_controls(),
        "identity_separation": {
            "object_identity_keys": sorted(OBJECT_IDENTITY_KEYS),
            "content_digest_algorithms": sorted(ADMITTED_IDS),
            "statement": ("a repository object id and a content digest are different systems. "
                          "A value is assigned to the object-identity system only when its "
                          "key names an object identity; every other digest-shaped value is "
                          "a content digest claim"),
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
        "locations": ["src", "tests", "examples", "Cargo.toml", "Cargo.lock", "build.rs",
                      "rust-toolchain.toml"],
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
                      "forensics/multitrack/default-authority.json",
                      "courts/phase18/timing/third_party"],
    },
    {
        "id": "trust_metadata",
        "required": True,
        "description": "the claim set, trust-gap inventory, independence and freshness records, and the constitution",
        "locations": ["evidence/etp0", "evidence/etp", "evidence/etp-t8", "evidence/etp-t9",
                      "AGENTS.md", "docs/ETP-TODO.md", "docs/ETP-ADDENDUM-B.md",
                      "docs/ETP-CLAIM-ALGEBRA.md", "docs/EXTERNAL-REPRODUCTION.md",
                      "docs/INDEPENDENCE.md", "docs/EVIDENCE-FRESHNESS.md"],
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


def _location_audit(files: list[str], location: str) -> dict[str, Any]:
    if location in files:
        return {"location": location, "kind": "file", "exists": True, "tracked_files": 1}
    prefixed = [path for path in files if path.startswith(location.rstrip("/") + "/")]
    return {"location": location, "kind": "directory",
            "exists": bool(prefixed), "tracked_files": len(prefixed)}


def verifier_reconstructability(repo: Path, commit: str) -> dict[str, Any]:
    """What a third party needs to rebuild the verifier itself.

    The tool digest is recorded twice: the blob at the candidate commit (what the
    records describe) and the working-tree bytes that actually produced this
    evidence commit. They differ while the tool is being changed, and recording
    both makes that visible instead of hiding it.
    """
    candidate_tool = blob_sha256(repo, commit, TOOL_PATH)
    working = Path(__file__).resolve()
    working_digest = hashlib.sha256(working.read_bytes()).hexdigest()
    supporting = []
    for path in (ETP6_VERIFIER, ETP6_ENTRY):
        try:
            supporting.append({"path": path, "sha256": blob_sha256(repo, commit, path)})
        except subprocess.CalledProcessError:
            supporting.append({"path": path, "sha256": None,
                               "state": "ABSENT_AT_CANDIDATE"})
    return {
        "interpreter": {
            "requirement": "CPython 3.11 or another Python 3.11 implementation",
            "language_contract": "the tool imports only the standard library",
            "verified_on": f"CPython {sys.version_info.major}.{sys.version_info.minor}",
            "platform_recorded": platform.system(),
        },
        "standard_library_imports": [
            "argparse", "datetime", "gzip", "hashlib", "io", "json", "platform",
            "re", "subprocess", "sys", "tarfile", "tempfile", "zlib",
            "pathlib", "typing",
        ],
        "third_party_dependencies": [],
        "tools": [
            {"path": TOOL_PATH, "sha256_at_candidate": candidate_tool,
             "digest_basis": "CANDIDATE_COMMIT_BLOB"},
            {"path": TOOL_PATH, "sha256_of_working_tree": working_digest,
             "digest_basis": "WORKING_TREE_AT_EVIDENCE_COMMIT"},
        ],
        "supporting_verifiers": supporting,
        "recorded": {
            "interpreter_requirement": True,
            "standard_library_only": True,
            "tool_digest": True,
            "candidate_tool_digest": True,
            "test_suite": "forensics/tools/tests/test_preservation.py is added by this "
                          "evidence commit; it is not present at the candidate",
        },
        "not_recorded": [
            "the interpreter binary's own digest; only the language version is recorded",
            "a reproducible interpreter build recipe; a standard CPython 3.11 installation "
            "is assumed and that assumption is not evidenced",
            "the platform's libc and zlib identities, although gzip and tarfile delegate "
            "decompression to zlib",
        ],
        "reconstruction_steps": [
            "install CPython 3.11 from any distribution and its standard library",
            "obtain forensics/tools/preservation.py and compare its SHA-256 with the "
            "recorded working-tree digest",
            "run --self-test, then validate, against a checkout of the candidate commit",
        ],
        "statement": ("the verifier is reconstructable from a standard-library Python 3.11 "
                      "installation and the recorded tool digests. The interpreter binary "
                      "and its dependencies are not recorded, so a byte-identical verifier "
                      "executable is not guaranteed"),
    }


def derive_archival(repo: Path, commit: str) -> dict[str, Any]:
    files = tracked_files(repo, commit)
    manifest_raw = _git_bytes(repo, "show", f"{commit}:{ETP6_MANIFEST}")
    manifest = json.loads(manifest_raw)
    bundled = {item["path"] for item in manifest.get("inputs", [])}
    selection = manifest.get("selection", {}).get("paths", [])

    classes = []
    without_location = []
    partial = []
    missing_locations: list[dict[str, str]] = []
    fully_bundled = []
    not_bundled = []
    for spec in ARCHIVAL_CLASSES:
        audit = [_location_audit(files, location) for location in spec.get("locations", [])]
        for row in audit:
            if not row["exists"]:
                missing_locations.append({"class": spec["id"], "location": row["location"]})
        members = _class_members(files, spec)
        in_bundle = [path for path in members if path in bundled]
        if not members:
            status = "NOT_ARCHIVED"
            without_location.append(spec["id"])
        else:
            status = "IN_REPOSITORY_ONLY"
        coverage = "NONE"
        if members:
            if len(in_bundle) == len(members):
                coverage = "FULL"
                fully_bundled.append(spec["id"])
            elif in_bundle:
                coverage = "PARTIAL"
                partial.append(spec["id"])
            else:
                not_bundled.append(spec["id"])
        classes.append({
            "id": spec["id"],
            "required": spec["required"],
            "description": spec["description"],
            "locations": spec.get("locations", []),
            "location_audit": audit,
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
        "candidate": commit_metadata(repo, commit),
        "self_document": {
            "path": "docs/PRESERVATION.md",
            "present_at_candidate": False,
            "statement": "this inventory describes the candidate commit; the normative document for this item is added by the evidence commit and is not present at the candidate, so it is not counted in any class",
        },
        "etp6": {
            "manifest": ETP6_MANIFEST,
            "manifest_schema": manifest.get("schema"),
            "candidate_commit": manifest.get("candidate", {}).get("commit"),
            "input_count": manifest.get("input_count"),
            "selection_paths": selection,
            "bundle_tracked_in_repository": False,
            "coverage_method": "path-set comparison against the manifest's input list",
            "coverage_caveat": "the manifest binds a different candidate commit, so a path present in both is not necessarily identical content; the comparison establishes class coverage, not byte identity",
        },
        "classes": classes,
        "classes_without_location": without_location,
        "classes_partially_bundled": partial,
        "classes_fully_bundled": fully_bundled,
        "classes_not_bundled": not_bundled,
        "missing_declared_locations": missing_locations,
        "etp6_cross_check": {
            "statement": "the ETP-6 manifest covers the classes it selects; it is a reproduction bundle, not a complete archive, and it predates the ETP-T1 to ETP-T13 records",
            "classes_fully_bundled": fully_bundled,
            "classes_partially_bundled": partial,
            "classes_not_bundled": not_bundled,
        },
        "external_durability": {
            "status": "NONE",
            "externally_durable_classes": [],
            "external_archives": [],
            "persistent_identifiers": [],
            "statement": "nothing in this repository is externally archived; every location above is inside this Git repository and is durable only for as long as a copy of that repository survives",
            "etp6_role": "BUNDLE_NOT_ARCHIVE",
            "etp6_statement": "the ETP-6 package is a self-contained reproduction bundle built from one commit; it is not an external archive, it has not been deposited with an independent archive, and it carries no external review receipt",
        },
        "refusals": {
            "class_unarchived": "PM_CLASS_UNARCHIVED",
            "external_durability_claimed": "PM_EXTERNAL_DURABILITY_CLAIMED",
            "archive_truncated": "PM_ARCHIVE_TRUNCATED",
            "archive_member_digest": "PM_ARCHIVE_MEMBER_DIGEST",
            "archive_member_missing": "PM_ARCHIVE_MEMBER_MISSING",
            "archive_member_unlisted": "PM_ARCHIVE_MEMBER_UNLISTED",
        },
        "archive_corruption_controls": {
            "method": "a deterministic tar.gz fixture and its manifest, verified by verify_archive_bytes",
            "controls": archive_controls(),
            "real_bundle_checked": False,
            "real_bundle_statement": ("the ETP-6 production archive is not tracked in this "
                                     "repository, so the corruption controls run against "
                                     "a fixture, not against the real bundle"),
        },
        "verifier_reconstructability": verifier_reconstructability(repo, commit),
    }


def derive_identity_systems(repo: Path, commit: str) -> dict[str, Any]:
    """Model four identity systems and their separation."""
    meta = commit_metadata(repo, commit)
    fmt = meta["object_format"]
    sample = "evidence/etp0/CLAIMS.json"
    raw = _git_bytes(repo, "show", f"{commit}:{sample}")
    object_id = _git(repo, "rev-parse", f"{commit}:{sample}").strip()
    object_bytes = f"blob {len(raw)}\0".encode() + raw
    object_algorithm = fmt
    content_digest = hashlib.sha256(raw).hexdigest()
    renewals = [make_renewal_record(repo, commit, path) for path in RENEWAL_SUBJECTS]
    return {
        "schema": "openssl-rs/etp-t13/identity-systems/1",
        "kind": "etp-t13-identity-systems",
        "candidate": meta,
        "systems": {
            "repository_object_identity": {
                "system": "repository_object_identity",
                "object_format": fmt,
                "object_id_algorithm": object_algorithm,
                "oid_hex_length": OBJECT_FORMATS[fmt]["oid_hex_length"],
                "observed_by": "git rev-parse --show-object-format",
                "subject": "a Git object (commit, tree, blob, tag) inside one object database",
                "computation": "the object format's hash over a header '<type> <size>\\0' plus the bytes",
                "not_a_content_digest": True,
                "format_change_implication": [
                    "a SHA-256 object format produces 64 hexadecimal object ids; a recorded 40-character id does not name an object in such a repository",
                    "the same bytes have different object ids in repositories with different object formats",
                    "a format change rewrites every object id; recorded ids must be re-derived and an old id never compared with a new one as one naming scheme",
                    "the format is read from the repository, never inferred from a digest length",
                ],
            },
            "content_digests": {
                "system": "content_digests",
                "subject": "a byte sequence, inside or outside the repository",
                "algorithms_admitted": sorted(ADMITTED_IDS),
                "naming_rule": ("every record names the algorithm in the field name or in an "
                                "adjacent digest_algorithm/hash_algorithm field; an unnamed "
                                "digest is a recorded migration population"),
                "relationship_to_object_identity": ("none: a content digest can be computed "
                                                    "without Git and an object id cannot"),
            },
            "signature_and_attestation": {
                "system": "signature_and_attestation",
                "status": "ABSENT",
                "algorithms": [],
                "statement": ("no DSSE envelope, Rekor entry, Sigstore bundle, OpenPGP "
                              "signature or trusted timestamp exists in this repository; "
                              "Addendum B is a work queue. No signature or attestation "
                              "algorithm is therefore admitted, recorded or claimed"),
                "non_claim": "the absence of signatures is not evidence of integrity, and this item does not create one",
            },
            "digest_renewal": {
                "system": "digest_renewal",
                "rule": ("a new authenticated commitment over the same archived bytes, "
                         "preserving the old binding rather than replacing it"),
                "records": renewals,
                "old_identity_is_never_rewritten": True,
                "what_a_renewal_cannot_do": [
                    "it cannot retroactively prove that an old signature was valid before a compromise",
                    "it cannot change a repository object id",
                    "it cannot establish the original timestamp; it inherits trust in it",
                ],
                "population_migrated": False,
            },
        },
        "distinctness_evidence": {
            "subject_path": sample,
            "same_bytes": True,
            "object_id": object_id,
            "object_id_algorithm": object_algorithm,
            "object_id_hex_length": len(object_id),
            "object_id_input": "blob header plus bytes",
            "content_digest": {"algorithm": "sha256", "digest": content_digest,
                               "hex_length": len(content_digest)},
            "statement": ("both values identify the same bytes and are not interchangeable: "
                          "the object id is the repository format's hash over the object "
                          "header plus the bytes, while the content digest is SHA-256 over "
                          "the raw bytes"),
            "object_header_bytes": object_bytes[:len(object_bytes) - len(raw)].decode(
                "utf-8", "replace"),
        },
        "separation_rules": [
            "an object format is read from the repository with git rev-parse --show-object-format",
            "a record that names an object format different from the observed one is refused (PM_IDENTITY_OBJECT_FORMAT_MISMATCH)",
            "a content digest is named by its field; its length never implies an object format",
            "a renewal binds two content-digest algorithms over identical bytes and records the object id separately",
            "no signature or attestation algorithm is recorded while the system is absent",
        ],
        "refusals": {
            "object_format_mismatch": "PM_IDENTITY_OBJECT_FORMAT_MISMATCH",
            "object_format_unknown": "PM_IDENTITY_OBJECT_FORMAT_UNKNOWN",
            "conflation": "PM_IDENTITY_CONFLATION",
            "signature_claimed": "PM_SIGNATURE_ALGORITHM_CLAIMED",
            "renewal_bytes_changed": "PM_RENEWAL_BYTES_CHANGED",
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


def require_class_location(record: dict[str, Any], class_id: str) -> dict[str, Any]:
    """Return the class row, or refuse ``PM_CLASS_UNARCHIVED``.

    This is the consumer-facing refusal: a third party asking where a class is
    kept is refused rather than told the class is archived when it has no
    location. It is separate from record validation, which only requires the
    record to be honest about the same fact.
    """
    for row in record.get("classes") or []:
        if row.get("id") != class_id:
            continue
        if not row.get("locations") or row.get("archival_status") == "NOT_ARCHIVED":
            raise Refusal("PM_CLASS_UNARCHIVED", class_id,
                          "the class is required but has no archival location")
        return row
    raise Refusal("PM_CLASS_UNARCHIVED", class_id, "the class is not present in the inventory")


def require_digest_algorithm(algorithm: str | None) -> str:
    """Return the admitted identifier, or refuse the digest."""
    if not algorithm:
        raise Refusal("PM_DIGEST_ALGORITHM_UNNAMED", "digest",
                      "the digest states no algorithm")
    canonical = normalise_algorithm(algorithm) or algorithm
    if canonical not in ADMITTED_IDS:
        raise Refusal("PM_DIGEST_ALGORITHM_UNADMITTED", algorithm,
                      "the algorithm is not in the admitted set")
    return canonical


def validate_formats(record: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    _require(record.get("schema") == "openssl-rs/etp-t13/formats/1",
             "PM_RECORD_SCHEMA", FORMATS_PATH, "unexpected record schema")
    counts = record.get("schemas", {}).get("counts", {})
    for key in ("tracked_json_files", "distinct_versioned_schema_identifiers",
                "schema_definitions_total", "schema_definitions_unversioned"):
        _require(isinstance(counts.get(key), int),
                 "PM_RECORD_SHAPE", FORMATS_PATH, f"missing count {key}")
    for entry in record.get("schemas", {}).get("entries", []):
        identifier = entry.get("identifier", "")
        try:
            parse_schema_identifier(identifier)
        except Refusal as refusal:
            problems.append(f"{refusal.rule} {identifier}")
        _require(bool(entry.get("version")), "PM_RECORD_SHAPE", identifier,
                 "no version recorded for a versioned identifier")
        _require(bool(entry.get("unknown_version_action")), "PM_RECORD_SHAPE",
                 identifier, "no unknown-version action")
        _require(entry.get("definition_status") in
                 ("DEFINED_IN_TOOL", "DEFINED_IN_SCHEMA_DOCUMENT", "UNDEFINED_IN_TRACKED_TREE"),
                 "PM_RECORD_SHAPE", identifier, "undefined attribution not declared")
    for row in record.get("schema_documents", []):
        if not row.get("version"):
            _require(row.get("rule") == "PM_SCHEMA_UNVERSIONED",
                     "PM_RECORD_SHAPE", row.get("path", "?"),
                     "an unversioned schema document is not declared")
    for row in record.get("code_schema_modules", []):
        _require(row.get("version_basis") is not None, "PM_RECORD_SHAPE",
                 row.get("path", "?"), "code registry has no version basis")
    for row in record.get("formats", []):
        _require(bool(row.get("spec_version")) and bool(row.get("unknown_version_action")),
                 "PM_RECORD_SHAPE", row.get("id", "?"),
                 "format has no specification version or action")
        _require(row.get("unknown_version_action") in UNKNOWN_VERSION_ACTIONS,
                 "PM_RECORD_SHAPE", row.get("id", "?"),
                 "format names an unknown-version action with no semantics")
    for migration in record.get("migrations", []):
        problems.extend(validate_migration(migration))
    cross = record.get("cross_version_reader") or {}
    _require(isinstance(cross, dict) and len(cross.get("known_versions") or []) >= 2,
             "PM_RECORD_SHAPE", FORMATS_PATH,
             "no cross-version reader over at least two versions is recorded")
    accepted = {row.get("version") for row in cross.get("accepted_examples") or []
                if "refusal" not in row}
    _require(set(cross.get("known_versions") or []) <= accepted,
             "PM_RECORD_SHAPE", FORMATS_PATH,
             f"not every known version has an accepted example: {sorted(accepted)}")
    _require((cross.get("unknown_version_refusal") or {}).get("demonstrated") is True,
             "PM_SCHEMA_UNKNOWN_VERSION", FORMATS_PATH,
             "an unknown version is not demonstrably refused")
    return problems


def validate_migration(migration: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    rule = migration.get("rule")
    if rule not in MIGRATION_RULES:
        return [f"PM_MIGRATION_RULE_UNKNOWN {migration.get('id')}"]
    if migration.get("history_rewritten") is not False:
        problems.append(f"PM_MIGRATION_HISTORY_REWRITTEN {migration.get('id')}: "
                        f"history_rewritten is not false")
    if rule == "EXPLICIT_CONVERTER_PRESERVING_SOURCE":
        source = migration.get("source") or {}
        if source.get("retained") is not True:
            problems.append(f"PM_MIGRATION_HISTORY_REWRITTEN {migration.get('id')}: "
                            f"source not retained")
        preserved = migration.get("preserved") or {}
        if preserved.get("ids_equal") is not True:
            problems.append(f"PM_MIGRATION_IDENTITY_LOST {migration.get('id')}: "
                            f"claim identities differ")
        if preserved.get("target_binds_source") is not True:
            problems.append(f"PM_MIGRATION_IDENTITY_LOST {migration.get('id')}: "
                            f"the target does not bind the source digest")
        if preserved.get("mapped_verdicts_equal") is not True:
            problems.append(f"PM_MIGRATION_IDENTITY_LOST {migration.get('id')}: "
                            f"the verdict map does not preserve the recorded verdicts")
    else:
        changes = migration.get("required_changes") or []
        demonstration = migration.get("population_acceptance") or {}
        demonstrated = demonstration.get("demonstrated") is True
        converter = bool(migration.get("converter"))
        bumped = migration.get("version_bumped") is True
        unresolved = (migration.get("required_change_resolution") or {}).get(
            "unresolved_changes")
        if changes and not (bumped or demonstrated):
            problems.append(
                f"PM_MIGRATION_REQUIRED_FIELD_WITHOUT_CONVERTER {migration.get('id')}: "
                f"{len(changes)} required change(s), no version bump, no acceptance demonstration")
        if changes and unresolved is None and not (converter or bumped):
            problems.append(
                f"PM_MIGRATION_REQUIRED_FIELD_WITHOUT_CONVERTER {migration.get('id')}: "
                f"no resolution recorded")
        if changes and unresolved not in (None, 0) and not (converter or bumped):
            problems.append(
                f"PM_MIGRATION_REQUIRED_FIELD_WITHOUT_CONVERTER {migration.get('id')}: "
                f"{unresolved} required change(s) invalidate retained documents and no "
                f"converter is named")
        if not changes and (bumped or converter):
            problems.append(f"PM_MIGRATION_RULE_UNKNOWN {migration.get('id')}: "
                            f"a converter is named for a change set with no required change")
    return problems


def validate_digests(record: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    _require(record.get("schema") == "openssl-rs/etp-t13/digests/1",
             "PM_RECORD_SCHEMA", DIGESTS_PATH, "unexpected record schema")
    admitted = record.get("admitted_algorithms") or []
    ids = [entry.get("id") for entry in admitted]
    _require(len(ids) == len(set(ids)), "PM_RECORD_SHAPE", DIGESTS_PATH,
             "duplicate admitted algorithm")
    _require(all(entry.get("id") in ADMITTED_IDS for entry in admitted),
             "PM_DIGEST_ALGORITHM_UNADMITTED", DIGESTS_PATH,
             "record admits an algorithm outside the declared set")
    for entry in admitted:
        _require(bool(entry.get("status")) and bool(entry.get("renewal_priority")),
                 "PM_RECORD_SHAPE", str(entry.get("id")),
                 "admitted algorithm lacks a status or a renewal priority")
    population = record.get("population") or {}
    for algorithm, count in (population.get("named", {}).get("by_algorithm") or {}).items():
        if algorithm not in ADMITTED_IDS:
            problems.append(f"PM_DIGEST_ALGORITHM_UNADMITTED {algorithm} ({count})")
    unadmitted = population.get("unadmitted", {}).get("by_algorithm") or {}
    if unadmitted:
        problems.append(f"PM_DIGEST_ALGORITHM_UNADMITTED {sorted(unadmitted)}")
    unnamed = population.get("unnamed", {})
    _require(unnamed.get("documents", 0)
             == record.get("migration_population", {}).get("documents", -1),
             "PM_RECORD_SHAPE", DIGESTS_PATH,
             "unnamed population and migration population disagree")
    _require(isinstance(population.get("absent_markers", {}).get("occurrences"), int),
             "PM_RECORD_SHAPE", DIGESTS_PATH, "absent-marker population is missing")
    _require(isinstance(population.get("mislabelled_length", {}).get("occurrences"), int),
             "PM_RECORD_SHAPE", DIGESTS_PATH, "length-mismatch population is missing")
    _require(record.get("migration_population", {}).get("state") == "RECORDED_NOT_EDITED",
             "PM_RECORD_SHAPE", DIGESTS_PATH, "migration population is not recorded as unedited")
    renewal = record.get("renewal_plan") or {}
    for key in ("what_is_rehashed", "how_the_old_relationship_is_preserved",
                "what_is_never_rewritten", "renewal_record_fields"):
        _require(bool(renewal.get(key)), "PM_RECORD_SHAPE", DIGESTS_PATH,
                 f"renewal plan lacks {key}")
    _require(renewal.get("status") in ("PLAN_ONLY", "RENEWED"),
             "PM_RECORD_SHAPE", DIGESTS_PATH, "renewal plan has no status")
    _require(isinstance(population.get("repository_object_ids", {}).get("occurrences"), int),
             "PM_RECORD_SHAPE", DIGESTS_PATH,
             "the repository object-id population is not separated from the digest population")
    records = record.get("renewal_records") or []
    _require(bool(records), "PM_RECORD_SHAPE", DIGESTS_PATH,
             "no renewal record is present")
    for entry in records:
        old = entry.get("old") or {}
        new = entry.get("new") or {}
        _require(old.get("algorithm") in ADMITTED_IDS, "PM_DIGEST_ALGORITHM_UNADMITTED",
                 str(old.get("algorithm")), "a renewal names an unadmitted old algorithm")
        _require(new.get("algorithm") in ADMITTED_IDS, "PM_DIGEST_ALGORITHM_UNADMITTED",
                 str(new.get("algorithm")), "a renewal names an unadmitted new algorithm")
        _require(old.get("algorithm") != new.get("algorithm"), "PM_RENEWAL_BYTES_CHANGED",
                 str(entry.get("subject")), "a renewal must bind two different algorithms")
        _require(entry.get("bytes_identical") is True, "PM_RENEWAL_BYTES_CHANGED",
                 str(entry.get("subject")), "the renewal does not state identical bytes")
    verification = record.get("renewal_verification") or {}
    _require(verification.get("records_verified") == len(records),
             "PM_RECORD_SHAPE", DIGESTS_PATH,
             "the renewal verification count disagrees with the renewal records")
    for control in record.get("archive_controls") or []:
        _require(control.get("passed") is True, str(control.get("rule") or "PM_RECORD_SHAPE"),
                 str(control.get("control")),
                 f"archive control did not fire: {control.get('detail')}")
    return problems


def validate_archival(record: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    _require(record.get("schema") == "openssl-rs/etp-t13/archival/1",
             "PM_RECORD_SCHEMA", ARCHIVAL_PATH, "unexpected record schema")
    classes = record.get("classes") or []
    required = [row for row in classes if row.get("required")]
    empty = sorted(row["id"] for row in required if not row.get("locations"))
    recorded = sorted(record.get("classes_without_location") or [])
    if empty != recorded:
        problems.append(f"PM_CLASS_UNARCHIVED declared={recorded} observed={empty}")
    for row in classes:
        _require(row.get("externally_durable") is False,
                 "PM_EXTERNAL_DURABILITY_CLAIMED", row.get("id", "?"),
                 "an external durability claim is not supported")
        _require(isinstance(row.get("inside_repository"), bool),
                 "PM_RECORD_SHAPE", row.get("id", "?"),
                 "inside_repository is not declared")
        if row.get("archival_status") == "NOT_ARCHIVED":
            _require(not row.get("tracked_files"),
                     "PM_RECORD_SHAPE", row.get("id", "?"),
                     "a class with members is not NOT_ARCHIVED")
        else:
            _require(bool(row.get("tracked_files")),
                     "PM_CLASS_UNARCHIVED", row.get("id", "?"),
                     "a class without members claims an archival location")
    durability = record.get("external_durability") or {}
    _require(durability.get("status") == "NONE",
             "PM_EXTERNAL_DURABILITY_CLAIMED", ARCHIVAL_PATH,
             "durability status must be NONE")
    _require(not durability.get("external_archives")
             and not durability.get("persistent_identifiers"),
             "PM_EXTERNAL_DURABILITY_CLAIMED", ARCHIVAL_PATH,
             "an external archive or persistent identifier is claimed")
    _require(durability.get("etp6_role") == "BUNDLE_NOT_ARCHIVE",
             "PM_RECORD_SHAPE", ARCHIVAL_PATH,
             "the ETP-6 package role is not stated as a bundle")
    corrupt = record.get("archive_corruption_controls") or {}
    controls = corrupt.get("controls") or []
    _require(len(controls) >= 4, "PM_RECORD_SHAPE", ARCHIVAL_PATH,
             "fewer than four archive corruption controls are recorded")
    for control in controls:
        _require(control.get("passed") is True, str(control.get("rule") or "PM_RECORD_SHAPE"),
                 str(control.get("control")),
                 f"archive control did not fire: {control.get('detail')}")
    reproducibility = record.get("verifier_reconstructability") or {}
    _require(reproducibility.get("interpreter", {}).get("requirement"),
             "PM_RECORD_SHAPE", ARCHIVAL_PATH,
             "no interpreter requirement is recorded for rebuilding the verifier")
    _require(bool(reproducibility.get("tools")), "PM_RECORD_SHAPE", ARCHIVAL_PATH,
             "no verifier tool digest is recorded")
    _require(bool(reproducibility.get("not_recorded")), "PM_RECORD_SHAPE", ARCHIVAL_PATH,
             "the verifier record does not state what is not recorded")
    return problems


def validate_identity_systems(record: dict[str, Any]) -> list[str]:
    """Check the four systems are present, separate and internally consistent."""
    problems: list[str] = []
    _require(record.get("schema") == "openssl-rs/etp-t13/identity-systems/1",
             "PM_RECORD_SCHEMA", IDENTITY_PATH, "unexpected record schema")
    systems = record.get("systems") or {}
    for name in ("repository_object_identity", "content_digests",
                 "signature_and_attestation", "digest_renewal"):
        _require(name in systems, "PM_RECORD_SHAPE", IDENTITY_PATH,
                 f"the {name} system is missing")
    repo_system = systems.get("repository_object_identity") or {}
    fmt = repo_system.get("object_format")
    _require(fmt in OBJECT_FORMATS, "PM_IDENTITY_OBJECT_FORMAT_UNKNOWN", str(fmt),
             "the record names an object format this tool does not know")
    _require(repo_system.get("oid_hex_length")
             == OBJECT_FORMATS.get(fmt, {}).get("oid_hex_length"),
             "PM_IDENTITY_OBJECT_FORMAT_MISMATCH", str(fmt),
             "the object-id length does not match the object format")
    signature = systems.get("signature_and_attestation") or {}
    if signature.get("status") == "ABSENT":
        _require(not signature.get("algorithms"), "PM_SIGNATURE_ALGORITHM_CLAIMED",
                 "signature_and_attestation",
                 "an absent signature system names algorithms")
    else:
        _require(bool(signature.get("algorithms")), "PM_SIGNATURE_ALGORITHM_CLAIMED",
                 "signature_and_attestation",
                 "a present signature system names no algorithm")
    renewal = systems.get("digest_renewal") or {}
    records = renewal.get("records") or []
    _require(bool(records), "PM_RECORD_SHAPE", IDENTITY_PATH,
             "no renewal record is present")
    for entry in records:
        _require((entry.get("bytes_identical") is True), "PM_RENEWAL_BYTES_CHANGED",
                 str(entry.get("subject")), "a renewal does not bind identical bytes")
        old = (entry.get("old") or {}).get("algorithm")
        new = (entry.get("new") or {}).get("algorithm")
        _require(old in ADMITTED_IDS and new in ADMITTED_IDS and old != new,
                 "PM_DIGEST_ALGORITHM_UNADMITTED", str(entry.get("subject")),
                 "a renewal does not bind two admitted, distinct algorithms")
    evidence = record.get("distinctness_evidence") or {}
    _require(evidence.get("object_id") and evidence.get("content_digest"),
             "PM_IDENTITY_CONFLATION", IDENTITY_PATH,
             "the record does not show an object id beside a content digest")
    _require(len(str(evidence.get("object_id"))) == OBJECT_FORMATS[fmt]["oid_hex_length"],
             "PM_IDENTITY_OBJECT_FORMAT_MISMATCH", str(evidence.get("object_id")),
             "the worked object id does not match the object format")
    digest = evidence.get("content_digest") or {}
    _require(digest.get("algorithm") in ADMITTED_IDS, "PM_DIGEST_ALGORITHM_UNADMITTED",
             str(digest.get("algorithm")), "the content digest names an unadmitted algorithm")
    _require(evidence.get("object_id") != digest.get("digest"), "PM_IDENTITY_CONFLATION",
             IDENTITY_PATH, "the object id and the content digest are recorded as one value")
    require_object_format(record.get("candidate") or {}, fmt)
    refuse_conflation(record.get("candidate") or {}, fmt)
    return problems


def compare_records(recorded: dict[str, Any], derived: dict[str, Any],
                    fields: tuple[str, ...], label: str) -> list[str]:
    """Pure drift comparison; ``generated_utc`` and ``kernel`` fields are excluded."""
    mismatches = []
    for field in fields:
        if _canonical(recorded.get(field)) != _canonical(derived.get(field)):
            mismatches.append(f"{label}:{field}")
    return mismatches


def check_tree_records(repo: Path, commit: str) -> dict[str, Any]:
    """Re-derive the four records at `commit` and compare the committed ones."""
    formats = derive_formats(repo, commit)
    digests = derive_digests(repo, commit)
    archival = derive_archival(repo, commit)
    identity = derive_identity_systems(repo, commit)
    recorded_formats = _load_json(repo / FORMATS_PATH)
    recorded_digests = _load_json(repo / DIGESTS_PATH)
    recorded_archival = _load_json(repo / ARCHIVAL_PATH)
    recorded_identity = _load_json(repo / IDENTITY_PATH)

    mismatches: list[str] = []
    mismatches += compare_records(
        recorded_formats, formats,
        ("formats", "schema_documents", "code_schema_modules", "schemas",
         "cross_version_reader", "migrations"),
        "formats")
    mismatches += compare_records(
        recorded_digests, digests,
        ("admitted_algorithms", "population", "migration_population", "renewal_plan",
         "renewal_records", "renewal_verification", "archive_controls",
         "identity_separation"),
        "digests")
    mismatches += compare_records(
        recorded_archival, archival,
        ("self_document", "etp6", "classes", "classes_without_location",
         "classes_partially_bundled", "etp6_cross_check", "external_durability",
         "missing_declared_locations", "archive_corruption_controls",
         "verifier_reconstructability"),
        "archival")
    mismatches += compare_records(
        recorded_identity, identity,
        ("systems", "distinctness_evidence", "separation_rules", "refusals"),
        "identity")
    for recorded, derived, label in (
        (recorded_formats, formats, "formats"),
        (recorded_digests, digests, "digests"),
        (recorded_archival, archival, "archival"),
        (recorded_identity, identity, "identity"),
    ):
        if _canonical(recorded.get("candidate")) != _canonical(derived.get("candidate")):
            mismatches.append(f"{label}:candidate")
    return {
        "mismatches": mismatches,
        "formats": formats,
        "digests": digests,
        "archival": archival,
        "identity": identity,
    }


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def open_populations(formats: dict[str, Any], digests: dict[str, Any],
                     archival: dict[str, Any]) -> list[str]:
    """The populations this item records but does not repair."""
    out = []
    counts = formats.get("schemas", {}).get("counts", {})
    if counts.get("document_declared_unversioned_documents"):
        out.append(f"PM_SCHEMA_UNVERSIONED document-declared "
                   f"{counts['document_declared_unversioned_documents']}")
    for row in formats.get("schemas", {}).get("unversioned_schema_documents", []):
        out.append(f"PM_SCHEMA_UNVERSIONED schema-document {row['path']}")
    for row in formats.get("code_schema_modules", []):
        if not row.get("version"):
            out.append(f"PM_SCHEMA_UNVERSIONED code-schema-module {row['path']}")
    for path in formats.get("schemas", {}).get("undefined_identifiers", []):
        out.append(f"PM_SCHEMA_UNDEFINED identifier {path}")
    for path in formats.get("schemas", {}).get("schema_documents_without_reader", []):
        out.append(f"PM_SCHEMA_NO_READER schema-document {path}")
    for path in formats.get("schemas", {}).get("non_schema_documents", {}).get(
            "evidence_records_declaring_no_schema", []):
        out.append(f"PM_DOCUMENT_VERSION_UNDECLARED {path}")
    unnamed = digests.get("population", {}).get("unnamed", {})
    if unnamed.get("documents"):
        out.append(f"PM_DIGEST_ALGORITHM_UNNAMED {unnamed['documents']} documents "
                   f"({unnamed['occurrences']} occurrences)")
    absent = digests.get("population", {}).get("absent_markers", {})
    if absent.get("occurrences"):
        out.append(f"PM_DIGEST_ABSENT {absent['occurrences']} occurrences")
    if digests.get("population", {}).get("mislabelled_length", {}).get("occurrences"):
        out.append("PM_DIGEST_LENGTH_MISMATCH "
                   f"{digests['population']['mislabelled_length']['occurrences']}")
    for class_id in archival.get("classes_without_location", []):
        out.append(f"PM_CLASS_UNARCHIVED {class_id}")
    return out


# ---------------------------------------------------------------------------
# Self-test: one negative control per refusal, plus positive and determinism
# ---------------------------------------------------------------------------


def self_test() -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: str, rule: str | None = None) -> None:
        controls.append({"control": name, "passed": passed, "detail": detail,
                         "rule": rule})

    # 1. unversioned schema refused
    try:
        parse_schema_identifier("openssl-rs/thing")
        record("unversioned_schema_refused", False, "no refusal", "PM_SCHEMA_UNVERSIONED")
    except Refusal as refusal:
        record("unversioned_schema_refused", refusal.rule == "PM_SCHEMA_UNVERSIONED",
               refusal.rule, "PM_SCHEMA_UNVERSIONED")

    # 2. versioned schema accepted (positive)
    try:
        family, version, _part = parse_schema_identifier("openssl-rs/thing/v2")
        record("versioned_schema_accepted",
               family == "openssl-rs/thing" and version == "v2", f"{family} {version}")
    except Refusal as refusal:
        record("versioned_schema_accepted", False, refusal.rule)

    # 3. part marker is not a version
    try:
        _family, version, part = parse_schema_identifier("openssl-rs/thing/v1/part")
        record("part_marker_not_a_version", version == "v1" and part,
               f"{version} part={part}")
    except Refusal as refusal:
        record("part_marker_not_a_version", False, refusal.rule)

    # 4. undeclared document version refused
    try:
        require_document_version({"kind": "receipt"}, "evidence/x.json")
        record("undeclared_document_version_refused", False, "no refusal",
               "PM_DOCUMENT_VERSION_UNDECLARED")
    except Refusal as refusal:
        record("undeclared_document_version_refused",
               refusal.rule == "PM_DOCUMENT_VERSION_UNDECLARED", refusal.rule,
               "PM_DOCUMENT_VERSION_UNDECLARED")

    # 5. declared document accepted (positive)
    try:
        kind = classify_json_document({"schema": CLAIMS_IDENTIFIER}, "evidence/x.json")
        record("declared_document_accepted", kind["class"] == "schema_bearing", kind["class"])
    except Refusal as refusal:
        record("declared_document_accepted", False, refusal.rule)

    # 6. unnamed digest refused
    try:
        require_digest_algorithm(None)
        record("unnamed_digest_refused", False, "no refusal", "PM_DIGEST_ALGORITHM_UNNAMED")
    except Refusal as refusal:
        record("unnamed_digest_refused",
               refusal.rule == "PM_DIGEST_ALGORITHM_UNNAMED", refusal.rule,
               "PM_DIGEST_ALGORITHM_UNNAMED")

    # 7. named digest accepted (positive)
    scan = _scan_digests({"sha256": "a" * 64}, "evidence/x.json")
    record("named_digest_accepted", scan["named"].get("sha256") == 1,
           f"named={scan['named']}")

    # 8. an adjacent algorithm field names the digest
    scan = _scan_digests({"digest_algorithm": "sha256", "digest": "a" * 64},
                         "evidence/x.json")
    record("sibling_algorithm_field_names_digest",
           scan["named"].get("sha256") == 1 and not scan["unnamed"],
           f"named={scan['named']} unnamed={scan['unnamed']}")

    # 8a. an enclosing field that names the algorithm covers its path-keyed values
    scan = _scan_digests({"files_sha256": {"src/evp/legacy_md5.rs": "b" * 64}},
                         "evidence/x.json")
    record("enclosing_field_names_path_keyed_digest",
           scan["named"].get("sha256") == 1 and not scan["unnamed"]
           and not scan["mislabelled"],
           f"named={scan['named']} unnamed={scan['unnamed']} "
           f"mislabelled={scan['mislabelled']}")

    # 8b. an adjacent unadmitted algorithm is refused, not silently unnamed
    scan = _scan_digests({"digest_algorithm": "crc32", "digest": "a" * 64},
                         "evidence/x.json")
    record("sibling_unadmitted_algorithm_refused",
           scan["unadmitted"].get("crc32") == 1, f"unadmitted={scan['unadmitted']}")

    # 9. unadmitted algorithm refused
    try:
        require_digest_algorithm("crc32")
        record("unadmitted_algorithm_refused", False, "no refusal",
               "PM_DIGEST_ALGORITHM_UNADMITTED")
    except Refusal as refusal:
        record("unadmitted_algorithm_refused",
               refusal.rule == "PM_DIGEST_ALGORITHM_UNADMITTED", refusal.rule,
               "PM_DIGEST_ALGORITHM_UNADMITTED")

    # 10. admitted algorithm accepted (positive), including a normalised spelling
    try:
        canonical = require_digest_algorithm("SHA-256")
        record("admitted_algorithm_accepted", canonical == "sha256", canonical)
    except Refusal as refusal:
        record("admitted_algorithm_accepted", False, refusal.rule)

    # 11. a value that cannot be the digest it names is reported
    scan = _scan_digests({"sha256": "a" * 40}, "evidence/x.json")
    record("algorithm_length_mismatch_reported",
           len(scan["mislabelled"]) == 1 and scan["mislabelled"][0]["length"] == 40,
           f"mislabelled={scan['mislabelled']}")
    constant_scan = _scan_digests({"SHA256_DIGEST_LENGTH": "64"}, "evidence/x.json")
    record("constant_key_is_not_a_digest",
           not constant_scan["named"] and not constant_scan["non_digest_values"],
           f"named={constant_scan['named']} non_digest={constant_scan['non_digest_values']}")
    absent_scan = _scan_digests({"sha256": "UNRESOLVED"}, "evidence/x.json")
    record("absent_marker_reported",
           absent_scan["absent_markers"].get("sha256") == 1
           and not absent_scan["named"] and not absent_scan["non_digest_values"],
           f"absent={absent_scan['absent_markers']} named={absent_scan['named']}")
    path_scan = _scan_digests({"src/evp/legacy_md5.rs": "b" * 64}, "evidence/x.json")
    record("subject_path_is_not_an_algorithm_claim",
           not path_scan["named"] and path_scan["unnamed"].get("src/evp/legacy_md5.rs") == 1,
           f"named={path_scan['named']} unnamed={path_scan['unnamed']}")

    # 12. unarchived class reported
    fake = {
        "schema": "openssl-rs/etp-t13/archival/1",
        "classes": [{"id": "external_review_record", "required": True, "locations": [],
                     "archival_status": "NOT_ARCHIVED", "externally_durable": False,
                     "inside_repository": False, "tracked_files": 0}],
        "classes_without_location": ["external_review_record"],
        "external_durability": {"status": "NONE", "external_archives": [],
                                "persistent_identifiers": [],
                                "etp6_role": "BUNDLE_NOT_ARCHIVE"},
    }
    try:
        require_class_location(fake, "external_review_record")
        record("unarchived_class_reported", False, "no refusal", "PM_CLASS_UNARCHIVED")
    except Refusal as refusal:
        record("unarchived_class_reported",
               refusal.rule == "PM_CLASS_UNARCHIVED", refusal.rule, "PM_CLASS_UNARCHIVED")

    # 13. archived class with no false durability accepted (positive)
    fake_ok = {
        "schema": "openssl-rs/etp-t13/archival/1",
        "classes": [{"id": "source", "required": True, "locations": ["src"],
                     "archival_status": "IN_REPOSITORY_ONLY", "externally_durable": False,
                     "inside_repository": True, "tracked_files": 898}],
        "classes_without_location": [],
        "external_durability": {"status": "NONE", "external_archives": [],
                                "persistent_identifiers": [],
                                "etp6_role": "BUNDLE_NOT_ARCHIVE"},
        "archive_corruption_controls": {
            "controls": [{"control": f"c{index}", "passed": True, "detail": "fixture",
                          "rule": None} for index in range(4)],
        },
        "verifier_reconstructability": {
            "interpreter": {"requirement": "CPython 3.11"},
            "tools": [{"path": "forensics/tools/preservation.py"}],
            "not_recorded": ["the interpreter binary digest"],
        },
    }
    problems = validate_archival(fake_ok)
    record("archived_class_accepted", problems == [], str(problems))
    record("located_class_required", require_class_location(fake_ok, "source")["id"] == "source",
           "source")

    # 14. migration that rewrites history refused
    bad_migration = {
        "id": "MIG-BAD",
        "rule": "EXPLICIT_CONVERTER_PRESERVING_SOURCE",
        "source": {"path": "evidence/old.json", "retained": False},
        "history_rewritten": True,
    }
    problems = validate_migration(bad_migration)
    record("migration_rewrite_refused",
           any(item.startswith("PM_MIGRATION_HISTORY_REWRITTEN") for item in problems),
           str(problems), "PM_MIGRATION_HISTORY_REWRITTEN")

    # 14a. a converter that loses claim identities is refused
    identity_migration = {
        "id": "MIG-LOSS",
        "rule": "EXPLICIT_CONVERTER_PRESERVING_SOURCE",
        "source": {"path": "evidence/old.json", "retained": True},
        "history_rewritten": False,
        "preserved": {"ids_equal": False, "target_binds_source": True,
                      "mapped_verdicts_equal": True},
    }
    problems = validate_migration(identity_migration)
    record("migration_identity_loss_refused",
           any(item.startswith("PM_MIGRATION_IDENTITY_LOST") for item in problems),
           str(problems), "PM_MIGRATION_IDENTITY_LOST")

    # 15. preserving migration accepted (positive)
    good_migration = {
        "id": "MIG-GOOD",
        "rule": "EXPLICIT_CONVERTER_PRESERVING_SOURCE",
        "source": {"path": "evidence/old.json", "retained": True},
        "history_rewritten": False,
        "preserved": {"ids_equal": True, "target_binds_source": True,
                      "mapped_verdicts_equal": True},
    }
    record("preserving_migration_accepted", validate_migration(good_migration) == [],
           "no problem")

    # 16. a required change with no converter and no demonstration is refused
    bad_additive = {
        "id": "MIG-ADD",
        "rule": "FORWARD_ONLY_WITH_EXPLICIT_HISTORY",
        "history_rewritten": False,
        "required_changes": [{"revision": "abc", "tightened_paths": ["$"]}],
        "converter": None,
        "version_bumped": False,
        "population_acceptance": {"demonstrated": False},
    }
    problems = validate_migration(bad_additive)
    record("required_field_change_needs_converter",
           any("PM_MIGRATION_REQUIRED_FIELD_WITHOUT_CONVERTER" in item for item in problems),
           str(problems), "PM_MIGRATION_REQUIRED_FIELD_WITHOUT_CONVERTER")

    # 17. a required change whose retained documents are still accepted needs no converter
    good_additive = {
        "id": "MIG-ADD-OK",
        "rule": "FORWARD_ONLY_WITH_EXPLICIT_HISTORY",
        "history_rewritten": False,
        "required_changes": [{"revision": "abc", "retained_document_accepted": True}],
        "converter": None,
        "version_bumped": False,
        "population_acceptance": {"demonstrated": True, "problems": []},
        "required_change_resolution": {"unresolved_changes": 0},
    }
    record("required_change_with_acceptance_accepted",
           validate_migration(good_additive) == [], "no problem")

    # 18. an external durability claim is refused
    lying = {
        "schema": "openssl-rs/etp-t13/archival/1",
        "classes": [{"id": "source", "required": True, "locations": ["src"],
                     "archival_status": "IN_REPOSITORY_ONLY", "externally_durable": True,
                     "inside_repository": True, "tracked_files": 1}],
        "classes_without_location": [],
        "external_durability": {"status": "NONE", "external_archives": [],
                                "persistent_identifiers": [],
                                "etp6_role": "BUNDLE_NOT_ARCHIVE"},
    }
    try:
        problems = validate_archival(lying)
    except Refusal as refusal:
        problems = [f"{refusal.rule}"]
    record("external_durability_claim_refused",
           any(item.startswith("PM_EXTERNAL_DURABILITY_CLAIMED") for item in problems),
           str(problems), "PM_EXTERNAL_DURABILITY_CLAIMED")

    # 19. drift is detected by the pure comparison
    recorded = {"a": 1, "b": [1, 2]}
    derived = {"a": 1, "b": [1, 3]}
    record("drift_detected",
           compare_records(recorded, derived, ("a", "b"), "x") == ["x:b"],
           "x:b")

    # 20. repository object identity and content digests are separate systems
    good_candidate = {"commit": "a" * 40, "object_format": "sha1",
                      "object_id_hex_length": 40}
    try:
        require_object_format(good_candidate, "sha1")
        record("object_format_match_accepted", True, "sha1/40")
    except Refusal as refusal:
        record("object_format_match_accepted", False, refusal.rule)

    mismatched = {"commit": "a" * 40, "object_format": "sha256",
                  "object_id_hex_length": 40}
    try:
        require_object_format(mismatched, "sha1")
        record("object_format_mismatch_refused", False, "no refusal",
               "PM_IDENTITY_OBJECT_FORMAT_MISMATCH")
    except Refusal as refusal:
        record("object_format_mismatch_refused",
               refusal.rule == "PM_IDENTITY_OBJECT_FORMAT_MISMATCH", refusal.rule,
               "PM_IDENTITY_OBJECT_FORMAT_MISMATCH")

    wrong_length = {"commit": "a" * 64, "object_format": "sha1",
                    "object_id_hex_length": 64}
    try:
        require_object_format(wrong_length, "sha1")
        record("object_id_length_refused", False, "no refusal",
               "PM_IDENTITY_OBJECT_FORMAT_MISMATCH")
    except Refusal as refusal:
        record("object_id_length_refused",
               refusal.rule == "PM_IDENTITY_OBJECT_FORMAT_MISMATCH", refusal.rule,
               "PM_IDENTITY_OBJECT_FORMAT_MISMATCH")

    try:
        require_object_format({"commit": "a" * 40, "object_format": "md5"}, "sha1")
        record("unknown_object_format_refused", False, "no refusal",
               "PM_IDENTITY_OBJECT_FORMAT_UNKNOWN")
    except Refusal as refusal:
        record("unknown_object_format_refused",
               refusal.rule == "PM_IDENTITY_OBJECT_FORMAT_UNKNOWN", refusal.rule,
               "PM_IDENTITY_OBJECT_FORMAT_UNKNOWN")

    try:
        refuse_conflation({"object_id_algorithm": "sha256", "commit": "a" * 40}, "sha1")
        record("conflation_refused", False, "no refusal", "PM_IDENTITY_CONFLATION")
    except Refusal as refusal:
        record("conflation_refused", refusal.rule == "PM_IDENTITY_CONFLATION",
               refusal.rule, "PM_IDENTITY_CONFLATION")
    try:
        refuse_conflation({"object_id_algorithm": "sha1", "commit": "a" * 40}, "sha1")
        record("non_conflated_identity_accepted", True, "sha1")
    except Refusal as refusal:
        record("non_conflated_identity_accepted", False, refusal.rule)

    # 21. an absent signature system that names algorithms is refused
    claimed = {
        "schema": "openssl-rs/etp-t13/identity-systems/1",
        "candidate": good_candidate,
        "systems": {
            "repository_object_identity": {"object_format": "sha1", "oid_hex_length": 40},
            "content_digests": {},
            "signature_and_attestation": {"status": "ABSENT", "algorithms": ["ed25519"]},
            "digest_renewal": {"records": [{"subject": "x", "bytes_identical": True,
                                              "old": {"algorithm": "sha256"},
                                              "new": {"algorithm": "sha384"}}]},
        },
        "distinctness_evidence": {"object_id": "a" * 40,
                                   "content_digest": {"algorithm": "sha256",
                                                       "digest": "b" * 64}},
    }
    try:
        problems = validate_identity_systems(claimed)
    except Refusal as refusal:
        problems = [refusal.rule]
    record("absent_signature_algorithm_refused",
           any(item.startswith("PM_SIGNATURE_ALGORITHM_CLAIMED") for item in problems),
           str(problems), "PM_SIGNATURE_ALGORITHM_CLAIMED")

    # 22. renewal over identical bytes is accepted; over different bytes refused
    sample = b"archived evidence bytes\n"
    renewal = {
        "subject": "evidence/x.bin",
        "subject_content_sha256": hashlib.sha256(sample).hexdigest(),
        "old": {"algorithm": "sha256", "digest": digest_bytes("sha256", sample)},
        "new": {"algorithm": "sha384", "digest": digest_bytes("sha384", sample)},
        "bytes_identical": True,
    }
    try:
        verify_renewal(renewal, sample)
        record("renewal_identical_bytes_accepted", True, "sha256+sha384")
    except Refusal as refusal:
        record("renewal_identical_bytes_accepted", False, refusal.rule)
    try:
        verify_renewal(renewal, sample + b"x")
        record("renewal_differing_bytes_refused", False, "no refusal",
               "PM_RENEWAL_BYTES_CHANGED")
    except Refusal as refusal:
        record("renewal_differing_bytes_refused",
               refusal.rule == "PM_RENEWAL_BYTES_CHANGED", refusal.rule,
               "PM_RENEWAL_BYTES_CHANGED")

    # 23. the cross-version reader accepts two versions and refuses a third
    v1 = {"schema": f"{CROSS_VERSION_FAMILY}/v1", "family": "f",
          "source_identity": {}, "verdict": "x", "closure": {}}
    v2 = {"schema": f"{CROSS_VERSION_FAMILY}/v2", "family": "f", "graph": {},
          "precision": {}, "refusals": []}
    try:
        read_v1 = read_versioned_document(v1, "v1.json")
        read_v2 = read_versioned_document(v2, "v2.json")
        record("two_versions_accepted",
               read_v1["version"] == "v1" and read_v2["version"] == "v2",
               f"{read_v1['version']},{read_v2['version']}")
    except Refusal as refusal:
        record("two_versions_accepted", False, refusal.rule)
    unknown = dict(v2)
    unknown["schema"] = f"{CROSS_VERSION_FAMILY}/v3"
    try:
        read_versioned_document(unknown, "v3.json")
        record("unknown_version_refused", False, "no refusal", "PM_SCHEMA_UNKNOWN_VERSION")
    except Refusal as refusal:
        record("unknown_version_refused",
               refusal.rule == "PM_SCHEMA_UNKNOWN_VERSION", refusal.rule,
               "PM_SCHEMA_UNKNOWN_VERSION")

    # 24. the four archive corruption controls
    controls.extend(archive_controls())

    # 25. every admission rule has a control
    covered = {control["rule"] for control in controls if control.get("rule")}
    missing = sorted(set(ADMISSION_RULES) - covered)
    record("every_admission_rule_has_a_control", not missing, f"missing={missing}")

    return controls


def determinism_controls(repo: Path, commit: str,
                        first: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Two derivations over the same candidate must be byte-identical.

    When the caller already derived the four records, it passes them in so the
    expensive population scan runs once more, not twice more.
    """
    names = ("formats", "digests", "archival", "identity")
    if first is None:
        first = {name: derive(repo, commit, name) for name in names}
    first_text = {name: _serialise(first[name]) for name in names}
    second_text = {name: _serialise(derive(repo, commit, name)) for name in names}
    controls = []
    for name in names:
        controls.append({
            "control": f"determinism_{name}",
            "passed": first_text[name] == second_text[name],
            "detail": hashlib.sha256(first_text[name].encode()).hexdigest(),
            "rule": None,
        })
    return controls


def derive(repo: Path, commit: str, which: str) -> dict[str, Any]:
    if which == "formats":
        return derive_formats(repo, commit)
    if which == "digests":
        return derive_digests(repo, commit)
    if which == "archival":
        return derive_archival(repo, commit)
    if which == "identity":
        return derive_identity_systems(repo, commit)
    raise ValueError(which)


def _serialise(record: dict[str, Any]) -> str:
    return json.dumps(record, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def build(repo: Path, rev: str) -> int:
    commit = resolve_commit(repo, rev)
    formats = derive_formats(repo, commit)
    digests = derive_digests(repo, commit)
    archival = derive_archival(repo, commit)
    identity = derive_identity_systems(repo, commit)
    out = repo / EVIDENCE
    out.mkdir(parents=True, exist_ok=True)
    for path, record in ((FORMATS_PATH, formats), (DIGESTS_PATH, digests),
                         (ARCHIVAL_PATH, archival), (IDENTITY_PATH, identity)):
        (repo / path).write_text(_serialise(record), encoding="utf-8")
    cross = formats["cross_version_reader"]
    print(f"wrote {FORMATS_PATH} ({len(formats['schemas']['entries'])} versioned identifiers, "
          f"{formats['schemas']['counts']['schema_definitions_unversioned']} unversioned definitions, "
          f"cross-version {cross['version_population']})")
    print(f"wrote {DIGESTS_PATH} ({digests['population']['named']['documents']} named, "
          f"{digests['population']['unnamed']['documents']} unnamed documents, "
          f"{digests['population']['repository_object_ids']['occurrences']} repository object ids, "
          f"{len(digests['renewal_records'])} renewals)")
    print(f"wrote {ARCHIVAL_PATH} ({len(archival['classes'])} classes, "
          f"{len(archival['classes_without_location'])} without a location, "
          f"{len(archival['archive_corruption_controls']['controls'])} archive controls)")
    print(f"wrote {IDENTITY_PATH} (object format {identity['candidate']['object_format']}, "
          f"{identity['systems']['signature_and_attestation']['status']} signatures)")
    return 0


def validate(repo: Path, strict: bool = False) -> int:
    failures: list[str] = []
    records = {}
    for path, validator in ((FORMATS_PATH, validate_formats),
                            (DIGESTS_PATH, validate_digests),
                            (ARCHIVAL_PATH, validate_archival),
                            (IDENTITY_PATH, validate_identity_systems)):
        full = repo / path
        if not full.exists():
            print(f"REFUSED PM_RECORD_MISSING {path}", file=sys.stderr)
            return 2
        record = _load_json(full)
        records[path] = record
        failures.extend(validator(record))

    commit = records[FORMATS_PATH].get("candidate", {}).get("commit")

    # Every record's candidate names the repository-identity system. If the
    # repository reports a different object format, no record is read as if the
    # ids were comparable.
    try:
        observed = repository_object_format(repo)
    except Refusal as refusal:
        observed = None
        failures.append(f"{refusal.rule} {refusal.path}: {refusal.detail}")
    if observed:
        for path in (FORMATS_PATH, DIGESTS_PATH, ARCHIVAL_PATH, IDENTITY_PATH):
            candidate = records[path].get("candidate") or {}
            try:
                require_object_format(candidate, observed)
                refuse_conflation(candidate, observed)
            except Refusal as refusal:
                failures.append(f"{refusal.rule} {path}: {refusal.detail}")

    tree_result: dict[str, Any] | None = None
    if not commit:
        failures.append("PM_RECORD_SHAPE FORMATS.json: no candidate commit")
    else:
        try:
            tree_result = check_tree_records(repo, commit)
            failures.extend(f"PM_DRIFT {item}" for item in tree_result["mismatches"])
        except Exception as error:  # a candidate that cannot be read is a refusal
            failures.append(f"PM_CANDIDATE_UNREADABLE {commit}: {error}")

    # A renewal record is verified against the archived bytes, not only against
    # itself; a record whose digests cover different bytes is refused here.
    if commit:
        for entry in records[DIGESTS_PATH].get("renewal_records") or []:
            subject = entry.get("subject")
            try:
                raw = _git_bytes(repo, "show", f"{commit}:{subject}")
                verify_renewal(entry, raw)
            except Refusal as refusal:
                failures.append(f"{refusal.rule} {refusal.path}: {refusal.detail}")
            except subprocess.CalledProcessError:
                failures.append(f"PM_CANDIDATE_UNREADABLE renewal subject {subject}")

    controls = self_test()
    if commit:
        try:
            controls += determinism_controls(
                repo, commit,
                first=tree_result if tree_result is not None else None)
        except Exception as error:
            failures.append(f"PM_CANDIDATE_UNREADABLE determinism: {error}")
    for control in controls:
        if not control["passed"]:
            failures.append(f"PM_CONTROL_FAILED {control['control']}: {control['detail']}")

    population = []
    if tree_result is not None:
        population = open_populations(tree_result["formats"], tree_result["digests"],
                                      tree_result["archival"])

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print(f"PASS {FORMATS_PATH} {DIGESTS_PATH} {ARCHIVAL_PATH} {IDENTITY_PATH}; "
          f"{len(controls)} controls passed; candidate "
          f"{records[FORMATS_PATH]['candidate']['commit']}; "
          f"object format {observed}")
    for item in population:
        print(f"OPEN {item}")
    if strict:
        if population:
            for item in population:
                print(f"REFUSED {item}", file=sys.stderr)
            return 1
        print("PASS strict: no open population")
    return 0


def status(repo: Path, class_id: str) -> int:
    path = repo / ARCHIVAL_PATH
    if not path.exists():
        print(f"REFUSED PM_RECORD_MISSING {ARCHIVAL_PATH}", file=sys.stderr)
        return 2
    record = _load_json(path)
    try:
        row = require_class_location(record, class_id)
    except Refusal as refusal:
        print(f"REFUSED {refusal.rule} {refusal.path}: {refusal.detail}", file=sys.stderr)
        return 1
    print(f"ARCHIVED {class_id} inside_repository={row['inside_repository']} "
          f"externally_durable={row['externally_durable']} "
          f"tracked_files={row['tracked_files']} etp6_coverage={row['etp6_coverage']}")
    return 0


def archive_check(archive_path: str, manifest_path: str) -> int:
    """Verify an archive against a manifest; used by the corruption controls."""
    archive = Path(archive_path)
    manifest_file = Path(manifest_path)
    if not archive.is_file() or not manifest_file.is_file():
        print("REFUSED PM_INVOCATION archive-check needs an archive and a manifest file",
              file=sys.stderr)
        return 2
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    try:
        result = verify_archive_bytes(archive.read_bytes(), manifest)
    except Refusal as refusal:
        print(f"REFUSED {refusal.rule} {refusal.path}: {refusal.detail}", file=sys.stderr)
        return 1
    print(f"PASS archive {result['members']}/{result['manifest_members']} members, "
          f"{result['digest_algorithm']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?",
                        choices=("build", "validate", "status", "archive-check"),
                        default="validate")
    parser.add_argument("class_id", nargs="?", default=None)
    parser.add_argument("manifest_path", nargs="?", default=None)
    parser.add_argument("--repo", default=str(REPO_ROOT))
    parser.add_argument("--at", default="HEAD", help="candidate revision for build")
    parser.add_argument("--strict", action="store_true",
                        help="turn recorded populations into refusals")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--determinism", action="store_true")
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()

    if args.self_test:
        controls = self_test()
        for control in controls:
            status_word = "PASS" if control["passed"] else "FAIL"
            print(f"{status_word} {control['control']}: {control['detail']}")
        return 0 if all(control["passed"] for control in controls) else 1

    if args.determinism:
        commit = resolve_commit(repo, args.at)
        controls = determinism_controls(repo, commit)
        for control in controls:
            status_word = "PASS" if control["passed"] else "FAIL"
            print(f"{status_word} {control['control']}: {control['detail']}")
        return 0 if all(control["passed"] for control in controls) else 1

    if args.command == "build":
        return build(repo, args.at)
    if args.command == "status":
        if not args.class_id:
            print("REFUSED PM_INVOCATION status requires a class identifier", file=sys.stderr)
            return 2
        return status(repo, args.class_id)
    if args.command == "archive-check":
        if not args.class_id or not args.manifest_path:
            print("REFUSED PM_INVOCATION archive-check requires ARCHIVE and MANIFEST",
                  file=sys.stderr)
            return 2
        return archive_check(args.class_id, args.manifest_path)
    return validate(repo, args.strict)


if __name__ == "__main__":
    sys.exit(main())
