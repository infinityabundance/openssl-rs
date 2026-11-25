#!/usr/bin/env python3
"""publication.py -- classify evidence, build a publishable bundle, verify it.

Why this tool exists
--------------------
`docs/ETP-ADDENDUM-B.md` §B.15 requires a publication policy and §B.16 requires a
pre-publication classification and sanitisation gate: a transparency-log
submission is potentially permanent and public, so material that was not
classified is not published, and private material is never published.  This
venue has neither a public Rekor endpoint nor an external party, so the
publication itself is `NOT_RUN`; what can be done offline is to make the gate
real, build one bundle out of classified material only, and give an outsider a
verifier that runs from a fresh directory with no access to this tree.

The default is **not to publish**.  A path that no rule classifies is
`UNCLASSIFIED` and a bundle containing it is refused, not partially redacted.
The four classes are `PUBLIC_RELEASE_CRITICAL`, `PUBLIC_SUPPORTING`,
`INTERNAL_NOT_PUBLISHED` and `PRIVATE_NEVER_PUBLISHED`.

Commands
--------
    publication.py scan   [--policy PATH] [--json] [--out PATH]
    publication.py classify PATH [PATH ...]
    publication.py build  [--policy PATH] [--out DIR]
    publication.py verify [--policy PATH] [--bundle DIR] [--json]
    publication.py claim  [--publish] [--endpoint URL] [--external-verified]

Exit status: 0 when the requested operation succeeds, 1 for a refusal, 2 for a
usage error.  `build` refuses and writes nothing on any refusal.  Bytes are
deterministic: no clock, no environment and no absolute path enters a record.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import base64
import binascii
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY = REPO_ROOT / "evidence" / "b4" / "CLASSIFICATION.json"
DEFAULT_BUNDLE = REPO_ROOT / "evidence" / "b4" / "BUNDLE"

POLICY_SCHEMA = "openssl-rs/b4/classification/1"
MANIFEST_SCHEMA = "openssl-rs/b4/bundle-manifest/1"
MANIFEST_NAME = "MANIFEST.json"
ENTRY_POINT = "verify.py"
ENTRY_SHELL = "verify.sh"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

PUBLIC_RELEASE_CRITICAL = "PUBLIC_RELEASE_CRITICAL"
PUBLIC_SUPPORTING = "PUBLIC_SUPPORTING"
INTERNAL_NOT_PUBLISHED = "INTERNAL_NOT_PUBLISHED"
PRIVATE_NEVER_PUBLISHED = "PRIVATE_NEVER_PUBLISHED"
UNCLASSIFIED = "UNCLASSIFIED"

CLASSES = (
    PUBLIC_RELEASE_CRITICAL,
    PUBLIC_SUPPORTING,
    INTERNAL_NOT_PUBLISHED,
    PRIVATE_NEVER_PUBLISHED,
)
PUBLISHABLE = (PUBLIC_RELEASE_CRITICAL, PUBLIC_SUPPORTING)

#: Stable refusal vocabulary.  One control per code is recorded in
#: `evidence/b4/CONTROLS.json`; the normative document names every code.
REFUSALS = {
    "PB_REFUSED_UNCLASSIFIED": (
        "an artefact no policy rule classifies; unclassified material is never published"
    ),
    "PB_REFUSED_PRIVATE_MATERIAL": (
        "an artefact classified PRIVATE_NEVER_PUBLISHED; it may not enter a bundle"
    ),
    "PB_REFUSED_INTERNAL_MATERIAL": (
        "an artefact classified INTERNAL_NOT_PUBLISHED; only release-critical and "
        "supporting material may enter a bundle"
    ),
    "PB_REFUSED_PRIVATE_REFERENCE": (
        "a member references a private scratch path, a home directory, a host-only "
        "path, a token or a credential"
    ),
    "PB_REFUSED_ABSOLUTE_PATH": "a member references an absolute path",
    "PB_REFUSED_UNBOUND_MEMBER": (
        "a member's digest is absent from the manifest, does not match it, or the "
        "member is not declared at all"
    ),
    "PB_REFUSED_RELEASE_MEMBER_MISSING": (
        "a bundle omits a member the policy declares release-critical"
    ),
    "PB_REFUSED_CLASSIFICATION_MISMATCH": (
        "a manifest classification disagrees with the policy for the member's source"
    ),
    "PB_REFUSED_NO_PUBLIC_SERVICE": (
        "a publication was claimed but no admitted public endpoint exists"
    ),
    "PB_REFUSED_EXTERNAL_NOT_RUN": (
        "independent verification was claimed but no external party ran it"
    ),
    "PB_REFUSED_MANIFEST_INVALID": (
        "the bundle manifest is absent, does not parse, has a foreign schema, or its "
        "body does not hash to its own digest"
    ),
    "PB_REFUSED_IO": "an input could not be read",
    "PB_REFUSED_USAGE": "the command line was used incorrectly",
}

OUTCOMES = (
    "PUBLIC_BUNDLE_VERIFIED",
    "BUNDLE_INVALID",
    "SCAN_COMPLETE",
    "BUILD_COMPLETE",
    "CLAIM_REFUSED",
)


class Refusal(Exception):
    """A refusal carries a stable code; the caller never sees a bare traceback."""

    def __init__(self, code: str, detail: str) -> None:
        if code not in REFUSALS:
            raise ValueError(f"unknown refusal code {code!r}")
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _refuse(code: str, detail: str) -> None:
    raise Refusal(code, detail)


# ---------------------------------------------------------------------------
# Canonical bytes and digests
# ---------------------------------------------------------------------------


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def pretty(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_body(document: Mapping[str, Any], field: str) -> str:
    body = {key: value for key, value in document.items() if key != field}
    return sha256_bytes(canonical(body))


# ---------------------------------------------------------------------------
# Policy loading and the classification decision
# ---------------------------------------------------------------------------

#: Content whose presence makes a member unpublishable.  The first group names a
#: private or host-only location; the second names a secret.  Both are refused;
#: the code differs so an operator can tell *what* was found.
PRIVATE_REFERENCE_PATTERNS = (
    ("court-scratch", re.compile("court" + "/" + "tmp")),
    ("home-directory", re.compile(r"(?<![\w.])/(?:home|Users)/[A-Za-z0-9_.-]+")),
    ("root-home", re.compile(r"(?<![\w.])" + "/" + "root" + "/")),
    ("host-only-tmp", re.compile(r"(?<![\w.])" + "/" + "tmp" + "/[A-Za-z0-9_.-]+")),
    ("file-url", re.compile("file" + ":" + "//")),
    ("bearer-token", re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("authorization-header", re.compile(r"(?i)Authorization:\s*\S+")),
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private-key-pem", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "credential-assignment",
        re.compile(
            r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret"
            r"|password|passwd|passphrase)\s*[:=]\s*[\"'][^\"']{6,}[\"']"
        ),
    ),
)

#: A JSON string value that is an absolute POSIX filesystem path.  A URL does
#: not match, and neither does a JSON pointer such as `/records`: the value has
#: to begin at a conventional filesystem root and carry an interior separator.
ABSOLUTE_PATH_PATTERN = re.compile(
    r'"/(?:home|Users|root|tmp|var|usr|etc|opt|mnt|srv|work|data|proc|sys|dev|run)/[^"\s]*'
    r'|[A-Za-z]:\\[^"\s]*"'
)


def _pattern_matches(pattern: str, path: str) -> bool:
    """A basename pattern or a path glob; `**/` crosses directories."""
    return fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(
        path.rsplit("/", 1)[-1], pattern
    )


def validate_policy(policy: Mapping[str, Any]) -> None:
    if not isinstance(policy, Mapping):
        _refuse("PB_REFUSED_MANIFEST_INVALID", "the policy is not an object")
    if policy.get("default") not in (UNCLASSIFIED,):
        _refuse(
            "PB_REFUSED_MANIFEST_INVALID",
            "the policy default must be UNCLASSIFIED: publication is opt-in",
        )
    classes = policy.get("classes")
    if not isinstance(classes, Mapping) or set(classes) != set(CLASSES):
        _refuse(
            "PB_REFUSED_MANIFEST_INVALID",
            "the policy must define exactly the four classes",
        )
    rules = policy.get("rules")
    if not isinstance(rules, list) or not rules:
        _refuse("PB_REFUSED_MANIFEST_INVALID", "the policy defines no rules")
    for rule in rules:
        if not isinstance(rule, Mapping):
            _refuse("PB_REFUSED_MANIFEST_INVALID", "a rule is not an object")
        if rule.get("class") not in CLASSES:
            _refuse(
                "PB_REFUSED_MANIFEST_INVALID",
                f"rule {rule.get('id')!r} names no declared class",
            )
        if rule.get("kind") not in ("exact", "under", "depth"):
            _refuse(
                "PB_REFUSED_MANIFEST_INVALID",
                f"rule {rule.get('id')!r} has an unknown kind",
            )
        if not isinstance(rule.get("reason"), str) or not rule["reason"].strip():
            _refuse(
                "PB_REFUSED_MANIFEST_INVALID",
                f"rule {rule.get('id')!r} records no reason",
            )
    critical = policy.get("releaseCritical")
    if not isinstance(critical, list):
        _refuse(
            "PB_REFUSED_MANIFEST_INVALID", "releaseCritical is not an array"
        )


def classify_path(policy: Mapping[str, Any], path: str) -> tuple[str, str, str]:
    """Return `(class, rule_id, reason)` for a repository-relative path.

    Precedence is a private pattern, then an exact rule, then a scope rule, then
    the unclassified default.  A private pattern outranks everything, so a
    secret-bearing file cannot be promoted by naming it, and no catch-all ever
    turns an unknown path into a publishable one.
    """
    for entry in policy.get("privatePatterns", []):
        if _pattern_matches(entry["pattern"], path):
            return PRIVATE_NEVER_PUBLISHED, entry["id"], entry["reason"]
    for rule in policy["rules"]:
        if rule["kind"] == "exact" and rule.get("path") == path:
            return rule["class"], rule["id"], rule["reason"]
    for rule in policy["rules"]:
        if rule["kind"] == "under":
            prefix = rule["path"]
            if path == prefix or path.startswith(prefix):
                return rule["class"], rule["id"], rule["reason"]
        if rule["kind"] == "depth":
            parts = path.split("/")
            if (
                len(parts) == int(rule["depth"])
                and parts[0] == rule["root"]
            ):
                return rule["class"], rule["id"], rule["reason"]
    return (
        UNCLASSIFIED,
        "no-rule",
        "no policy rule classifies this path; the default is not to publish",
    )


# ---------------------------------------------------------------------------
# Content scans
# ---------------------------------------------------------------------------


def _walk_strings(value: Any, depth: int = 0) -> Iterable[str]:
    if depth > 64:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _walk_strings(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item, depth + 1)


def _decoded_payload_strings(document: Any) -> Iterable[str]:
    """Decode a DSSE-style base64 payload so its text is scanned too."""
    if not isinstance(document, Mapping):
        return
    payload = document.get("payload")
    if not isinstance(payload, str) or len(payload) < 8:
        return
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return
    try:
        yield raw.decode("utf-8")
    except UnicodeDecodeError:
        return


def member_texts(path: str, data: bytes) -> Iterable[str]:
    """Every text a member exposes: its bytes, its JSON strings, its payload."""
    yield data.decode("utf-8", "replace")
    if not path.endswith(".json"):
        return
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return
    yield from _walk_strings(document)
    yield from _decoded_payload_strings(document)


def scan_member_text(path: str, data: bytes) -> tuple[str, str] | None:
    """Return `(code, detail)` for the first private reference or absolute path."""
    for text in member_texts(path, data):
        for name, pattern in PRIVATE_REFERENCE_PATTERNS:
            match = pattern.search(text)
            if match:
                return (
                    "PB_REFUSED_PRIVATE_REFERENCE",
                    f"{path}: {name}: {match.group(0)[:60]!r}",
                )
        match = ABSOLUTE_PATH_PATTERN.search(text)
        if match:
            return (
                "PB_REFUSED_ABSOLUTE_PATH",
                f"{path}: {match.group(0)[:60]!r}",
            )
    return None


# ---------------------------------------------------------------------------
# The declared input set and the bounded scan
# ---------------------------------------------------------------------------


def _git(repo: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", str(repo), *arguments],
        capture_output=True,
        check=False,
    )


def _tracked_at(repo: Path, commit: str, roots: Iterable[str]) -> list[str]:
    arguments = ["ls-tree", "-r", "--name-only", commit, "--", *roots]
    result = _git(repo, *arguments)
    if result.returncode != 0:
        _refuse(
            "PB_REFUSED_IO",
            f"git ls-tree {commit} failed: {result.stderr.decode('utf-8', 'replace').strip()}",
        )
    return [line for line in result.stdout.decode("utf-8").splitlines() if line]


def _files_under(directory: Path, repo: Path) -> list[str]:
    if not directory.is_dir():
        return []
    return sorted(
        str(path.relative_to(repo))
        for path in directory.rglob("*")
        if path.is_file()
    )


def declared_population(
    policy: Mapping[str, Any], repo: Path = REPO_ROOT
) -> tuple[list[str], dict[str, Any]]:
    """The bounded input set: the pinned tree plus the declared directories.

    Pinning the commit is what makes the measurement reproducible: a record
    committed later does not change the population this run measured.  The
    bundle directories are added because they are the material under test and
    they are produced before the scan.
    """
    declared = policy.get("declaredInputSet") or {}
    commit = declared.get("commit")
    roots = declared.get("roots") or ["evidence"]
    excluded = tuple(declared.get("excludePrefixes") or ())
    if not commit:
        _refuse("PB_REFUSED_IO", "the policy declares no input commit")
    tracked = _tracked_at(repo, commit, roots)
    kept = [
        path
        for path in tracked
        if not any(path == prefix or path.startswith(prefix) for prefix in excluded)
    ]
    extra: list[str] = []
    for directory in declared.get("includeDirectories") or []:
        extra.extend(_files_under(repo / directory, repo))
    population = sorted(set(kept) | set(extra))
    meta = {
        "commit": commit,
        "roots": list(roots),
        "excludePrefixes": list(excluded),
        "includeDirectories": list(declared.get("includeDirectories") or []),
        "trackedAtCommit": len(tracked),
        "addedFromDirectories": len([p for p in extra if p not in set(tracked)]),
        "excluded": len(tracked) - len(kept),
        "population": len(population),
    }
    return population, meta


def scan_tree(
    policy: Mapping[str, Any], repo: Path = REPO_ROOT
) -> dict[str, Any]:
    """Classify the declared population and bound the content inspection."""
    population, meta = declared_population(policy, repo)
    bound = policy.get("scanBound") or {}
    max_files = int(bound.get("maxFiles", 1200))
    max_per_file = int(bound.get("maxBytesPerMember", 65536))
    max_total = int(bound.get("maxBytesTotal", 33554432))

    counts = {name: 0 for name in CLASSES}
    counts[UNCLASSIFIED] = 0
    basis = {"explicit": 0, "scope": 0, "privatePattern": 0, "unclassified": 0}
    private_references: list[str] = []
    absolute_paths: list[str] = []
    content_scanned = 0
    content_skipped = 0
    truncated = 0
    bytes_read = 0
    bound_reached = False

    for index, path in enumerate(population):
        if index >= max_files:
            bound_reached = True
            break
        klass, rule_id, _reason = classify_path(policy, path)
        counts[klass] += 1
        if klass == UNCLASSIFIED:
            basis["unclassified"] += 1
        elif rule_id.startswith("scope-") or rule_id.startswith("top-level"):
            basis["scope"] += 1
        elif rule_id.startswith("private-"):
            basis["privatePattern"] += 1
        else:
            basis["explicit"] += 1
        if bytes_read >= max_total:
            content_skipped += 1
            bound_reached = True
            continue
        target = repo / path
        try:
            with target.open("rb") as handle:
                data = handle.read(min(max_per_file, max_total - bytes_read))
        except OSError:
            content_skipped += 1
            continue
        content_scanned += 1
        bytes_read += len(data)
        if len(data) == max_per_file:
            truncated += 1
            bound_reached = True
        finding = scan_member_text(path, data)
        if finding is not None:
            code, detail = finding
            if code == "PB_REFUSED_PRIVATE_REFERENCE":
                private_references.append(path)
            else:
                absolute_paths.append(path)

    return {
        "schema": "openssl-rs/b4/scan/1",
        "populationSource": meta,
        "bound": {
            "maxFiles": max_files,
            "maxBytesPerMember": max_per_file,
            "maxBytesTotal": max_total,
            "reached": bound_reached,
            "filesConsidered": len(population),
            "contentScanned": content_scanned,
            "contentNotScanned": content_skipped,
            "truncatedMembers": truncated,
            "bytesRead": bytes_read,
            "note": (
                "classification uses the path only and covers the whole population; "
                "the content scan is bounded per member and in total, so the reference "
                "counts are lower bounds over the uninspected tail"
            ),
        },
        "counts": counts,
        "classified": sum(counts[name] for name in CLASSES),
        "unclassified": counts[UNCLASSIFIED],
        "private": counts[PRIVATE_NEVER_PUBLISHED],
        "basis": basis,
        "referenceScan": {
            "privateReferenceArtefacts": len(private_references),
            "absolutePathArtefacts": len(absolute_paths),
            "privateReferenceExamples": private_references[:10],
            "absolutePathExamples": absolute_paths[:10],
        },
    }


# ---------------------------------------------------------------------------
# The bundle: members, manifest, and the generated entry point
# ---------------------------------------------------------------------------

#: The five source artefacts.  The four release-critical ones are exactly the
#: policy's `releaseCritical` set; the A10 envelope is supporting material.
BUNDLE_SOURCES = (
    {
        "member": "members/a9-statement-a8-shard-000.json",
        "source": "evidence/a9/STATEMENTS/a8-shard-000.json",
        "role": "in-toto statement (A9) for the A8 shard",
        "classification": PUBLIC_RELEASE_CRITICAL,
    },
    {
        "member": "members/a10-envelope-a8-shard-000.json",
        "source": "evidence/a10/ENVELOPES/a8-shard-000.json",
        "role": "DSSE envelope (A10) over the A8 shard statement; test-only signature",
        "classification": PUBLIC_SUPPORTING,
    },
    {
        "member": "members/b1-publication.json",
        "source": "evidence/b1/PUBLICATION.json",
        "role": "B1 fixture publication record, identity FIXTURE-1",
        "classification": PUBLIC_RELEASE_CRITICAL,
    },
    {
        "member": "members/a5-admission.json",
        "source": "evidence/a5/ADMISSION.json",
        "role": "A5 admission record: the state each declared population is admitted at",
        "classification": PUBLIC_RELEASE_CRITICAL,
    },
    {
        "member": "members/a17-freeze-forward.json",
        "source": "evidence/a17/FREEZE-forward.json",
        "role": "A17 forward-freeze record (OPEN); a forward commitment, not a closure",
        "classification": PUBLIC_RELEASE_CRITICAL,
    },
)

GENERATED_ROLES = {
    "README.md": "bundle description, member table and non-claims",
    ENTRY_POINT: "independently executable verifier",
    ENTRY_SHELL: "shell convenience form of the verifier",
}

ENTRY_SHELL_SOURCE = """#!/bin/sh
# The shell form of verify.py. It calls no external command: the script's own
# directory is derived by parameter expansion, and the interpreter is taken from
# PATH, which the caller controls.
set -eu
here=${0%/*}
[ "$here" = "$0" ] && here=.
exec python3 -I -S -B "$here/verify.py" "$@"
"""

ENTRY_POINT_SOURCE = '''#!/usr/bin/env python3
"""Verify a public publication bundle from its own files alone.

Run this program in the bundle directory.  It imports nothing from the project
that produced the bundle: every input is a file beside it.

    python3 verify.py              # check, print one JSON line, exit 0/1
    sh verify.sh                   # the same, through the shell wrapper

It checks the manifest body against its own digest, every member against its
recorded size and SHA-256, that no undeclared file is present, that every
release-critical member the embedded policy declares is present with the
declared class, that each member's class agrees with the embedded policy, that
each member carries no private reference and no absolute path, and that every
declared subject label occurs in its member.

A pass means these files are internally consistent and classified for
publication.  It does not mean any external party ran this program, and it does
not mean a transparency log published anything.
"""
from __future__ import annotations

import base64
import binascii
import fnmatch
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = "MANIFEST.json"
CLASSES = (
    "PUBLIC_RELEASE_CRITICAL",
    "PUBLIC_SUPPORTING",
    "INTERNAL_NOT_PUBLISHED",
    "PRIVATE_NEVER_PUBLISHED",
)
PUBLISHABLE = ("PUBLIC_RELEASE_CRITICAL", "PUBLIC_SUPPORTING")

PRIVATE_REFERENCE_PATTERNS = (
    ("court-scratch", re.compile("court" + "/" + "tmp")),
    ("home-directory", re.compile(r"(?<![\\w.])/(?:home|Users)/[A-Za-z0-9_.-]+")),
    ("root-home", re.compile(r"(?<![\\w.])" + "/" + "root" + "/")),
    ("host-only-tmp", re.compile(r"(?<![\\w.])" + "/" + "tmp" + "/[A-Za-z0-9_.-]+")),
    ("file-url", re.compile("file" + ":" + "//")),
    ("bearer-token", re.compile(r"Bearer\\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("authorization-header", re.compile(r"(?i)" + "Auth" + "orization:" + r"\\s*\\S+")),
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private-key-pem", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "credential-assignment",
        re.compile(
            r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret"
            r"|password|passwd|passphrase)\\s*[:=]\\s*[\\"'][^\\"']{6,}[\\"']"
        ),
    ),
)
ABSOLUTE_PATH_PATTERN = re.compile(
    r'"/(?:home|Users|root|tmp|var|usr|etc|opt|mnt|srv|work|data|proc|sys|dev|run)/[^"\\s]*'
    r'|[A-Za-z]:\\\\[^"\\s]*"'
)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def refusal(code, detail):
    print(json.dumps({"code": code, "outcome": "BUNDLE_INVALID", "detail": detail},
                     sort_keys=True))
    return 1


def digests(manifest):
    body = {key: value for key, value in manifest.items() if key != "manifestDigest"}
    return hashlib.sha256(canonical(body)).hexdigest()


def classify(policy, path):
    for entry in policy.get("privatePatterns", []):
        pattern = entry["pattern"]
        if fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(
            path.rsplit("/", 1)[-1], pattern
        ):
            return "PRIVATE_NEVER_PUBLISHED"
    for rule in policy.get("rules", []):
        if rule.get("kind") == "exact" and rule.get("path") == path:
            return rule["class"]
    for rule in policy.get("rules", []):
        if rule.get("kind") == "under":
            prefix = rule["path"]
            if path == prefix or path.startswith(prefix):
                return rule["class"]
        if rule.get("kind") == "depth":
            parts = path.split("/")
            if len(parts) == int(rule["depth"]) and parts[0] == rule["root"]:
                return rule["class"]
    return "UNCLASSIFIED"


def strings(value, depth=0):
    if depth > 64:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from strings(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item, depth + 1)


def texts(path, data):
    yield data.decode("utf-8", "replace")
    if not path.endswith(".json"):
        return
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return
    yield from strings(document)
    payload = document.get("payload") if isinstance(document, dict) else None
    if isinstance(payload, str) and len(payload) >= 8:
        try:
            yield base64.b64decode(payload, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass


def main():
    manifest_path = ROOT / MANIFEST
    if not manifest_path.is_file():
        return refusal("PB_REFUSED_MANIFEST_INVALID", "no MANIFEST.json beside verify.py")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return refusal("PB_REFUSED_MANIFEST_INVALID", f"manifest: {error}")
    if manifest.get("schema") != "openssl-rs/b4/bundle-manifest/1":
        return refusal("PB_REFUSED_MANIFEST_INVALID", "foreign manifest schema")
    if manifest.get("manifestDigest") != digests(manifest):
        return refusal("PB_REFUSED_MANIFEST_INVALID", "manifest body does not hash to its digest")

    policy = manifest.get("policy") or {}
    members = manifest.get("members") or []
    declared = {}
    for row in members:
        path = row.get("path")
        if not isinstance(path, str) or path in declared:
            return refusal("PB_REFUSED_MANIFEST_INVALID", "member table is malformed")
        declared[path] = row

    on_disk = sorted(
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*")
        if path.is_file() and str(path.relative_to(ROOT)) != MANIFEST
    )
    for path in on_disk:
        if path not in declared:
            return refusal("PB_REFUSED_UNBOUND_MEMBER", f"{path}: present but not in the manifest")
    for path, row in declared.items():
        target = ROOT / path
        if not target.is_file():
            return refusal("PB_REFUSED_UNBOUND_MEMBER", f"{path}: declared but absent")
        data = target.read_bytes()
        if len(data) != row.get("bytes"):
            return refusal("PB_REFUSED_UNBOUND_MEMBER", f"{path}: size differs from the manifest")
        if hashlib.sha256(data).hexdigest() != row.get("sha256"):
            return refusal("PB_REFUSED_UNBOUND_MEMBER", f"{path}: digest differs from the manifest")

    for path, row in declared.items():
        klass = row.get("classification")
        if klass not in CLASSES:
            return refusal("PB_REFUSED_CLASSIFICATION_MISMATCH", f"{path}: {klass!r} is not a class")
        source = row.get("sourcePath")
        if source is not None and classify(policy, source) != klass:
            return refusal(
                "PB_REFUSED_CLASSIFICATION_MISMATCH",
                f"{path}: manifest says {klass}, policy says {classify(policy, source)}",
            )
        if klass == "PRIVATE_NEVER_PUBLISHED":
            return refusal("PB_REFUSED_PRIVATE_MATERIAL", f"{path}: private")
        if klass == "INTERNAL_NOT_PUBLISHED":
            return refusal("PB_REFUSED_INTERNAL_MATERIAL", f"{path}: internal")
        if klass not in PUBLISHABLE:
            return refusal("PB_REFUSED_UNCLASSIFIED", f"{path}: unclassified")

    present_sources = {row.get("sourcePath") for row in declared.values()}
    for entry in policy.get("releaseCritical", []):
        source = entry.get("sourcePath")
        if source not in present_sources:
            return refusal(
                "PB_REFUSED_RELEASE_MEMBER_MISSING",
                f"{source}: release-critical but the bundle omits it",
            )
    for entry in policy.get("releaseCritical", []):
        source = entry.get("sourcePath")
        for path, row in declared.items():
            if row.get("sourcePath") == source and row.get("classification") != "PUBLIC_RELEASE_CRITICAL":
                return refusal(
                    "PB_REFUSED_RELEASE_MEMBER_MISSING",
                    f"{source}: carried as {row.get('classification')}, not release-critical",
                )

    for path, row in declared.items():
        data = (ROOT / path).read_bytes()
        for text in texts(path, data):
            for name, pattern in PRIVATE_REFERENCE_PATTERNS:
                match = pattern.search(text)
                if match:
                    return refusal(
                        "PB_REFUSED_PRIVATE_REFERENCE",
                        f"{path}: {name}: {match.group(0)[:60]!r}",
                    )
            match = ABSOLUTE_PATH_PATTERN.search(text)
            if match:
                return refusal("PB_REFUSED_ABSOLUTE_PATH", f"{path}: {match.group(0)[:60]!r}")

    labels = manifest.get("subjectLabels") or {}
    for path, expected in labels.items():
        if path not in declared:
            return refusal("PB_REFUSED_UNBOUND_MEMBER", f"{path}: labelled but absent")
        data = (ROOT / path).read_text(encoding="utf-8", errors="replace")
        for label in expected:
            if label not in data:
                return refusal(
                    "PB_REFUSED_UNBOUND_MEMBER",
                    f"{path}: declared label {label!r} does not occur in the member",
                )

    if manifest.get("entryPoint") != "verify.py" or "verify.py" not in declared:
        return refusal("PB_REFUSED_MANIFEST_INVALID", "the entry point is not a declared member")
    declarations = manifest.get("declarations") or {}
    if declarations.get("network") is not False:
        return refusal("PB_REFUSED_MANIFEST_INVALID", "the bundle does not declare no network")

    print(json.dumps({
        "code": "PB_OK",
        "outcome": "PUBLIC_BUNDLE_VERIFIED",
        "venue": "local",
        "external": "NOT_RUN",
        "members": len(declared),
        "releaseCritical": sum(
            1 for row in declared.values()
            if row.get("classification") == "PUBLIC_RELEASE_CRITICAL"
        ),
        "manifestDigest": manifest["manifestDigest"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _readme(policy: Mapping[str, Any], members: list[dict[str, Any]]) -> bytes:
    lines = [
        "# Public publication bundle — B4",
        "",
        "This directory is a **candidate** publication bundle. It is built only from",
        "material the classification policy admits. It has been verified **in this",
        "venue**; no external party has run the verifier, and no transparency log",
        "holds these digests. A publishable bundle is not a published one.",
        "",
        "## Members",
        "",
        "| member | class | bytes | sha256 | source |",
        "|---|---|---:|---|---|",
    ]
    for row in sorted(members, key=lambda item: item["path"]):
        lines.append(
            "| `{path}` | `{classification}` | {bytes} | `{sha256}` | `{sourcePath}` |".format(
                path=row["path"],
                classification=row["classification"],
                bytes=row["bytes"],
                sha256=row["sha256"],
                sourcePath=row["sourcePath"],
            )
        )
    lines += [
        "",
        "## Labels",
        "",
        "The B1 publication record is the test fixture **FIXTURE-1**: its log is a",
        "six-leaf fixture, its checkpoint key is a test-only HMAC-SHA256 key, and it",
        "is not a Rekor log entry. The A10 envelope signature is test-only as well.",
        "",
        "## Verify it",
        "",
        "```sh",
        "python3 verify.py          # Python 3.8 or newer",
        "sh verify.sh               # the same, through the shell wrapper",
        "```",
        "",
        "The verifier checks the manifest body against its own digest, every member",
        "against its recorded size and SHA-256, that no undeclared file is present,",
        "that every release-critical member the embedded policy declares is present",
        "with the declared class, that each member's class agrees with the embedded",
        "policy, and that no member carries a private reference or an absolute path.",
        "",
        "## Non-claims",
        "",
        "* A pass means these files are internally consistent and classified for",
        "  publication. It is not a publication, an inclusion proof, a signature by",
        "  an authority, or a statement that any claim in a member is true.",
        "* The manifest is not self-authenticating: a rewritten bundle can carry a",
        "  rewritten manifest. Obtain its digest through a channel you trust.",
        "* No external party has run this verifier. The external status is `PENDING`.",
        "",
    ]
    return ("\n".join(lines)).encode("utf-8")


def _generated_members(
    policy: Mapping[str, Any], repo: Path, sources: Iterable[Mapping[str, Any]]
) -> tuple[dict[str, bytes], list[dict[str, Any]]]:
    """Bytes and manifest rows for the sources and the three generated files."""
    bodies: dict[str, bytes] = {}
    rows: list[dict[str, Any]] = []
    for entry in sources:
        source = repo / entry["source"]
        if not source.is_file():
            _refuse("PB_REFUSED_IO", f"{entry['source']} does not exist")
        try:
            data = source.read_bytes()
        except OSError as error:
            _refuse("PB_REFUSED_IO", f"{entry['source']}: {error}")
        bodies[entry["member"]] = data
        rows.append(
            {
                "path": entry["member"],
                "role": entry["role"],
                "sourcePath": entry["source"],
                "classification": entry["classification"],
                "bytes": len(data),
                "sha256": sha256_bytes(data),
            }
        )
    bodies[ENTRY_POINT] = ENTRY_POINT_SOURCE.encode("utf-8")
    bodies[ENTRY_SHELL] = ENTRY_SHELL_SOURCE.encode("utf-8")
    for path in (ENTRY_POINT, ENTRY_SHELL):
        rows.append(
            {
                "path": path,
                "role": GENERATED_ROLES[path],
                "sourcePath": None,
                "classification": PUBLIC_SUPPORTING,
                "bytes": len(bodies[path]),
                "sha256": sha256_bytes(bodies[path]),
            }
        )
    readme = _readme(policy, rows)
    if "README.md" in bodies:
        raise AssertionError("README.md collides with a source member")
    bodies["README.md"] = readme
    for row in rows:
        if row["path"] == "README.md":
            row["bytes"] = len(readme)
            row["sha256"] = sha256_bytes(readme)
            break
    else:
        rows.append(
            {
                "path": "README.md",
                "role": GENERATED_ROLES["README.md"],
                "sourcePath": None,
                "classification": PUBLIC_SUPPORTING,
                "bytes": len(readme),
                "sha256": sha256_bytes(readme),
            }
        )
    return bodies, rows


def _embedded_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    """The part of the policy an outsider needs, bound by its own digest."""
    body = {
        "policyId": policy.get("policyId"),
        "default": policy.get("default"),
        "classes": policy.get("classes"),
        "rules": policy.get("rules"),
        "privatePatterns": policy.get("privatePatterns", []),
        "releaseCritical": policy.get("releaseCritical", []),
    }
    body["policyDigest"] = sha256_bytes(canonical(body))
    return body


def _subject_labels(members: Iterable[Mapping[str, Any]]) -> dict[str, list[str]]:
    """Labels a member must carry; only the members that exist are listed."""
    present = {row["path"] for row in members}
    labels: dict[str, list[str]] = {}
    if "members/b1-publication.json" in present:
        labels["members/b1-publication.json"] = ["FIXTURE-1"]
    if "members/a10-envelope-a8-shard-000.json" in present:
        labels["members/a10-envelope-a8-shard-000.json"] = [
            "application/vnd.in-toto+json"
        ]
    return labels


def manifest_document(
    policy: Mapping[str, Any], members: list[dict[str, Any]]
) -> dict[str, Any]:
    embedded = _embedded_policy(policy)
    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "bundleId": policy.get("bundleId", "b4-public-bundle"),
        "policy": embedded,
        "members": sorted(members, key=lambda item: item["path"]),
        "releaseCriticalMembers": sorted(
            row["path"]
            for row in members
            if row["classification"] == PUBLIC_RELEASE_CRITICAL
        ),
        "subjectLabels": _subject_labels(members),
        "entryPoint": ENTRY_POINT,
        "entryShell": ENTRY_SHELL,
        "minimumInterpreter": "3.8",
        "exactCommands": ["python3 verify.py", "sh verify.sh"],
        "declarations": {
            "network": False,
            "privateState": "none",
            "absolutePaths": False,
            "unclassifiedMembers": 0,
        },
        "refusalCodes": sorted(REFUSALS),
        "outcomes": list(OUTCOMES),
    }
    manifest["manifestDigest"] = digest_body(manifest, "manifestDigest")
    return manifest


def build(
    policy: Mapping[str, Any],
    repo: Path = REPO_ROOT,
    out: Path | None = None,
    sources: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the bundle, or refuse and write nothing.

    Everything is checked in memory first; the directory is written to a
    temporary sibling and moved into place only after every check passed.  The
    `sources` override exists for controls; the CLI always uses the declared set.
    """
    validate_policy(policy)
    out = Path(out) if out is not None else DEFAULT_BUNDLE
    bodies, rows = _generated_members(
        policy, repo, BUNDLE_SOURCES if sources is None else sources
    )

    for row in rows:
        source = row["sourcePath"]
        if source is None:
            klass = row["classification"]
        else:
            klass, rule_id, reason = classify_path(policy, source)
            if klass == UNCLASSIFIED:
                _refuse(
                    "PB_REFUSED_UNCLASSIFIED",
                    f"{source}: {reason}",
                )
            if klass == PRIVATE_NEVER_PUBLISHED:
                _refuse(
                    "PB_REFUSED_PRIVATE_MATERIAL",
                    f"{source}: classified PRIVATE_NEVER_PUBLISHED by {rule_id}",
                )
            if klass == INTERNAL_NOT_PUBLISHED:
                _refuse(
                    "PB_REFUSED_INTERNAL_MATERIAL",
                    f"{source}: classified INTERNAL_NOT_PUBLISHED by {rule_id}",
                )
            if row["classification"] != klass:
                _refuse(
                    "PB_REFUSED_CLASSIFICATION_MISMATCH",
                    f"{source}: member says {row['classification']}, policy says {klass}",
                )
        if klass not in PUBLISHABLE:
            _refuse("PB_REFUSED_CLASSIFICATION_MISMATCH", f"{row['path']}: {klass}")

    critical_sources = {entry["sourcePath"] for entry in policy["releaseCritical"]}
    present = {row["sourcePath"] for row in rows if row["sourcePath"] is not None}
    missing = sorted(critical_sources - present)
    if missing:
        _refuse(
            "PB_REFUSED_RELEASE_MEMBER_MISSING",
            "the build omits release-critical material: " + ", ".join(missing),
        )

    for path, data in bodies.items():
        finding = scan_member_text(path, data)
        if finding is not None:
            _refuse(*finding)

    manifest = manifest_document(policy, rows)
    manifest_bytes = pretty(manifest)

    parent = out.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".b4-bundle-", dir=str(parent)))
    try:
        for path, data in bodies.items():
            target = staging / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (staging / MANIFEST_NAME).write_bytes(manifest_bytes)
        if out.exists():
            shutil.rmtree(out)
        # `mkdtemp` creates a private directory; the bundle is read by the
        # orchestrator and by any recipient, so it must be world-readable.
        os.chmod(staging, 0o755)
        staging.rename(out)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return {
        "schema": "openssl-rs/b4/build/1",
        "bundle": str(out.name),
        "members": len(rows),
        "releaseCritical": len(manifest["releaseCriticalMembers"]),
        "manifestDigest": manifest["manifestDigest"],
        "policyDigest": manifest["policy"]["policyDigest"],
        "membersTable": sorted(manifest["members"], key=lambda item: item["path"]),
    }


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _load_manifest(bundle: Path) -> dict[str, Any]:
    path = bundle / MANIFEST_NAME
    if not path.is_file():
        _refuse("PB_REFUSED_MANIFEST_INVALID", f"{path.name} is absent")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        _refuse("PB_REFUSED_MANIFEST_INVALID", f"{path.name}: {error}")
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        _refuse("PB_REFUSED_MANIFEST_INVALID", "the manifest is not this schema")
    if manifest.get("manifestDigest") != digest_body(manifest, "manifestDigest"):
        _refuse(
            "PB_REFUSED_MANIFEST_INVALID",
            "the manifest body does not hash to its own digest",
        )
    return manifest


def verify_bundle(
    bundle: Path | None = None,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Check a bundle directory; return a result or raise a coded `Refusal`."""
    bundle = Path(bundle) if bundle is not None else DEFAULT_BUNDLE
    if not bundle.is_dir():
        _refuse("PB_REFUSED_IO", f"{bundle} is not a directory")
    manifest = _load_manifest(bundle)

    embedded = manifest.get("policy") or {}
    validate_policy(embedded)
    if policy is not None:
        validate_policy(policy)
        if _embedded_policy(policy)["policyDigest"] != embedded.get("policyDigest"):
            _refuse(
                "PB_REFUSED_CLASSIFICATION_MISMATCH",
                "the bundle's embedded policy is not the supplied policy",
            )

    rows = manifest.get("members")
    if not isinstance(rows, list) or not rows:
        _refuse("PB_REFUSED_MANIFEST_INVALID", "the manifest declares no members")
    declared: dict[str, dict[str, Any]] = {}
    for row in rows:
        path = row.get("path")
        if not isinstance(path, str) or path in declared:
            _refuse("PB_REFUSED_MANIFEST_INVALID", "a member row is malformed")
        declared[path] = row

    on_disk = sorted(
        str(path.relative_to(bundle))
        for path in bundle.rglob("*")
        if path.is_file() and str(path.relative_to(bundle)) != MANIFEST_NAME
    )
    for path in on_disk:
        if path not in declared:
            _refuse(
                "PB_REFUSED_UNBOUND_MEMBER",
                f"{path}: present in the bundle but not recorded in the manifest",
            )
    for path, row in declared.items():
        target = bundle / path
        if not target.is_file():
            _refuse("PB_REFUSED_UNBOUND_MEMBER", f"{path}: declared but absent")
        data = target.read_bytes()
        if len(data) != row.get("bytes") or sha256_bytes(data) != row.get("sha256"):
            _refuse(
                "PB_REFUSED_UNBOUND_MEMBER",
                f"{path}: bytes differ from the manifest",
            )

    for path, row in declared.items():
        klass = row.get("classification")
        if klass not in CLASSES:
            _refuse(
                "PB_REFUSED_CLASSIFICATION_MISMATCH",
                f"{path}: {klass!r} is not one of the four classes",
            )
        source = row.get("sourcePath")
        if source is None:
            expected = PUBLIC_SUPPORTING
        else:
            expected, rule_id, reason = classify_path(embedded, source)
            if expected == UNCLASSIFIED:
                _refuse("PB_REFUSED_UNCLASSIFIED", f"{source}: {reason}")
        if klass != expected:
            _refuse(
                "PB_REFUSED_CLASSIFICATION_MISMATCH",
                f"{path}: manifest says {klass}, policy says {expected}",
            )
        if klass == PRIVATE_NEVER_PUBLISHED:
            _refuse("PB_REFUSED_PRIVATE_MATERIAL", f"{path}: private material")
        if klass == INTERNAL_NOT_PUBLISHED:
            _refuse("PB_REFUSED_INTERNAL_MATERIAL", f"{path}: internal material")
        if klass not in PUBLISHABLE:
            _refuse("PB_REFUSED_UNCLASSIFIED", f"{path}: not publishable")

    present_sources = {row.get("sourcePath") for row in declared.values()}
    for entry in embedded["releaseCritical"]:
        source = entry["sourcePath"]
        if source not in present_sources:
            _refuse(
                "PB_REFUSED_RELEASE_MEMBER_MISSING",
                f"{source}: release-critical but the bundle omits it",
            )
        carrying = [
            path
            for path, row in declared.items()
            if row.get("sourcePath") == source
        ]
        for path in carrying:
            if declared[path]["classification"] != PUBLIC_RELEASE_CRITICAL:
                _refuse(
                    "PB_REFUSED_RELEASE_MEMBER_MISSING",
                    f"{path}: carries release-critical material at "
                    f"{declared[path]['classification']}",
                )

    for path in sorted(declared):
        data = (bundle / path).read_bytes()
        finding = scan_member_text(path, data)
        if finding is not None:
            _refuse(*finding)

    labels = manifest.get("subjectLabels") or {}
    for path, expected_labels in labels.items():
        if path not in declared:
            _refuse("PB_REFUSED_UNBOUND_MEMBER", f"{path}: labelled but absent")
        text = (bundle / path).read_text(encoding="utf-8", errors="replace")
        for label in expected_labels:
            if label not in text:
                _refuse(
                    "PB_REFUSED_UNBOUND_MEMBER",
                    f"{path}: declared label {label!r} does not occur",
                )

    if manifest.get("entryPoint") != ENTRY_POINT or ENTRY_POINT not in declared:
        _refuse("PB_REFUSED_MANIFEST_INVALID", "the entry point is not a member")

    return {
        "schema": "openssl-rs/b4/verification/1",
        "code": "PB_OK",
        "outcome": "PUBLIC_BUNDLE_VERIFIED",
        "publishable": True,
        "venue": "in-venue",
        "externalVerification": "PENDING",
        "members": len(declared),
        "releaseCritical": len(manifest.get("releaseCriticalMembers", [])),
        "supporting": sum(
            1
            for row in declared.values()
            if row.get("classification") == PUBLIC_SUPPORTING
        ),
        "manifestDigest": manifest["manifestDigest"],
        "policyDigest": embedded["policyDigest"],
        "memberDigests": {
            path: declared[path]["sha256"] for path in sorted(declared)
        },
    }


def publication_claim(
    *,
    publish: bool = False,
    endpoint: str | None = None,
    external_verified: bool = False,
    external_ran: bool = False,
) -> dict[str, Any]:
    """A publication claim is refused unless the service and the party exist."""
    if publish and not endpoint:
        _refuse(
            "PB_REFUSED_NO_PUBLIC_SERVICE",
            "no admitted public endpoint exists in this venue",
        )
    if external_verified and not external_ran:
        _refuse(
            "PB_REFUSED_EXTERNAL_NOT_RUN",
            "no external party ran the verifier",
        )
    return {
        "schema": "openssl-rs/b4/claim/1",
        "admittedService": bool(endpoint),
        "endpoint": endpoint,
        "published": 0,
        "externalVerification": "PENDING" if not external_ran else "REPORTED",
        "code": "PB_OK",
    }


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def load_policy(path: Path = DEFAULT_POLICY) -> dict[str, Any]:
    if not path.is_file():
        _refuse("PB_REFUSED_IO", f"{path} does not exist")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        _refuse("PB_REFUSED_IO", f"{path}: {error}")
    if not isinstance(document, dict) or document.get("schema") != POLICY_SCHEMA:
        _refuse("PB_REFUSED_IO", f"{path}: not a classification policy")
    policy = document.get("policy")
    if not isinstance(policy, dict):
        _refuse("PB_REFUSED_IO", f"{path}: no policy body")
    validate_policy(policy)
    return policy


def _print_line(**fields: Any) -> None:
    print(" ".join(f"{key}={value}" for key, value in fields.items()))


def command_scan(args: argparse.Namespace) -> int:
    policy = load_policy(Path(args.policy))
    result = scan_tree(policy)
    if args.out:
        Path(args.out).write_bytes(pretty(result))
    if args.json:
        sys.stdout.buffer.write(pretty(result))
    else:
        counts = result["counts"]
        _print_line(
            code="PB_OK",
            outcome="SCAN_COMPLETE",
            population=result["populationSource"]["population"],
            base=result["populationSource"]["commit"][:9],
            classified=result["classified"],
            unclassified=result["unclassified"],
            private=result["private"],
            releaseCritical=counts[PUBLIC_RELEASE_CRITICAL],
            supporting=counts[PUBLIC_SUPPORTING],
            internal=counts[INTERNAL_NOT_PUBLISHED],
            privateReferenceArtefacts=result["referenceScan"]["privateReferenceArtefacts"],
            absolutePathArtefacts=result["referenceScan"]["absolutePathArtefacts"],
            boundReached=str(result["bound"]["reached"]).lower(),
        )
    return EXIT_OK


def command_classify(args: argparse.Namespace) -> int:
    policy = load_policy(Path(args.policy))
    for path in args.paths:
        klass, rule_id, _reason = classify_path(policy, path)
        _print_line(path=path, classification=klass, rule=rule_id)
    return EXIT_OK


def command_build(args: argparse.Namespace) -> int:
    policy = load_policy(Path(args.policy))
    result = build(policy, REPO_ROOT, Path(args.out))
    _print_line(
        code="PB_OK",
        outcome="BUILD_COMPLETE",
        bundle=Path(args.out).name,
        members=result["members"],
        releaseCritical=result["releaseCritical"],
        manifestDigest=result["manifestDigest"][:16],
    )
    return EXIT_OK


def command_verify(args: argparse.Namespace) -> int:
    policy = None
    if args.policy:
        policy = load_policy(Path(args.policy))
    result = verify_bundle(Path(args.bundle), policy)
    if args.json:
        sys.stdout.buffer.write(pretty(result))
    else:
        _print_line(
            code=result["code"],
            outcome=result["outcome"],
            bundle=Path(args.bundle).name,
            members=result["members"],
            releaseCritical=result["releaseCritical"],
            supporting=result["supporting"],
            publishable=str(result["publishable"]).lower(),
            venue=result["venue"],
            external=result["externalVerification"],
        )
    return EXIT_OK


def command_claim(args: argparse.Namespace) -> int:
    result = publication_claim(
        publish=args.publish,
        endpoint=args.endpoint,
        external_verified=args.external_verified,
        external_ran=args.external_ran,
    )
    _print_line(
        code=result["code"],
        admittedService=str(result["admittedService"]).lower(),
        published=result["published"],
        externalVerification=result["externalVerification"],
    )
    return EXIT_OK


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="publication.py",
        description="classify evidence, build a public bundle, verify it",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--policy", default=str(DEFAULT_POLICY))
    parsers = parser.add_subparsers(dest="command", required=True)

    scan = parsers.add_parser("scan", parents=[common], help="classify the declared input set")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--out")
    scan.set_defaults(func=command_scan)

    classify = parsers.add_parser("classify", parents=[common], help="classify named paths")
    classify.add_argument("paths", nargs="+")
    classify.set_defaults(func=command_classify)

    build_parser = parsers.add_parser("build", parents=[common], help="build the bundle")
    build_parser.add_argument("--out", default=str(DEFAULT_BUNDLE))
    build_parser.set_defaults(func=command_build)

    verify = parsers.add_parser("verify", parents=[common], help="verify a bundle")
    verify.add_argument("--bundle", default=str(DEFAULT_BUNDLE))
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=command_verify)

    claim = parsers.add_parser("claim", parents=[common], help="state what may be published")
    claim.add_argument("--publish", action="store_true")
    claim.add_argument("--endpoint")
    claim.add_argument("--external-verified", action="store_true")
    claim.add_argument("--external-ran", action="store_true")
    claim.set_defaults(func=command_claim)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_:
        return EXIT_USAGE if exit_.code not in (0, None) else EXIT_OK
    try:
        return int(args.func(args))
    except Refusal as refusal:
        print(f"publication.py: code={refusal.code} outcome=REFUSED detail={refusal.detail}",
              file=sys.stderr)
        return EXIT_REFUSED
    except OSError as error:
        print(f"publication.py: code=PB_REFUSED_IO outcome=REFUSED detail={error}",
              file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
