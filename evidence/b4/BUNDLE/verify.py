#!/usr/bin/env python3
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
    ("home-directory", re.compile(r"(?<![\w.])/(?:home|Users)/[A-Za-z0-9_.-]+")),
    ("root-home", re.compile(r"(?<![\w.])" + "/" + "root" + "/")),
    ("host-only-tmp", re.compile(r"(?<![\w.])" + "/" + "tmp" + "/[A-Za-z0-9_.-]+")),
    ("file-url", re.compile("file" + ":" + "//")),
    ("bearer-token", re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("authorization-header", re.compile(r"(?i)" + "Auth" + "orization:" + r"\s*\S+")),
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
ABSOLUTE_PATH_PATTERN = re.compile(
    r'"/(?:home|Users|root|tmp|var|usr|etc|opt|mnt|srv|work|data|proc|sys|dev|run)/[^"\s]*'
    r'|[A-Za-z]:\\[^"\s]*"'
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
