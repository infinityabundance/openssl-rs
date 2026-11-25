#!/usr/bin/env python3
"""build_evidence.py -- the deterministic producer for B0.

The producer reads ``docs/ETP-ADDENDUM-B.md``, extracts the pinned release table,
the C2SP table and the one recorded release-asset digest, joins them with a
declared profile of what this project adopts, and writes:

    evidence/b0/REGISTRY.json
    evidence/b0/SERVICE-CONFIGURATION.json

It then validates both records with ``forensics/tools/protocol_audit.py`` before
writing, so a record that would be refused is not produced.  Two runs write the
same bytes: the output is canonical JSON with sorted keys, one-space indent and
a trailing newline, and no field is read from the clock or the environment.

The producer installs nothing and contacts nothing.  The presence observations
it records are the ones measured on 2026-11-24 with ``command -v`` and a
tracked-path search; they are data in this file, not a live probe, so the record
is reproducible.

Usage:
    python3 evidence/b0/build_evidence.py [--check]

``--check`` validates the committed records without writing.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import protocol_audit as pa  # noqa: E402

ADDENDUM = REPO_ROOT / "docs/ETP-ADDENDUM-B.md"
REGISTRY_OUT = REPO_ROOT / "evidence/b0/REGISTRY.json"
SERVICE_OUT = REPO_ROOT / "evidence/b0/SERVICE-CONFIGURATION.json"

RECORDED_AT = "2026-11-24"
BASE_COMMIT = "5015b6239"
BASE_COMMIT_FULL = "5015b6239"

# The one release-asset digest §B.3.2 records.  It is read from the clause by
# `_recorded_digest`; the constant is the assertion that this is what was found.
RECORDED_DIGEST = "sha256:3af252cd59adea029eea7ff325dee8adb65074e45d0c03aaa6c083eb2461e8a6"

PRESENCE_CHECKS = [
    {
        "id": "command-v-rekor-server",
        "command": "command -v rekor-server",
        "result": "absent",
        "date": RECORDED_AT,
        "note": "the server binary is not on the PATH of the host or of the court container",
    },
    {
        "id": "command-v-rekor-cli",
        "command": "command -v rekor-cli",
        "result": "absent",
        "date": RECORDED_AT,
        "note": "no Rekor client is installed",
    },
    {
        "id": "command-v-rekor-tiles",
        "command": "command -v rekor-tiles",
        "result": "absent",
        "date": RECORDED_AT,
        "note": "the reference implementation is not installed",
    },
    {
        "id": "command-v-cosign",
        "command": "command -v cosign",
        "result": "absent",
        "date": RECORDED_AT,
        "note": "no Sigstore client is installed",
    },
    {
        "id": "command-v-sigstore",
        "command": "command -v sigstore",
        "result": "absent",
        "date": RECORDED_AT,
        "note": "no Sigstore CLI is installed",
    },
    {
        "id": "command-v-tsget",
        "command": "command -v tsget",
        "result": "absent",
        "date": RECORDED_AT,
        "note": "no RFC 3161 client helper is installed; the openssl CLI is present but no TSA endpoint or root is configured",
    },
    {
        "id": "command-v-openssl",
        "command": "command -v openssl",
        "result": "/usr/bin/openssl",
        "date": RECORDED_AT,
        "note": "the openssl CLI is present; it is not a transparency service and no TSA is configured",
    },
    {
        "id": "tracked-path-search",
        "command": "git grep -Iln rekor -- . ':!docs' ':!court'",
        "result": "record:no tracked path outside docs/ registers a Rekor endpoint, log key or witness",
        "date": RECORDED_AT,
        "note": "the only mentions of the transparency stack are the addendum, the queue and the Sigstore profile",
    },
]

# What this project adopts from each rekor-tiles tag.  The feature text for an
# adopted tag is the clause's own "substance relevant here" column; a tag this
# project does not adopt has that substance recorded as unsupported with the
# reason it is not admitted.
ADOPTED = {"v2.4.2", "v2.3.0", "v2.1.0"}

REKOR_UNSUPPORTED = {
    "v2.4.2": [
        (
            "identity-serve mode and the identity-based transparency API",
            "B.26",
            "the implementation labels the identity-transparency mode experimental and subject to breaking change; §B.26 keeps it off the production track",
        )
    ],
    "v2.4.1": [
        (
            "ML-DSA Tink keyset support in the upstream Sigstore library",
            "B.26",
            "upstream-library support is not an admitted checkpoint mechanism here; §B.26 keeps ML-DSA on the research track",
        )
    ],
    "v2.4.0": [
        (
            "the new leaf type",
            "B.5",
            "§B.5 admits a specific reviewed profile; the v2.4.0 leaf type is not that profile",
        ),
        (
            "ML-DSA signatures and the identity-based transparency API",
            "B.26",
            "the clause records ML-DSA as explicitly experimental and the identity mode as subject to breaking change",
        ),
        (
            "pure Ed25519 in hashedrekord",
            "B.5",
            "§B.5 excludes pure Ed25519 in hashedrekord for the admitted v2.4.x profile",
        ),
    ],
    "v2.3.0": [
        (
            "a dedicated DSSE log entry type",
            "B.5",
            "§B.5 forbids implementation against examples that describe a dedicated DSSE log entry",
        )
    ],
    "v2.2.1": [
        (
            "the v2.2.1 tag as this project's admitted profile",
            "B.5",
            "§B.5 admits a specific reviewed profile; this tag is recorded as baseline history",
        )
    ],
    "v2.2.0": [
        (
            "the AWS backend and the GCP CloudSQL + GCS backend",
            "B.3.2",
            "§B.3.2 records the POSIX backend at v2.1.0 as the backend this project uses; the cloud backends are not admitted",
        )
    ],
    "v2.1.0": [
        (
            "the cloud storage backends recorded at v2.2.0",
            "B.3.2",
            "§B.3.2 records POSIX as the backend this project uses for local and CI instances",
        )
    ],
    "v2.0.1": [
        (
            "log witnessing as a working capability",
            "B.11",
            "the tag enables witnessing; §B.11 records that no independent witness is available here, so the capability is pending",
        )
    ],
    "v2.0.0": [
        (
            "the v2.0.0 tag as this project's admitted profile",
            "B.5",
            "§B.5 admits a specific reviewed profile; this tag is recorded as baseline history",
        )
    ],
}

# A note carried beside the entries that would otherwise be read as a service.
REKOR_NOTES = {
    "v2.4.2": (
        "this is the tag whose linux/amd64 rekor-server-aws asset digest §B.3.2 "
        "records; the digest is for the AWS build, not for the POSIX-backend "
        "server B1 intends to run, so B1 must record a fresh digest at admission"
    ),
    "v2.1.0": "the POSIX storage backend is the one §B.3.2 records for local and CI instances",
    "v2.0.1": "witnessing is enabled in the tag; no witness exists in this tree",
}

C2SP_DETAIL = {
    "c2sp.org/tlog-tiles": {
        "role": ["log"],
        "supported": [
            ("static resource layout", "B.3.2"),
            ("tile geometry", "B.3.2"),
            ("entry bundles", "B.3.2"),
            ("pruning", "B.3.2"),
        ],
        "unsupported": [
            (
                "serving checkpoint, tile or bundle resources through an HTTP redirect",
                "B.3.2",
                "the clause requires that resources must not serve redirects; a redirecting mirror is not an admitted log",
            )
        ],
    },
    "c2sp.org/tlog-checkpoint": {
        "role": ["checkpoint"],
        "supported": [
            ("the checkpoint body", "B.3.2"),
            ("note signature algorithms", "B.3.2"),
        ],
        "unsupported": [
            (
                "ML-DSA-44 checkpoint cosignatures in production",
                "B.26",
                "C2SP recommends ML-DSA-44; the implementation labels the mode experimental and §B.26 records the deliberate divergence",
            )
        ],
    },
    "c2sp.org/tlog-cosignature": {
        "role": ["cosignature"],
        "supported": [
            ("checkpoint and subtree cosignature inputs", "B.3.2"),
            ("monotonicity of checkpoint cosignatures", "B.3.2"),
        ],
        "unsupported": [
            (
                "interoperable witness cosignatures over checkpoints",
                "B.11",
                "no independent witness set or cosignature producer exists here; §B.11 requires the witness-dependent property to be marked pending",
            )
        ],
    },
}

C2SP_ARTEFACT_NULL_REASON = (
    "§B.3.2 records the specification version and version date, not a document "
    "digest; no tracked record in this tree carries a digest for this specification"
)


def _clause_text(document: str, clause: str) -> str:
    text = pa.clause_text(document, clause)
    if text is None:
        raise SystemExit(f"b0: clause {clause} has no text in {ADDENDUM}")
    return text


def _rekor_rows(section: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    pattern = re.compile(
        r"^\|\s*`(?P<tag>v[0-9]+\.[0-9]+\.[0-9]+)`\s*\|\s*(?P<date>[0-9-]{10})\s*\|\s*"
        r"`(?P<commit>[0-9a-f]{7,40})`\s*\|\s*(?P<substance>.*?)\s*\|\s*$"
    )
    for line in section.splitlines():
        match = pattern.match(line)
        if match:
            rows.append(match.groupdict())
    if not rows:
        raise SystemExit("b0: the §B.3.2 rekor-tiles table could not be read")
    return rows


def _c2sp_rows(section: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    pattern = re.compile(
        r"^\|\s*`(?P<name>c2sp\.org/[^`]+)`\s*\|\s*(?P<version>v[0-9]+\.[0-9]+\.[0-9]+)\s*\|\s*"
        r"(?P<fixes>.*?)\s*\|\s*$"
    )
    for line in section.splitlines():
        match = pattern.match(line)
        if match:
            rows.append(match.groupdict())
    if not rows:
        raise SystemExit("b0: the §B.3.2 C2SP table could not be read")
    return rows


def _recorded_digest(section: str) -> str:
    match = re.search(r"sha256:[0-9a-f]{64}", section)
    if not match:
        raise SystemExit("b0: §B.3.2 records no release-asset digest")
    if match.group(0) != RECORDED_DIGEST:
        raise SystemExit(
            "b0: the recorded digest changed; re-read §B.3.2 before regenerating"
        )
    return match.group(0)


def _presence(binary: str, check: str, *, pinned: bool = True) -> dict[str, Any]:
    return {
        "pinned": pinned,
        "installed": False,
        "executable": False,
        "checkedBy": check,
        "binary": binary,
    }


def _line_of(document: str, needle: str) -> int | None:
    for index, line in enumerate(document.splitlines(), start=1):
        if needle in line:
            return index
    return None


def _rekor_components(document: str) -> list[dict[str, Any]]:
    section = _clause_text(document, "B.3.2")
    digest = _recorded_digest(section)
    components: list[dict[str, Any]] = []
    for row in _rekor_rows(section):
        tag = row["tag"]
        adopted = tag in ADOPTED
        supported = (
            [{"feature": row["substance"], "clause": "B.3.2"}] if adopted else []
        )
        unsupported = [
            {"feature": feature, "clause": clause, "reason": reason}
            for feature, clause, reason in REKOR_UNSUPPORTED.get(tag, [])
        ]
        if not adopted:
            unsupported.append(
                {
                    "feature": row["substance"],
                    "clause": "B.5",
                    "reason": (
                        "this tag is recorded as baseline history; §B.5 admits a "
                        "specific reviewed client and server profile"
                    ),
                }
            )
        deduped: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for entry in unsupported:
            key = (entry["feature"], entry["clause"])
            if key not in seen:
                seen.add(key)
                deduped.append(entry)
        unsupported = deduped
        is_digest_tag = tag == "v2.4.2"
        component: dict[str, Any] = {
            "id": f"rekor-tiles-{tag}",
            "kind": "release",
            "name": "sigstore/rekor-tiles",
            "version": tag,
            "releaseDate": row["date"],
            "upstreamCommit": row["commit"],
            "role": ["log"],
            "source": {
                "clause": "B.3.2",
                "path": pa.ADDENDUM,
                "line": _line_of(document, f"`{tag}`"),
            },
            "artefact": {
                "kind": "release-asset" if is_digest_tag else "release-tag",
                "name": (
                    "rekor-server-aws (linux/amd64)"
                    if is_digest_tag
                    else f"sigstore/rekor-tiles {tag}"
                ),
                "digest": digest if is_digest_tag else None,
                "digestNullReason": (
                    None
                    if is_digest_tag
                    else (
                        "§B.3.2 records no release-asset digest for this tag; no "
                        "tracked record in this tree carries one"
                    )
                ),
            },
            "supportedFeatures": supported,
            "unsupportedFeatures": unsupported,
            "presence": _presence("rekor-server", "command-v-rekor-server"),
            "serviceClaim": False,
            "adopted": adopted,
        }
        if tag in REKOR_NOTES:
            component["notes"] = REKOR_NOTES[tag]
        components.append(component)
    return components


def _c2sp_components(document: str) -> list[dict[str, Any]]:
    section = _clause_text(document, "B.3.2")
    components: list[dict[str, Any]] = []
    for row in _c2sp_rows(section):
        name = row["name"]
        detail = C2SP_DETAIL[name]
        components.append(
            {
                "id": name.replace("c2sp.org/", "c2sp-").replace(".", "-") + "-" + row["version"],
                "kind": "specification",
                "name": name,
                "version": row["version"],
                "releaseDate": "2026-10-07",
                "upstreamCommit": None,
                "upstreamCommitNullReason": (
                    "§B.3.2 records a specification version and version date; a "
                    "specification has no upstream commit and none is recorded"
                ),
                "role": detail["role"],
                "source": {"clause": "B.3.2", "path": pa.ADDENDUM, "line": None},
                "artefact": {
                    "kind": "specification",
                    "name": name,
                    "digest": None,
                    "digestNullReason": C2SP_ARTEFACT_NULL_REASON,
                },
                "supportedFeatures": [
                    {"feature": feature, "clause": clause}
                    for feature, clause in detail["supported"]
                ],
                "unsupportedFeatures": [
                    {"feature": feature, "clause": clause, "reason": reason}
                    for feature, clause, reason in detail["unsupported"]
                ],
                "presence": _presence("rekor-server", "command-v-rekor-server"),
                "serviceClaim": False,
                "adopted": True,
            }
        )
    return components


def _mechanism_components(document: str) -> list[dict[str, Any]]:
    b33 = _clause_text(document, "B.3.3")
    if "ML-DSA-44" not in b33:
        raise SystemExit("b0: §B.3.3 no longer records the ML-DSA-44 tension")
    return [
        {
            "id": "dsse-entry-type-change-v2.3.0",
            "kind": "change",
            "name": "DSSE entry type removed; DSSE published as hashedrekord",
            "version": "v2.3.0",
            "releaseDate": "2026-06-10",
            "upstreamCommit": "fa390b1",
            "role": ["log"],
            "source": {"clause": "B.3.2", "path": pa.ADDENDUM, "line": 116},
            "artefact": {
                "kind": "change",
                "name": "entry representation at sigstore/rekor-tiles v2.3.0",
                "digest": None,
                "digestNullReason": (
                    "the change is a protocol behaviour of the v2.3.0 tag; §B.3.2 "
                    "records no release-asset digest for that tag"
                ),
            },
            "supportedFeatures": [
                {
                    "feature": "DSSE statements are published as hashedrekord",
                    "clause": "B.3.3",
                },
                {
                    "feature": "one supported entry representation since v2.3.0",
                    "clause": "B.3.3",
                },
            ],
            "unsupportedFeatures": [
                {
                    "feature": "a dedicated DSSE log entry type",
                    "clause": "B.5",
                    "reason": "§B.5 forbids implementation against examples that describe a dedicated DSSE log entry",
                }
            ],
            "presence": _presence("rekor-server", "command-v-rekor-server"),
            "serviceClaim": False,
            "adopted": True,
            "notes": (
                "the protocol-required digest is the one the admitted client "
                "computes from the exact DSSE envelope, not the envelope JSON, "
                "the payload alone or an unrelated manifest hash (§B.3.3, §B.5)"
            ),
        },
        {
            "id": "ml-dsa-44",
            "kind": "mechanism",
            "name": "ML-DSA-44 checkpoint cosignature",
            "version": "ML-DSA-44",
            "releaseDate": None,
            "releaseDateNullReason": (
                "ML-DSA-44 is an algorithm the pinned checkpoint specification "
                "recommends and the implementation exposes experimentally; §B.3.2 "
                "records it under specification and release versions, not as an "
                "artefact with its own release date"
            ),
            "upstreamCommit": None,
            "upstreamCommitNullReason": (
                "no implementation commit is recorded for the algorithm; §B.3.2 "
                "records the specification version and the experimental tag"
            ),
            "role": ["cosignature", "checkpoint"],
            "source": {"clause": "B.3.3", "path": pa.ADDENDUM, "line": 168},
            "artefact": {
                "kind": "mechanism",
                "name": "ML-DSA-44 checkpoint cosignature",
                "digest": None,
                "digestNullReason": (
                    "a signature algorithm is not a released artefact and §B.3.2 "
                    "records no digest for it; no tracked record carries one"
                ),
            },
            "supportedFeatures": [
                {
                    "feature": "ML-DSA-44 checkpoint cosignatures are recommended by C2SP for new deployments",
                    "clause": "B.3.3",
                }
            ],
            "unsupportedFeatures": [
                {
                    "feature": "production admission of ML-DSA-44",
                    "clause": "B.26",
                    "reason": "the implementation labels the mechanism experimental; §B.26 admits it only on the research track",
                }
            ],
            "presence": _presence("rekor-server", "command-v-rekor-server"),
            "serviceClaim": False,
            "adopted": False,
            "notes": "a C2SP recommendation, not an admitted production mechanism",
        },
        {
            "id": "sigstore-signing-config-v1-endpoint",
            "kind": "finding",
            "name": "Sigstore signing_config (Rekor service metadata)",
            "version": None,
            "versionNullReason": (
                "§B.3.3 records the inspection date (2026-10-22) but not the "
                "client build that produced the signing_config; no client version "
                "is recorded and none is inferred"
            ),
            "releaseDate": None,
            "releaseDateNullReason": "the signing_config is service metadata, not a release",
            "upstreamCommit": None,
            "upstreamCommitNullReason": "no upstream commit is recorded for the inspection",
            "observedDate": "2026-10-22",
            "role": ["client"],
            "source": {"clause": "B.3.3", "path": pa.ADDENDUM, "line": 176},
            "artefact": {
                "kind": "finding",
                "name": "the Rekor endpoint advertised by the default signing configuration",
                "digest": None,
                "digestNullReason": (
                    "the inspection recorded an advertised endpoint, not an "
                    "artefact; no digest is recorded and none is invented"
                ),
            },
            "supportedFeatures": [
                {"feature": "a Rekor v1 endpoint", "clause": "B.3.3"}
            ],
            "unsupportedFeatures": [
                {
                    "feature": "a Rekor v2 endpoint through the default signing configuration",
                    "clause": "B.3.3",
                    "reason": "the inspected signing_config advertised a v1 endpoint; installing a recent client does not activate a v2 log",
                }
            ],
            "presence": _presence("cosign", "command-v-cosign", pinned=False),
            "serviceClaim": False,
            "adopted": False,
            "notes": "recorded from §B.3.3; this item has no network access and did not repeat the inspection",
        },
    ]


def build_registry(document: str) -> dict[str, Any]:
    components = (
        _rekor_components(document)
        + _c2sp_components(document)
        + _mechanism_components(document)
    )
    pinned = sum(1 for c in components if c["presence"]["pinned"])
    installed = sum(1 for c in components if c["presence"]["installed"])
    executable = sum(1 for c in components if c["presence"]["executable"])
    return {
        "schema": pa.REGISTRY_SCHEMA,
        "item": "B0",
        "model": pa.MODEL_ID,
        "recordedAt": RECORDED_AT,
        "baseCommit": BASE_COMMIT,
        "source": {
            "addendum": pa.ADDENDUM,
            "freeze": pa.FREEZE,
            "note": (
                "every version, date, commit and digest below is read from the "
                "cited addendum clause; nothing is fetched"
            ),
        },
        "presenceCheck": {
            "date": RECORDED_AT,
            "method": (
                "command -v on the host and in the court container, plus a "
                "tracked-path search; no component is installed or started"
            ),
            "checks": PRESENCE_CHECKS,
        },
        "serviceReachable": False,
        "components": components,
        "summary": {
            "components": len(components),
            "pinned": pinned,
            "installed": installed,
            "executable": executable,
            "servicesReachable": 0,
        },
    }


# ---------------------------------------------------------------------------
# Service configuration
# ---------------------------------------------------------------------------

CLIENT_SUPPORT = [
    {
        "item": "A9",
        "module": "forensics/tools/intoto.py",
        "doc": "docs/INTOTO-STATEMENTS.md",
        "state": "IMPLEMENTED_WITH_LIMITS",
        "supports": "in-toto Statement v1 emission and verification, computed subject digests and record-bound predicates",
        "refusalPrefix": "IT_REFUSED_",
        "refusalCodes": [
            "IT_REFUSED_TYPE",
            "IT_REFUSED_MISSING_SUBJECT",
            "IT_REFUSED_SUBJECT_ABSENT",
            "IT_REFUSED_SUBJECT_DIGEST_FORM",
            "IT_REFUSED_SUBJECT_DIGEST_MISMATCH",
            "IT_REFUSED_DUPLICATE_SUBJECT",
            "IT_REFUSED_PREDICATE_TYPE",
            "IT_REFUSED_PREDICATE_FIELD",
            "IT_REFUSED_CLAIM_UPGRADE",
            "IT_REFUSED_RECORD_ABSENT",
            "IT_REFUSED_RECORD_INADMISSIBLE",
            "IT_REFUSED_STATEMENT_MUTATED",
        ],
        "observed": [
            {"path": "evidence/a9/STATEMENTS.json", "pointer": "totals/statements", "equals": 4},
            {"path": "evidence/a9/STATEMENTS.json", "pointer": "totals/codes", "equals": 12},
        ],
        "limits": [
            "a statement is not a signature, a proof, a verification or an admission",
            "no SLSA predicate type is used; no genuine SLSA statement exists",
            "no multi-subject statement is emitted against a real record",
        ],
        "evidence": "evidence/a9/STATEMENTS.json",
    },
    {
        "item": "A10",
        "module": "forensics/tools/dsse.py",
        "doc": "docs/DSSE-PAE.md",
        "state": "IMPLEMENTED_WITH_LIMITS",
        "supports": "DSSE v1 envelope framing and the exact PAE over received bytes",
        "refusalPrefix": "DS_REFUSED_",
        "refusalCodes": [
            "DS_REFUSED_ENVELOPE_INVALID",
            "DS_REFUSED_DUPLICATE_KEY",
            "DS_REFUSED_PAYLOAD_TYPE_MISSING",
            "DS_REFUSED_PAYLOAD_TYPE_MISMATCH",
            "DS_REFUSED_BASE64_NONCANONICAL",
            "DS_REFUSED_PAYLOAD_ABSENT",
            "DS_REFUSED_SIGNATURES_ABSENT",
            "DS_REFUSED_SIGNATURE_INVALID",
            "DS_REFUSED_PAE_RESERIALISED",
            "DS_REFUSED_PAE_LENGTH",
            "DS_REFUSED_PAYLOAD_NOT_STATEMENT",
            "DS_REFUSED_TRAILING_BYTES",
            "DS_REFUSED_OBJECT_SUPPLIED",
        ],
        "observed": [
            {"path": "evidence/a10/ENVELOPES.json", "pointer": "counts/envelopes", "equals": 4},
            {"path": "evidence/a10/ENVELOPES.json", "pointer": "counts/refusalCodes", "equals": 13},
        ],
        "limits": [
            "the signer and verifier are caller-supplied; the module makes no trust decision",
            "the four real envelopes use a test-only HMAC-SHA256 key",
            "no signature primitive is implemented",
        ],
        "evidence": "evidence/a10/ENVELOPES.json",
    },
    {
        "item": "A11",
        "module": "forensics/tools/harden.py",
        "doc": "docs/PARSER-HARDENING.md",
        "state": "IMPLEMENTED_WITH_LIMITS",
        "supports": "one strict JSON reader for received evidence, with a differential against a permissive reference",
        "refusalPrefix": "PH_REFUSED_",
        "refusalCodes": [
            "PH_REFUSED_ENCODING",
            "PH_REFUSED_BOM",
            "PH_REFUSED_DUPLICATE_KEY",
            "PH_REFUSED_DEPTH",
            "PH_REFUSED_SIZE",
            "PH_REFUSED_NONFINITE",
            "PH_REFUSED_TRAILING_DATA",
            "PH_REFUSED_INTEGER_RANGE",
            "PH_REFUSED_NUMBER_FORM",
            "PH_REFUSED_LONE_SURROGATE",
            "PH_REFUSED_CONTROL_CHARACTER",
            "PH_REFUSED_KEY_NOT_TEXT",
            "PH_REFUSED_SYNTAX",
        ],
        "observed": [
            {"path": "evidence/a11/SCAN.json", "pointer": "summary/strictOk", "equals": 331},
            {"path": "evidence/a11/SCAN.json", "pointer": "summary/files", "equals": 506},
            {"path": "evidence/a11/SCAN.json", "pointer": "summary/refused", "equals": 0},
        ],
        "limits": [
            "it hardens the evidence reader, not the Rust or C parsers",
            "a population record is frozen per candidate; growth is reported, not absorbed",
        ],
        "evidence": "evidence/a11/SCAN.json",
    },
    {
        "item": "A12",
        "module": "forensics/tools/independent_verify.py",
        "doc": "docs/INDEPENDENT-VERIFICATION.md",
        "state": "IMPLEMENTED_WITH_LIMITS",
        "supports": "the independent-verification decision: policy-selected external root, nine checks and four distinct outcomes",
        "refusalPrefix": "IV_REFUSED_",
        "refusalCodes": [
            "IV_REFUSED_ENVELOPE",
            "IV_REFUSED_KEY_FROM_ENVELOPE",
            "IV_REFUSED_SYMMETRIC",
            "IV_REFUSED_CANDIDATE_TRUST_ROOT",
            "IV_REFUSED_TRUST_ROOT_UNRECORDED",
            "IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH",
            "IV_REFUSED_SAME_DOMAIN",
            "IV_REFUSED_SELF_ISSUED",
            "IV_REFUSED_SIGNATURE",
            "IV_REFUSED_PAYLOAD_NOT_SUBJECT",
            "IV_REFUSED_SUBJECT_ABSENT",
            "IV_REFUSED_SUBJECT_MISMATCH",
            "IV_REFUSED_NO_PUBLIC_VERIFIER",
            "IV_REFUSED_TRUST_ROOT_STALE",
            "IV_REFUSED_MULTIPLE_ROOTS",
        ],
        "observed": [
            {"path": "evidence/a12/VERIFICATION.json", "pointer": "counts/independentlyVerified", "equals": 0},
            {"path": "evidence/a12/VERIFICATION.json", "pointer": "counts/envelopes", "equals": 4},
            {"path": "evidence/a12/VERIFICATION.json", "pointer": "counts/SELF_ISSUED", "equals": 4},
        ],
        "limits": [
            "the result is 0 of 4 envelopes independently verified and 4 self-issued",
            "no external trust root exists; the only recorded root is the A10 test-only HMAC key",
            "no signature primitive is implemented; a caller-supplied verifier decides",
        ],
        "evidence": "evidence/a12/VERIFICATION.json",
    },
    {
        "item": "A16",
        "module": "forensics/tools/sigstore_bundle.py",
        "doc": "docs/SIGSTORE-BUNDLES.md",
        "state": "IMPLEMENTED_WITH_LIMITS",
        "supports": "an offline Sigstore bundle v0.3 profile validator with explicit trust-root and freshness assumptions",
        "refusalPrefix": "SB_REFUSED_",
        "refusalCodes": [
            "SB_REFUSED_MEDIATYPE",
            "SB_REFUSED_VERSION",
            "SB_REFUSED_BUNDLE_INVALID",
            "SB_REFUSED_DUPLICATE_KEY",
            "SB_REFUSED_MATERIAL",
            "SB_REFUSED_CERT_CHAIN",
            "SB_REFUSED_CERT_ROOT_ABSENT",
            "SB_REFUSED_EXPIRED_CERT",
            "SB_REFUSED_ISSUER_MISMATCH",
            "SB_REFUSED_IDENTITY_MISMATCH",
            "SB_REFUSED_PAYLOAD_DIGEST",
            "SB_REFUSED_TLOG_ABSENT",
            "SB_REFUSED_TLOG_KIND",
            "SB_REFUSED_INTEGRATED_TIME",
            "SB_REFUSED_INCLUSION_PROOF",
            "SB_REFUSED_LOG_KEY_ABSENT",
            "SB_REFUSED_TIMESTAMP_ABSENT",
            "SB_REFUSED_TIMESTAMP_ROOT_ABSENT",
            "SB_REFUSED_TIMESTAMP_INVALID",
            "SB_REFUSED_SIGNATURE",
            "SB_REFUSED_POLICY_ABSENT",
            "SB_REFUSED_NETWORK_OR_CLIENT",
            "SB_REFUSED_INPUT_ABSENT",
        ],
        "observed": [
            {"path": "evidence/a16/INVENTORY.json", "pointer": "bundles", "equals": 0},
            {"path": "evidence/a16/INVENTORY.json", "pointer": "certificates", "equals": 0},
            {"path": "evidence/a16/INVENTORY.json", "pointer": "transparencyLogs", "equals": 0},
        ],
        "limits": [
            "0 Sigstore bundles, 0 transparency logs and 0 certificates exist here",
            "the log key, CA root and TSA root are supplied by policy and are not in the bundle or this tree",
            "the validator implements no signature primitive and contacts no network",
        ],
        "evidence": "evidence/a16/INVENTORY.json",
    },
    {
        "item": "A18",
        "module": "forensics/tools/key_lifecycle.py",
        "doc": "docs/KEY-LIFECYCLE.md",
        "state": "IMPLEMENTED_WITH_LIMITS",
        "supports": "a TUF-principles evaluator for rotation, delegation, expiry, revocation, anti-rollback, anti-freeze and stale releases",
        "refusalPrefix": "TK_REFUSED_",
        "refusalCodes": [
            "TK_REFUSED_REPOSITORY_INVALID",
            "TK_REFUSED_ROOT_ROLLBACK",
            "TK_REFUSED_ROOT_ROTATION_UNSIGNED_BY_OLD",
            "TK_REFUSED_TARGETS_ROLLBACK",
            "TK_REFUSED_SNAPSHOT_ROLLBACK",
            "TK_REFUSED_TIMESTAMP_ROLLBACK",
            "TK_REFUSED_SNAPSHOT_HASH_MISMATCH",
            "TK_REFUSED_TARGETS_HASH_MISMATCH",
            "TK_REFUSED_EXPIRED_METADATA",
            "TK_REFUSED_FREEZE",
            "TK_REFUSED_KEY_EXPIRED",
            "TK_REFUSED_KEY_NOT_YET_VALID",
            "TK_REFUSED_KEY_REVOKED",
            "TK_REFUSED_UNKNOWN_KEY",
            "TK_REFUSED_ROLE_KEY_MISMATCH",
            "TK_REFUSED_METADATA_THRESHOLD",
            "TK_REFUSED_DELEGATION_UNKNOWN",
            "TK_REFUSED_DELEGATION_EXPIRED",
            "TK_REFUSED_DELEGATION_HASH_MISMATCH",
            "TK_REFUSED_STALE_RELEASE",
            "TK_REFUSED_SIGNATURE",
        ],
        "observed": [
            {"path": "evidence/a18/INVENTORY.json", "pointer": "repositories", "equals": 0},
            {"path": "evidence/a18/INVENTORY.json", "pointer": "keyCount", "equals": 1},
            {"path": "evidence/a18/INVENTORY.json", "pointer": "revocationRecords", "equals": 0},
        ],
        "limits": [
            "0 repositories; every role and the stale-release check are NOT_RUN with TK_NOT_RUN",
            "the signature model is a structural digest, not cryptography",
            "one symmetric test-only key, with no expiry, revocation record, metadata version or delegation",
        ],
        "evidence": "evidence/a18/INVENTORY.json",
    },
]


def build_service(document: str) -> dict[str, Any]:
    return {
        "schema": pa.SERVICE_SCHEMA,
        "item": "B0",
        "model": pa.MODEL_ID,
        "recordedAt": RECORDED_AT,
        "baseCommit": BASE_COMMIT,
        "sources": {
            "addendum": pa.ADDENDUM,
            "freeze": pa.FREEZE,
            "modules": [entry["module"] for entry in CLIENT_SUPPORT],
            "note": (
                "the modules are the support that is actually present; the "
                "addendum is the register of what is pinned; the two are separate "
                "statements and neither implies a service"
            ),
        },
        "clientSupport": CLIENT_SUPPORT,
        "observed": {
            "clientSupport": len(CLIENT_SUPPORT),
            "statements": 4,
            "envelopes": 4,
            "bundles": 0,
            "repositories": 0,
            "independentlyVerified": "0/4",
        },
        "serviceConfigurationFinding": {
            "id": "SCF-1",
            "clause": "B.3.3",
            "observedDate": "2026-10-22",
            "state": "RECORDED",
            "verifiedHere": False,
            "finding": (
                "The Sigstore signing_config inspected on 2026-10-22 still "
                "advertised a Rekor v1 endpoint. A client version does not imply a "
                "v2 service, and installing a recent client does not activate a v2 log."
            ),
            "recordedIn": "docs/ETP-ADDENDUM-B.md B.3.3 item 2",
            "whatItMeansForB1": (
                "B1 may not assume a v2 endpoint exists. It must deploy and pin its "
                "own POSIX-backed Rekor v2 instance (§B.21), read the service "
                "metadata it actually uses (§B.10), and refuse a v1 fallback. A "
                "local slice cannot inherit a v2 endpoint from the client."
            ),
        },
        "tensions": [
            {
                "id": "T1",
                "clause": "B.3.3",
                "tension": (
                    "ML-DSA-44 is recommended by C2SP for new deployments and is "
                    "labelled experimental by the implementation."
                ),
                "consequence": (
                    "post-quantum checkpoint cosignatures stay on the research "
                    "track (§B.26); no production cosignature claim may cite the "
                    "C2SP recommendation as an available mechanism, and B1 uses the "
                    "classical signature path only."
                ),
                "resolved": False,
            },
            {
                "id": "T2",
                "clause": "B.3.3",
                "tension": (
                    "Service configuration is not implied by client version: the "
                    "inspected signing_config advertised a v1 endpoint."
                ),
                "consequence": (
                    "B1 cannot inherit a v2 endpoint and B4 must read authenticated "
                    "SigningConfig and TrustedRoot metadata (§B.10); any record that "
                    "infers a v2 service from a client version is refused."
                ),
                "resolved": False,
            },
            {
                "id": "T3",
                "clause": "B.3.3",
                "tension": (
                    "Older documentation describes a dedicated DSSE entry type; "
                    "since v2.3.0 one representation is supported and DSSE is "
                    "published as hashedrekord."
                ),
                "consequence": (
                    "B1 must derive the hashedrekord digest from the exact DSSE "
                    "envelope as the admitted client does (§B.5); the envelope "
                    "JSON, the payload alone and an unrelated manifest hash are not "
                    "substitutes, and A10's PAE is framing, not the log-entry digest."
                ),
                "resolved": False,
            },
        ],
        "claimsMade": [
            {
                "id": "CLM-01",
                "kind": "service",
                "claim": "a Rekor v2 transparency service is reachable from this tree",
                "established": False,
                "evidence": None,
                "reason": "no endpoint, log key or server binary exists; §B.3.3 records that the inspected signing_config advertised a v1 endpoint",
            },
            {
                "id": "CLM-02",
                "kind": "service",
                "claim": "a pinned rekor-tiles version is installed here",
                "established": False,
                "evidence": None,
                "reason": "command -v finds rekor-server, rekor-cli and rekor-tiles absent; no tracked binary exists",
            },
            {
                "id": "CLM-03",
                "kind": "service",
                "claim": "an admitted log key exists here",
                "established": False,
                "evidence": None,
                "reason": "evidence/a16/INVENTORY.json records 0 transparency logs and 0 log keys",
            },
            {
                "id": "CLM-04",
                "kind": "service",
                "claim": "a checkpoint cosignature can be produced or verified here",
                "established": False,
                "evidence": None,
                "reason": "no checkpoint resource, log key or cosignature implementation exists; the offline validator records SB_REFUSED_LOG_KEY_ABSENT",
            },
            {
                "id": "CLM-05",
                "kind": "service",
                "claim": "an independent witness set exists",
                "established": False,
                "evidence": None,
                "reason": "evidence/a12/TRUST-ROOTS.json records 0 external roots; witnessSet has 0 operators and 0 keys",
            },
            {
                "id": "CLM-06",
                "kind": "service",
                "claim": "an RFC 3161 timestamp authority is admitted",
                "established": False,
                "evidence": None,
                "reason": "evidence/a16/INVENTORY.json records 0 timestamp roots and no TSA is configured",
            },
            {
                "id": "CLM-07",
                "kind": "service",
                "claim": "a public Rekor endpoint is configured",
                "established": False,
                "evidence": None,
                "reason": "no tracked record names an endpoint; this item has no network access",
            },
            {
                "id": "CLM-08",
                "kind": "implementation",
                "claim": "an envelope in this tree is independently verified",
                "established": False,
                "evidence": "evidence/a12/VERIFICATION.json",
                "reason": "0 of 4 envelopes are independently verified; 4 are self-issued under the A10 test-only HMAC key",
            },
            {
                "id": "CLM-09",
                "kind": "implementation",
                "claim": "the DSSE/PAE module exists and refuses 13 named wrong conclusions",
                "established": True,
                "evidence": "docs/DSSE-PAE.md",
                "reason": "forensics/tools/dsse.py and its 13 controls; 4 envelopes",
            },
            {
                "id": "CLM-10",
                "kind": "implementation",
                "claim": "the in-toto statement module exists and refuses 12 named wrong conclusions",
                "established": True,
                "evidence": "docs/INTOTO-STATEMENTS.md",
                "reason": "forensics/tools/intoto.py and its 12 controls; 4 statements",
            },
            {
                "id": "CLM-11",
                "kind": "implementation",
                "claim": "the offline Sigstore bundle validator exists and there are 0 bundles",
                "established": True,
                "evidence": "docs/SIGSTORE-BUNDLES.md",
                "reason": "forensics/tools/sigstore_bundle.py, 23 refusal codes, 0 bundles",
            },
            {
                "id": "CLM-12",
                "kind": "implementation",
                "claim": "the key lifecycle evaluator exists and records 0 repositories",
                "established": True,
                "evidence": "docs/KEY-LIFECYCLE.md",
                "reason": "forensics/tools/key_lifecycle.py, 21 refusal codes plus TK_NOT_RUN, 0 repositories",
            },
            {
                "id": "CLM-13",
                "kind": "record",
                "claim": "every version in the registry is pinned by §B.3.2 and the recorded digest is the one §B.3.2 records",
                "established": True,
                "evidence": "docs/ETP-ADDENDUM-B.md",
                "reason": "registry evidence/b0/REGISTRY.json; protocol_audit.py refuses a version or digest that is not in its cited clause",
            },
            {
                "id": "CLM-14",
                "kind": "record",
                "claim": "signing_config advertised a v1 endpoint on 2026-10-22",
                "established": False,
                "evidence": "docs/ETP-ADDENDUM-B.md",
                "reason": "recorded by §B.3.3 from an upstream inspection; this item has no network access and did not repeat it",
            },
        ],
        "witnesses": {
            "classes": [
                {
                    "id": "log-key",
                    "primitive": "the admitted log's public key that verifies a checkpoint signature",
                    "available": False,
                    "checkedBy": "command-v-rekor-server",
                    "record": "evidence/a16/INVENTORY.json",
                    "observed": "bundles 0, transparencyLogs 0, certificates 0; no log key in the frozen population",
                },
                {
                    "id": "checkpoint-cosignature",
                    "primitive": "a checkpoint cosignature over (origin, size, hash) from an admitted cosigner",
                    "available": False,
                    "checkedBy": "command-v-rekor-server",
                    "record": "evidence/a16/INVENTORY.json",
                    "observed": "no checkpoint resource exists; the offline validator records SB_REFUSED_LOG_KEY_ABSENT",
                },
                {
                    "id": "witness-set",
                    "primitive": "a set of independent witness keys in distinct administrative domains with a quorum",
                    "available": False,
                    "checkedBy": "command-v-cosign",
                    "record": "evidence/a12/TRUST-ROOTS.json",
                    "observed": "counts.externalRoots 0; one symmetric same-party root",
                },
                {
                    "id": "rfc3161-tsa",
                    "primitive": "an admitted RFC 3161 timestamp authority with a trusted root and a verifier",
                    "available": False,
                    "checkedBy": "command-v-tsget",
                    "record": "evidence/a16/INVENTORY.json",
                    "observed": "no timestamp-authority root exists; every timestamp check is NOT_RUN",
                },
                {
                    "id": "public-rekor-endpoint",
                    "primitive": "an authenticated public Rekor v2 endpoint with SigningConfig and TrustedRoot",
                    "available": False,
                    "checkedBy": "command-v-rekor-cli",
                    "record": "docs/ETP-ADDENDUM-B.md",
                    "observed": "no endpoint is recorded; §B.3.3 records that signing_config advertised a v1 endpoint",
                },
            ],
            "witnessSet": {
                "operators": 0,
                "keys": 0,
                "quorum": None,
                "independent": False,
                "note": "no witness exists at any n; no quorum is admitted",
            },
        },
        "trustAssumptions": [
            {
                "id": "TA-B1",
                "item": "B1",
                "assumption": (
                    "a pinned rekor-tiles server binary matching a recorded digest "
                    "is installed and runs with the POSIX backend and a log key this "
                    "project controls"
                ),
                "state": "UNMET",
                "record": "evidence/a16/INVENTORY.json",
                "observed": "registry evidence/b0/REGISTRY.json records 0 installed and 0 executable; the only recorded digest is the v2.4.2 rekor-server-aws asset, not the POSIX-profile server",
                "wouldEstablish": (
                    "B1 records the digest of the exact server artefact it installs "
                    "and a checkpoint signed by its own log key"
                ),
            },
            {
                "id": "TA-B2",
                "item": "B2",
                "assumption": "an admitted RFC 3161 timestamp authority with a trusted root and a verifier",
                "state": "UNMET",
                "record": "evidence/a16/INVENTORY.json",
                "observed": "0 certificates and no timestamp-authority root",
                "wouldEstablish": "B2 integrates a TSA token and verifies it offline under an admitted root",
            },
            {
                "id": "TA-B3",
                "item": "B3",
                "assumption": "an authenticated signer for campaign opening and closure that is not the producer",
                "state": "UNMET",
                "record": "evidence/a12/VERIFICATION.json",
                "observed": "0 of 4 envelopes independently verified; 4 self-issued",
                "wouldEstablish": "a policy-selected external key verifies the opening and closing statements",
            },
            {
                "id": "TA-B4",
                "item": "B4",
                "assumption": "an admitted public-good Rekor v2 endpoint with authenticated SigningConfig and TrustedRoot metadata",
                "state": "UNMET",
                "record": "docs/ETP-ADDENDUM-B.md",
                "observed": "no endpoint is recorded; the inspected signing_config advertised v1",
                "wouldEstablish": "B4 reads authenticated service metadata and publishes to the admitted profile",
            },
            {
                "id": "TA-B5",
                "item": "B5",
                "assumption": "a witness set of independent operators with a quorum and persistent checkpoint state",
                "state": "UNMET",
                "record": "evidence/a12/TRUST-ROOTS.json",
                "observed": "0 external roots, 0 witness operators, no persistence",
                "wouldEstablish": "B5 admits independently operated witnesses and verifies their cosignatures",
            },
            {
                "id": "TA-B6",
                "item": "B6",
                "assumption": "an independent archive with content-addressed retrieval and a current-state revocation authority",
                "state": "UNMET",
                "record": "evidence/a18/INVENTORY.json",
                "observed": "0 repositories and 0 revocation records",
                "wouldEstablish": "B6 demonstrates offline reconstruction and a withdrawn claim refused by current-state policy",
            },
        ],
        "nonClaims": [
            "a registry entry is not a deployment and a pinned version is not an admitted service",
            "this item runs no Rekor, no witness, no timestamp authority and no Sigstore client",
            "no network access was used; nothing was fetched, installed or started",
            "the signing_config finding is recorded from §B.3.3, not re-observed here",
            "the presence observations are dated 2026-11-24 and are not a live guarantee",
            "0 of 4 envelopes are independently verified; SELF_ISSUED is not a pass",
            "the registry does not establish that any version is current or free of security advisories; §B.5 requires a recheck at admission",
        ],
    }


def _serialise(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def write_json(path: Path, document: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_bytes(_serialise(document))
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="produce the B0 registry and service configuration")
    parser.add_argument("--check", action="store_true", help="validate the committed records")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    document = ADDENDUM.read_text(encoding="utf-8")
    registry = build_registry(document)
    service = build_service(document)

    findings = pa.check_registry(registry, REPO_ROOT, document, live=False)
    findings += pa.check_service(service, registry, REPO_ROOT, document)
    if findings:
        for code, detail in findings:
            print(f"code={code} detail={detail}")
        print(
            "b0: refusing to write a record that protocol_audit would refuse: "
            + ",".join(sorted({code for code, _ in findings}))
        )
        return 1

    if not args.check:
        write_json(REGISTRY_OUT, registry)
        write_json(SERVICE_OUT, service)

    # The freeze names the two files this item writes; check that binding after
    # the files exist, so a first run from a clean checkout is reproducible.
    freeze_findings = pa.check_freeze_members(REPO_ROOT)
    if freeze_findings:
        for code, detail in freeze_findings:
            print(f"code={code} detail={detail}")
        print("b0: the written records do not satisfy the forward freeze")
        return 1

    summary = registry["summary"]
    print(
        f"b0: components={summary['components']} pinned={summary['pinned']} "
        f"installed={summary['installed']} executable={summary['executable']} "
        f"servicesReachable={summary['servicesReachable']} "
        f"clients={len(CLIENT_SUPPORT)} witnesses=0 trust=6/unmet codes=NONE"
    )
    print(
        f"b0: registry={REGISTRY_OUT.relative_to(REPO_ROOT)} "
        f"service={SERVICE_OUT.relative_to(REPO_ROOT)} "
        f"registry.sha256={hashlib.sha256(_serialise(registry)).hexdigest()} "
        f"service.sha256={hashlib.sha256(_serialise(service)).hexdigest()}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
