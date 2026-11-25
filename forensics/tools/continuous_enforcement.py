#!/usr/bin/env python3
"""continuous_enforcement.py -- keep the transparency policy from regressing silently.

Why this tool exists
--------------------
`docs/ETP-ADDENDUM-B.md` section B.30 defines B8 as "continuous enforcement":
integrate the admitted profile into `AGENTS.md`, release gates, ETP claim
schemas, CI and public non-claims, and prevent a silent regression of the
transparency guarantees.  A policy that lives only in prose regresses by
convention: the next commit removes a check, the document still says the check
runs, and nothing refuses.

This tool is the machine form of the policy.  It reads the records that state
the profile (B0 and B4), the claim document and its schema, the public
non-claims, the release gate and the enforcement record, and returns one finding
per wrong conclusion.  The release gate calls it as item 10
(``forensics/tools/release_gate.py``, ``check_transparency``); a refusal here is
a refused release.

What it refuses
---------------
``CE_REFUSED_PROFILE_ABSENT``
    the B0 registry, or the B4 publication record, is absent or is not readable
    as the record of that schema;
``CE_REFUSED_REGISTRY_STALE``
    the registry is internally inconsistent, or a version it declares is not
    found in the addendum clause it cites;
``CE_REFUSED_PUBLICATION_CLAIM``
    a claim's transparency state is ``PUBLISHED`` while the B4 record says
    ``published: 0``;
``CE_REFUSED_PROFILE_NOT_ADMITTED``
    a claim's transparency state is ``ADMITTED`` while the B4 record says
    ``admittedService: false``;
``CE_REFUSED_SCHEMA_FIELD_ABSENT``
    a claim carries a transparency-shaped field the schema does not define, a
    value outside the closed enum, or omits the field where the schema requires
    it;
``CE_REFUSED_UNBOUND_CLAIM``
    an ``ADMITTED`` or ``PUBLISHED`` claim names no statement and bundle digest,
    or names one that is not a SHA-256 digest;
``CE_REFUSED_NONCLAIMS_ABSENT``
    the public non-claims document is absent, does not name one of the five
    unestablished properties, or does not cite the section that requires it;
``CE_REFUSED_ENFORCEMENT_REGRESSION``
    a gate item has disappeared, the transparency item is no longer wired, the
    enforcement record or its normative document is absent, or a refusal code
    that used to be checked is no longer named.

``CE_OK`` is the positive code.  ``CE_REFUSED_USAGE`` is the command-line code.
Every refusal code has a control in ``evidence/b8/CONTROLS.json`` and a test in
``forensics/tools/tests/test_continuous_enforcement.py``.

What this does not establish
----------------------------
It checks that the enforcement is wired and that no claim asserts more than the
B4 record supports.  It does not decide that a statement was published, that a
log admitted it, that a witness exists, or that an independent party reproduced
anything.  A passing check is not a transparency result (AGENTS.md section 8).

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = "forensics/tools/continuous_enforcement.py"

REGISTRY_PATH = REPO_ROOT / "evidence/b0/REGISTRY.json"
PUBLICATION_PATH = REPO_ROOT / "evidence/b4/PUBLICATION.json"
CLAIMS_PATH = REPO_ROOT / "evidence/etp/claims.json"
SCHEMA_PATH = REPO_ROOT / "evidence/etp/claim.schema.json"
ADDENDUM_PATH = REPO_ROOT / "docs/ETP-ADDENDUM-B.md"
NONCLAIMS_PATH = REPO_ROOT / "docs/TRANSPARENCY-NON-CLAIMS.md"
GATE_PATH = REPO_ROOT / "forensics/tools/release_gate.py"
ENFORCEMENT_PATH = REPO_ROOT / "evidence/b8/ENFORCEMENT.json"
DOCUMENT_PATH = REPO_ROOT / "docs/CONTINUOUS-ENFORCEMENT.md"

SCHEMA_ENFORCEMENT = "openssl-rs/b8/enforcement/1"
SCHEMA_CONTROLS = "openssl-rs/b8/controls/1"
SCHEMA_REGISTRY = "openssl-rs/b0/registry/1"
SCHEMA_PUBLICATION = "openssl-rs/b4/publication/1"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

CODE_OK = "CE_OK"
CODE_USAGE = "CE_REFUSED_USAGE"

#: Stable refusal vocabulary.  The key is the code; the value names the wrong
#: conclusion it prevents.  ``docs/CONTINUOUS-ENFORCEMENT.md`` names every code
#: and the test that fires it.
REFUSALS: dict[str, str] = {
    "CE_REFUSED_PROFILE_ABSENT": (
        "the B0 registry or the B4 publication record is absent or unreadable, "
        "so the admitted profile cannot be stated"
    ),
    "CE_REFUSED_REGISTRY_STALE": (
        "the registry contradicts itself, or a version it declares is not in "
        "the addendum clause it cites"
    ),
    "CE_REFUSED_PUBLICATION_CLAIM": (
        "a claim asserts publication while the B4 record says published: 0"
    ),
    "CE_REFUSED_PROFILE_NOT_ADMITTED": (
        "a claim asserts admission while the B4 record says admittedService: false"
    ),
    "CE_REFUSED_SCHEMA_FIELD_ABSENT": (
        "a claim carries a transparency field the schema does not define, a "
        "value outside the closed enum, or omits the field where it is required"
    ),
    "CE_REFUSED_UNBOUND_CLAIM": (
        "an ADMITTED or PUBLISHED claim names no statement and bundle digest "
        "bound by SHA-256"
    ),
    "CE_REFUSED_NONCLAIMS_ABSENT": (
        "the public non-claims document is absent or does not name the "
        "unestablished properties it exists to state"
    ),
    "CE_REFUSED_ENFORCEMENT_REGRESSION": (
        "a gate item, the transparency wiring, the enforcement record, its "
        "document or a previously checked refusal code has disappeared"
    ),
    "CE_REFUSED_USAGE": "the command line was used incorrectly",
}
REFUSAL_CODES = tuple(REFUSALS)

#: The five properties the public non-claims document must name, and the marker
#: its text must contain.  The list is the complement of the §B.29 SEAL and
#: EXTERNAL rows: every SEAL obligation that is not met in this venue is named.
NONCLAIMS: tuple[tuple[str, str], ...] = (
    ("admitted-rekor-service", "no admitted Rekor service"),
    ("witness", "no witness"),
    ("trusted-timestamp", "no trusted timestamp"),
    ("publication", "no publication"),
    ("independent-reproduction", "no independent reproduction"),
)
NONCLAIMS_CLAUSE = "§B.29"

#: The release gate's items, in the order the queue defines.  A missing function
#: is a missing item; a symbol that is not called from ``evaluate`` is a
#: disconnected item.  The last row is B8's own item.
GATE_ITEMS: tuple[tuple[str, str, str], ...] = (
    ("1", "candidate identity", "resolve_candidate"),
    ("2", "claim set", "check_claims"),
    ("2b", "identity triage", "load_triage"),
    ("3", "interop receipts", "check_receipts"),
    ("4", "instrument register", "check_instruments"),
    ("5", "external package", "check_package"),
    ("6", "documentation consistency", "check_docs"),
    ("7", "role authorisation", "check_authorisation"),
    ("8", "thresholds", "check_thresholds"),
    ("9", "release policy", "check_policy"),
    ("10", "transparency enforcement", "check_transparency"),
)
TRANSPARENCY_ITEM = "10"

#: The claim-level condition under which the schema requires ``transparency``.
#: The tool reads the rule from the schema; this constant is only the value a
#: schema without the rule is checked against (a missing rule is a regression).
TRANSPARENCY_REQUIRED_AUTHORITY = "public-transparency-log"

#: Transparency states that assert an achievement and therefore need a binding.
BOUND_STATES = ("ADMITTED", "PUBLISHED")
DEFAULT_STATE_ENUM = ("NOT_ADMITTED", "ADMITTED", "PUBLISHED")
DEFAULT_FIELDS = ("state", "profile", "statementDigest", "bundleDigest", "publishedAt")
DEFAULT_SHA256 = "^[0-9a-f]{64}$"
DEFAULT_TIMESTAMP = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"


@dataclass(frozen=True)
class Finding:
    code: str
    artefact: str
    detail: str

    def line(self) -> str:
        return f"REFUSED {self.code} {self.artefact}: {self.detail}"


@dataclass
class CheckResult:
    findings: list[Finding]
    population: dict[str, Any]

    def refused(self) -> bool:
        return bool(self.findings)


def pretty(value: Any) -> bytes:
    """Canonical bytes: sorted keys, one-space indent, one trailing newline."""
    return (json.dumps(value, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _duplicate_key(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"duplicate object key {key!r}")
        seen.add(key)
    return dict(pairs)


def _non_finite(token: str) -> Any:
    raise ValueError(f"non-finite number {token}")


def load_json(path: Path) -> Any:
    return json.loads(
        Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=_duplicate_key,
        parse_constant=_non_finite,
    )


def _text(path: Path) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return None


def _clause_section(addendum: str, clause: str) -> str | None:
    """The text of one ``### B.x.y.`` section, or None when it is absent."""
    match = re.search(rf"^###\s+{re.escape(clause)}\.", addendum, re.MULTILINE)
    if match is None:
        return None
    following = re.search(r"^###\s+B\.", addendum[match.end():], re.MULTILINE)
    end = match.end() + following.start() if following else len(addendum)
    return addendum[match.start():end]


def _as_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


# ---------------------------------------------------------------------------
# 1. The profile records (B0 and B4)
# ---------------------------------------------------------------------------
def check_registry(
    registry: Path | str = REGISTRY_PATH,
    addendum: Path | str = ADDENDUM_PATH,
) -> list[Finding]:
    """The B0 registry must exist and its versions must be in the cited clauses."""
    registry = Path(registry)
    addendum_path = Path(addendum)
    if not registry.is_file():
        return [Finding(
            "CE_REFUSED_PROFILE_ABSENT", str(registry),
            "the B0 registry is absent; an absent profile record is a refusal, not a skip",
        )]
    try:
        document = load_json(registry)
    except (OSError, ValueError) as exc:
        return [Finding(
            "CE_REFUSED_REGISTRY_STALE", str(registry),
            f"the registry cannot be read as JSON: {exc}",
        )]
    if not isinstance(document, dict):
        return [Finding(
            "CE_REFUSED_REGISTRY_STALE", str(registry), "the registry is not a JSON object"
        )]
    findings: list[Finding] = []
    if document.get("schema") != SCHEMA_REGISTRY:
        findings.append(Finding(
            "CE_REFUSED_REGISTRY_STALE", str(registry),
            f"schema is {document.get('schema')!r}, expected {SCHEMA_REGISTRY!r}",
        ))
    if document.get("item") != "B0":
        findings.append(Finding(
            "CE_REFUSED_REGISTRY_STALE", str(registry),
            f"item is {document.get('item')!r}, expected 'B0'",
        ))

    summary = document.get("summary")
    components = document.get("components")
    if not isinstance(summary, dict) or not isinstance(components, list):
        return findings + [Finding(
            "CE_REFUSED_REGISTRY_STALE", str(registry),
            "the registry has no summary object or no components list",
        )]

    if "serviceReachable" not in document:
        findings.append(Finding(
            "CE_REFUSED_REGISTRY_STALE", str(registry),
            "the registry does not state serviceReachable",
        ))
    elif bool(document.get("serviceReachable")) != bool(summary.get("servicesReachable", 0) > 0):
        findings.append(Finding(
            "CE_REFUSED_REGISTRY_STALE", str(registry),
            f"serviceReachable={document.get('serviceReachable')!r} disagrees with "
            f"summary.servicesReachable={summary.get('servicesReachable')!r}",
        ))

    installed = executable = 0
    for component in components:
        if not isinstance(component, dict):
            findings.append(Finding(
                "CE_REFUSED_REGISTRY_STALE", str(registry),
                "a components entry is not an object",
            ))
            continue
        presence = component.get("presence")
        if isinstance(presence, dict):
            installed += 1 if presence.get("installed") is True else 0
            executable += 1 if presence.get("executable") is True else 0
    if _as_int(summary.get("installed")) is not None and summary["installed"] != installed:
        findings.append(Finding(
            "CE_REFUSED_REGISTRY_STALE", str(registry),
            f"summary.installed={summary['installed']} but {installed} component(s) are installed",
        ))
    if _as_int(summary.get("executable")) is not None and summary["executable"] != executable:
        findings.append(Finding(
            "CE_REFUSED_REGISTRY_STALE", str(registry),
            f"summary.executable={summary['executable']} but {executable} component(s) are executable",
        ))

    addendum_text = _text(addendum_path)
    if addendum_text is None:
        findings.append(Finding(
            "CE_REFUSED_REGISTRY_STALE", str(addendum_path),
            "the addendum cannot be read, so no declared version can be checked",
        ))
        return findings

    for component in components:
        if not isinstance(component, dict):
            continue
        version = component.get("version")
        if version is None:
            continue
        source = component.get("source")
        clause = source.get("clause") if isinstance(source, dict) else None
        ident = str(component.get("id", "<no id>"))
        if not isinstance(clause, str) or not isinstance(version, str):
            findings.append(Finding(
                "CE_REFUSED_REGISTRY_STALE", ident,
                "a declared version has no source clause",
            ))
            continue
        section = _clause_section(addendum_text, clause)
        if section is None:
            findings.append(Finding(
                "CE_REFUSED_REGISTRY_STALE", ident,
                f"the cited clause {clause} is not in {addendum_path}",
            ))
        elif version not in section:
            findings.append(Finding(
                "CE_REFUSED_REGISTRY_STALE", ident,
                f"version {version!r} is not in the cited clause {clause}",
            ))
    return findings


def check_publication(publication: Path | str = PUBLICATION_PATH) -> list[Finding]:
    """The B4 record must exist and must state publication and admission."""
    publication = Path(publication)
    if not publication.is_file():
        return [Finding(
            "CE_REFUSED_PROFILE_ABSENT", str(publication),
            "the B4 publication record is absent; the admitted profile cannot be stated",
        )]
    try:
        document = load_json(publication)
    except (OSError, ValueError) as exc:
        return [Finding(
            "CE_REFUSED_PROFILE_ABSENT", str(publication),
            f"the publication record cannot be read: {exc}",
        )]
    if not isinstance(document, dict):
        return [Finding(
            "CE_REFUSED_PROFILE_ABSENT", str(publication),
            "the publication record is not a JSON object",
        )]
    findings: list[Finding] = []
    if document.get("schema") != SCHEMA_PUBLICATION:
        findings.append(Finding(
            "CE_REFUSED_PROFILE_ABSENT", str(publication),
            f"schema is {document.get('schema')!r}, expected {SCHEMA_PUBLICATION!r}",
        ))
    if _as_int(document.get("published")) is None or document.get("published") < 0:
        findings.append(Finding(
            "CE_REFUSED_PROFILE_ABSENT", str(publication),
            "published is not a non-negative integer",
        ))
    if not isinstance(document.get("admittedService"), bool):
        findings.append(Finding(
            "CE_REFUSED_PROFILE_ABSENT", str(publication),
            "admittedService is not a boolean",
        ))
    if not isinstance(document.get("profile"), dict):
        findings.append(Finding(
            "CE_REFUSED_PROFILE_ABSENT", str(publication),
            "the record names no profile object",
        ))
    return findings


# ---------------------------------------------------------------------------
# 2. The claim schema and the claims
# ---------------------------------------------------------------------------
def transparency_definition(schema: Mapping[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return (fields, state enum) from the schema, refusing a missing definition."""
    definitions = schema.get("$defs") if isinstance(schema, dict) else None
    block = definitions.get("transparency") if isinstance(definitions, dict) else None
    if not isinstance(block, dict):
        raise ValueError("the schema has no $defs/transparency")
    properties = block.get("properties")
    state = properties.get("state") if isinstance(properties, dict) else None
    states = state.get("enum") if isinstance(state, dict) else None
    return (
        tuple(sorted(properties)) if isinstance(properties, dict) else (),
        tuple(states) if isinstance(states, list) else (),
    )


def transparency_required_authority(schema: Mapping[str, Any]) -> str | None:
    """The authority kind that makes ``transparency`` required, read from the schema."""
    definition = schema.get("$defs", {}).get("claim", {}) if isinstance(schema, dict) else {}
    for rule in definition.get("allOf", []) if isinstance(definition, dict) else []:
        if not isinstance(rule, dict):
            continue
        then = rule.get("then")
        if isinstance(then, dict) and then.get("required") == ["transparency"]:
            try:
                return rule["if"]["properties"]["authority"]["properties"]["kind"]["const"]
            except (KeyError, TypeError):
                return None
    return None


def _pattern(schema: Mapping[str, Any], name: str, default: str) -> str:
    definition = schema.get("$defs", {}).get(name, {}) if isinstance(schema, dict) else {}
    pattern = definition.get("pattern") if isinstance(definition, dict) else None
    return pattern if isinstance(pattern, str) else default


def _valid(pattern: str, value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def check_claims(
    claims: Path | str = CLAIMS_PATH,
    schema: Path | str = SCHEMA_PATH,
    publication: Path | str = PUBLICATION_PATH,
) -> tuple[list[Finding], dict[str, Any]]:
    """Every claim's transparency field must be defined, bound and honest."""
    claims, schema, publication = Path(claims), Path(schema), Path(publication)
    population: dict[str, Any] = {
        "claimCount": 0,
        "claimsWithTransparency": 0,
        "byState": {},
        "requiredBy": TRANSPARENCY_REQUIRED_AUTHORITY,
    }
    if not schema.is_file():
        return [Finding(
            "CE_REFUSED_ENFORCEMENT_REGRESSION", str(schema),
            "the claim schema is absent, so the transparency field cannot be enforced",
        )], population
    try:
        schema_document = load_json(schema)
    except (OSError, ValueError) as exc:
        return [Finding(
            "CE_REFUSED_ENFORCEMENT_REGRESSION", str(schema),
            f"the claim schema cannot be read: {exc}",
        )], population
    if not isinstance(schema_document, dict):
        return [Finding(
            "CE_REFUSED_ENFORCEMENT_REGRESSION", str(schema),
            "the claim schema is not a JSON object",
        )], population
    try:
        fields, states = transparency_definition(schema_document)
    except ValueError as exc:
        return [Finding(
            "CE_REFUSED_ENFORCEMENT_REGRESSION", str(schema), str(exc)
        )], population
    required_authority = transparency_required_authority(schema_document)
    if required_authority is None:
        return [Finding(
            "CE_REFUSED_ENFORCEMENT_REGRESSION", str(schema),
            "the schema no longer requires transparency for a transparency-log authority",
        )], population
    population["requiredBy"] = required_authority

    if not claims.is_file():
        return [Finding(
            "CE_REFUSED_ENFORCEMENT_REGRESSION", str(claims),
            "the claim document is absent, so no transparency assertion can be checked",
        )], population
    try:
        document = load_json(claims)
    except (OSError, ValueError) as exc:
        return [Finding(
            "CE_REFUSED_ENFORCEMENT_REGRESSION", str(claims),
            f"the claim document cannot be read: {exc}",
        )], population
    records = document.get("claims") if isinstance(document, dict) else None
    if not isinstance(records, list):
        return [Finding(
            "CE_REFUSED_ENFORCEMENT_REGRESSION", str(claims),
            "the claim document has no claims array",
        )], population

    published = 0
    admitted = False
    if publication.is_file():
        try:
            record = load_json(publication)
        except (OSError, ValueError):
            record = {}
        if isinstance(record, dict):
            published = _as_int(record.get("published")) or 0
            admitted = record.get("admittedService") is True

    sha_pattern = _pattern(schema_document, "sha256", DEFAULT_SHA256)
    stamp_pattern = (
        schema_document.get("$defs", {}).get("transparency", {})
        .get("properties", {}).get("publishedAt", {}).get("pattern", DEFAULT_TIMESTAMP)
    )
    profile_enum = tuple(
        schema_document.get("$defs", {}).get("transparency", {})
        .get("properties", {}).get("profile", {}).get("enum", ())
    )

    findings: list[Finding] = []
    population["claimCount"] = len([row for row in records if isinstance(row, dict)])
    for row in records:
        if not isinstance(row, dict):
            continue
        ident = str(row.get("id", "<no id>"))
        for key in row:
            if key.startswith("transparency") and key != "transparency":
                findings.append(Finding(
                    "CE_REFUSED_SCHEMA_FIELD_ABSENT", f"{ident}/{key}",
                    f"claim {ident} carries {key!r}, which the schema does not define",
                ))
        authority = row.get("authority")
        authority_kind = authority.get("kind") if isinstance(authority, dict) else None
        present = "transparency" in row
        if authority_kind == required_authority and not present:
            findings.append(Finding(
                "CE_REFUSED_SCHEMA_FIELD_ABSENT", ident,
                f"claim {ident} names authority.kind={authority_kind!r} but carries no "
                "transparency field, which the schema requires for that authority",
            ))
        if not present:
            continue
        population["claimsWithTransparency"] += 1
        block = row.get("transparency")
        if not isinstance(block, dict):
            findings.append(Finding(
                "CE_REFUSED_SCHEMA_FIELD_ABSENT", ident,
                f"claim {ident} has a transparency field that is not an object",
            ))
            continue
        unknown = sorted(set(block) - set(fields))
        if unknown:
            findings.append(Finding(
                "CE_REFUSED_SCHEMA_FIELD_ABSENT", ident,
                f"claim {ident} carries undefined transparency field(s) {unknown}",
            ))
        state = block.get("state")
        if state not in states:
            findings.append(Finding(
                "CE_REFUSED_SCHEMA_FIELD_ABSENT", f"{ident}/state",
                f"claim {ident} state {state!r} is not one of {list(states)}",
            ))
            continue
        population["byState"][state] = population["byState"].get(state, 0) + 1
        profile = block.get("profile")
        if profile is not None and profile_enum and profile not in profile_enum:
            findings.append(Finding(
                "CE_REFUSED_SCHEMA_FIELD_ABSENT", f"{ident}/profile",
                f"claim {ident} profile {profile!r} is not one of {list(profile_enum)}",
            ))
        if state in BOUND_STATES:
            if not isinstance(block.get("profile"), str) or not block.get("profile"):
                findings.append(Finding(
                    "CE_REFUSED_UNBOUND_CLAIM", f"{ident}/profile",
                    f"claim {ident} states {state} but names no profile",
                ))
            for name in ("statementDigest", "bundleDigest"):
                if not _valid(sha_pattern, block.get(name)):
                    findings.append(Finding(
                        "CE_REFUSED_UNBOUND_CLAIM", f"{ident}/{name}",
                        f"claim {ident} states {state} but {name} is not a SHA-256 digest",
                    ))
            if state == "PUBLISHED":
                if "publishedAt" not in block:
                    findings.append(Finding(
                        "CE_REFUSED_SCHEMA_FIELD_ABSENT", f"{ident}/publishedAt",
                        f"claim {ident} states PUBLISHED but carries no publishedAt",
                    ))
                elif not _valid(str(stamp_pattern), block.get("publishedAt")):
                    findings.append(Finding(
                        "CE_REFUSED_SCHEMA_FIELD_ABSENT", f"{ident}/publishedAt",
                        f"claim {ident} publishedAt is not an RFC 3339 UTC instant",
                    ))
                if published < 1:
                    findings.append(Finding(
                        "CE_REFUSED_PUBLICATION_CLAIM", ident,
                        f"claim {ident} asserts PUBLISHED while evidence/b4/PUBLICATION.json "
                        f"records published={published}",
                    ))
            if state == "ADMITTED" and not admitted:
                findings.append(Finding(
                    "CE_REFUSED_PROFILE_NOT_ADMITTED", ident,
                    f"claim {ident} asserts ADMITTED while evidence/b4/PUBLICATION.json "
                    "records admittedService=false",
                ))
    return findings, population


# ---------------------------------------------------------------------------
# 3. The public non-claims
# ---------------------------------------------------------------------------
def check_nonclaims(nonclaims: Path | str = NONCLAIMS_PATH) -> list[Finding]:
    """The public non-claims document must exist and name every property."""
    nonclaims = Path(nonclaims)
    text = _text(nonclaims)
    if text is None:
        return [Finding(
            "CE_REFUSED_NONCLAIMS_ABSENT", str(nonclaims),
            "the public non-claims document is absent; a non-claim that is not "
            "written is one a reader can infer wrongly",
        )]
    findings: list[Finding] = []
    lowered = text.lower()
    for ident, marker in NONCLAIMS:
        if marker.lower() not in lowered:
            findings.append(Finding(
                "CE_REFUSED_NONCLAIMS_ABSENT", f"{nonclaims}#{ident}",
                f"the document does not name {marker!r}",
            ))
    if NONCLAIMS_CLAUSE.lower() not in lowered:
        findings.append(Finding(
            "CE_REFUSED_NONCLAIMS_ABSENT", str(nonclaims),
            f"the document does not cite {NONCLAIMS_CLAUSE}, the section that requires the list",
        ))
    return findings


# ---------------------------------------------------------------------------
# 4. The enforcement wiring
# ---------------------------------------------------------------------------
def _evaluate_block(source: str) -> str:
    match = re.search(r"^def evaluate\(.*?(?=^def\s)", source, re.MULTILINE | re.DOTALL)
    return match.group(0) if match else ""


def check_enforcement(
    gate: Path | str = GATE_PATH,
    enforcement: Path | str | None = ENFORCEMENT_PATH,
    document: Path | str = DOCUMENT_PATH,
    gate_text: str | None = None,
    enforcement_record: Mapping[str, Any] | None = None,
    document_text: str | None = None,
) -> list[Finding]:
    """Every gate item and every transparency code must still be wired and named."""
    gate = Path(gate)
    source = gate_text if gate_text is not None else _text(gate)
    if source is None:
        return [Finding(
            "CE_REFUSED_ENFORCEMENT_REGRESSION", str(gate),
            "the release gate source is absent",
        )]
    findings: list[Finding] = []
    block = _evaluate_block(source)
    for number, label, symbol in GATE_ITEMS:
        if f"def {symbol}(" not in source:
            findings.append(Finding(
                "CE_REFUSED_ENFORCEMENT_REGRESSION", f"gate-{number}",
                f"item {number} ({label}) has disappeared: {symbol} is not defined",
            ))
        elif f"{symbol}(" not in block:
            findings.append(Finding(
                "CE_REFUSED_ENFORCEMENT_REGRESSION", f"gate-{number}",
                f"item {number} ({label}) is not called from evaluate()",
            ))
    if "continuous_enforcement" not in source:
        findings.append(Finding(
            "CE_REFUSED_ENFORCEMENT_REGRESSION", str(gate),
            "the release gate no longer names continuous_enforcement",
        ))
    if "10. transparency" not in source:
        findings.append(Finding(
            "CE_REFUSED_ENFORCEMENT_REGRESSION", str(gate),
            "the release gate's item list no longer names item 10 (transparency)",
        ))

    if enforcement_record is None:
        record_path = Path(enforcement) if enforcement is not None else ENFORCEMENT_PATH
        if not record_path.is_file():
            findings.append(Finding(
                "CE_REFUSED_ENFORCEMENT_REGRESSION", str(record_path),
                "the B8 enforcement record is absent; the baseline of checked codes is gone",
            ))
            record = None
        else:
            try:
                record = load_json(record_path)
            except (OSError, ValueError) as exc:
                findings.append(Finding(
                    "CE_REFUSED_ENFORCEMENT_REGRESSION", str(record_path),
                    f"the enforcement record cannot be read: {exc}",
                ))
                record = None
    else:
        record = dict(enforcement_record)
    declared = record.get("refusalCodes") if isinstance(record, dict) else None
    if not isinstance(declared, list):
        if record is not None:
            findings.append(Finding(
                "CE_REFUSED_ENFORCEMENT_REGRESSION", "evidence/b8/ENFORCEMENT.json",
                "the enforcement record states no refusalCodes list",
            ))
    else:
        missing = sorted(set(REFUSAL_CODES) - set(declared))
        if missing:
            findings.append(Finding(
                "CE_REFUSED_ENFORCEMENT_REGRESSION", "evidence/b8/ENFORCEMENT.json",
                f"the enforcement record no longer names the checked code(s) {missing}",
            ))
        unknown = sorted(set(declared) - set(REFUSAL_CODES) - {CODE_OK})
        if unknown:
            findings.append(Finding(
                "CE_REFUSED_ENFORCEMENT_REGRESSION", "evidence/b8/ENFORCEMENT.json",
                f"the enforcement record names code(s) the tool does not emit {unknown}",
            ))

    doc_path = Path(document)
    text = document_text if document_text is not None else _text(doc_path)
    if text is None:
        findings.append(Finding(
            "CE_REFUSED_ENFORCEMENT_REGRESSION", str(doc_path),
            "the normative enforcement document is absent",
        ))
    else:
        for code in REFUSAL_CODES:
            if code not in text:
                findings.append(Finding(
                    "CE_REFUSED_ENFORCEMENT_REGRESSION", str(doc_path),
                    f"the document no longer names {code}",
                ))
    return findings


def check(
    registry: Path | str = REGISTRY_PATH,
    publication: Path | str = PUBLICATION_PATH,
    claims: Path | str = CLAIMS_PATH,
    schema: Path | str = SCHEMA_PATH,
    nonclaims: Path | str = NONCLAIMS_PATH,
    gate: Path | str = GATE_PATH,
    enforcement: Path | str | None = ENFORCEMENT_PATH,
    document: Path | str = DOCUMENT_PATH,
    addendum: Path | str = ADDENDUM_PATH,
    enforcement_record: Mapping[str, Any] | None = None,
) -> CheckResult:
    findings: list[Finding] = []
    findings.extend(check_registry(registry, addendum))
    findings.extend(check_publication(publication))
    claim_findings, population = check_claims(claims, schema, publication)
    findings.extend(claim_findings)
    findings.extend(check_nonclaims(nonclaims))
    findings.extend(check_enforcement(
        gate=gate,
        enforcement=enforcement,
        document=document,
        enforcement_record=enforcement_record,
    ))
    population["refusalCount"] = len(findings)
    return CheckResult(findings, population)


# ---------------------------------------------------------------------------
# 5. Controls
# ---------------------------------------------------------------------------
def _fixture_claim(state: str, **extra: Any) -> dict[str, Any]:
    block = {"state": state}
    block.update(extra)
    return {
        "claims": [
            {
                "id": "B8-FIXTURE-001",
                "authority": {"kind": "repository-policy"},
                "transparency": block,
            }
        ]
    }


def _write(path: Path, value: Any) -> Path:
    path.write_text(json.dumps(value, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path


def controls_record() -> dict[str, Any]:
    """One control per refusal code plus the positive and usage codes.

    Every control builds its input in a temporary directory or mutates an
    in-memory record; none mutates a tracked file.
    """
    import tempfile

    rows: list[dict[str, Any]] = []

    def record(ident: str, expected: str, observed: str, detail: str) -> None:
        rows.append({
            "controlOnly": True,
            "id": ident,
            "expectedCode": expected,
            "observedCode": observed,
            "detail": detail,
        })

    with tempfile.TemporaryDirectory(prefix="b8-controls-") as temporary:
        tmp = Path(temporary)

        absent = check_registry(tmp / "absent-registry.json")
        record("profile-absent", "CE_REFUSED_PROFILE_ABSENT",
               absent[0].code if absent else CODE_OK,
               "the B0 registry path does not exist")

        stale = load_json(REGISTRY_PATH)
        stale["components"][0]["version"] = "v9.9.9"
        stale_path = _write(tmp / "stale-registry.json", stale)
        stale_findings = check_registry(stale_path)
        record("registry-stale", "CE_REFUSED_REGISTRY_STALE",
               stale_findings[0].code if stale_findings else CODE_OK,
               "the newest release version is replaced by v9.9.9, which no clause names")

        digest = "a" * 64
        published_claim = _write(tmp / "claims-published.json", _fixture_claim(
            "PUBLISHED",
            profile="public-good-rekor-v2",
            statementDigest=digest,
            bundleDigest=digest,
            publishedAt="2026-11-24T00:00:00Z",
        ))
        published_findings, _ = check_claims(published_claim)
        codes = [finding.code for finding in published_findings]
        record("publication-claim", "CE_REFUSED_PUBLICATION_CLAIM",
               "CE_REFUSED_PUBLICATION_CLAIM" if "CE_REFUSED_PUBLICATION_CLAIM" in codes else CODE_OK,
               "a claim asserts PUBLISHED while B4 records published=0")

        admitted_claim = _write(tmp / "claims-admitted.json", _fixture_claim(
            "ADMITTED",
            profile="public-good-rekor-v2",
            statementDigest=digest,
            bundleDigest=digest,
        ))
        admitted_findings, _ = check_claims(admitted_claim)
        codes = [finding.code for finding in admitted_findings]
        record("profile-not-admitted", "CE_REFUSED_PROFILE_NOT_ADMITTED",
               "CE_REFUSED_PROFILE_NOT_ADMITTED" if "CE_REFUSED_PROFILE_NOT_ADMITTED" in codes else CODE_OK,
               "a claim asserts ADMITTED while B4 records admittedService=false")

        schema_claim = _write(tmp / "claims-schema-field.json",
                              _fixture_claim("MAYBE", note="a free-text assertion"))
        schema_findings, _ = check_claims(schema_claim)
        codes = [finding.code for finding in schema_findings]
        record("schema-field-absent", "CE_REFUSED_SCHEMA_FIELD_ABSENT",
               "CE_REFUSED_SCHEMA_FIELD_ABSENT" if "CE_REFUSED_SCHEMA_FIELD_ABSENT" in codes else CODE_OK,
               "a claim uses state MAYBE and an undefined note field")

        unbound_claim = _write(tmp / "claims-unbound.json",
                               _fixture_claim("ADMITTED", profile="public-good-rekor-v2"))
        unbound_findings, _ = check_claims(unbound_claim)
        codes = [finding.code for finding in unbound_findings]
        record("unbound-claim", "CE_REFUSED_UNBOUND_CLAIM",
               "CE_REFUSED_UNBOUND_CLAIM" if "CE_REFUSED_UNBOUND_CLAIM" in codes else CODE_OK,
               "an ADMITTED claim names no statement or bundle digest")

        nonclaims_findings = check_nonclaims(tmp / "absent-non-claims.md")
        record("nonclaims-absent", "CE_REFUSED_NONCLAIMS_ABSENT",
               nonclaims_findings[0].code if nonclaims_findings else CODE_OK,
               "the public non-claims document path does not exist")

        gate_text = _text(GATE_PATH) or ""
        record_value = {
            "refusalCodes": list(REFUSAL_CODES),
        }
        regression = check_enforcement(
            gate_text=gate_text.replace("def check_transparency(", "def transparency_removed("),
            enforcement_record=record_value,
            document_text=_text(DOCUMENT_PATH) or "",
        )
        record("enforcement-regression", "CE_REFUSED_ENFORCEMENT_REGRESSION",
               regression[0].code if regression else CODE_OK,
               "the check_transparency definition is renamed, so item 10 has disappeared")

        honest_claim = _write(tmp / "claims-not-admitted.json",
                              _fixture_claim("NOT_ADMITTED", profile="public-good-rekor-v2"))
        honest_findings, honest_population = check_claims(honest_claim)
        record("not-admitted-honest", CODE_OK,
               "CE_REFUSED_PUBLICATION_CLAIM" if honest_findings else CODE_OK,
               "a claim honestly records NOT_ADMITTED and adds no refusal "
               f"({honest_population['claimsWithTransparency']} claim carries the field)")

    usage = None
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        usage = main(["check", "--not-a-flag"])
    record("usage", CODE_USAGE, CODE_USAGE if usage == EXIT_USAGE else CODE_OK,
           "--not-a-flag is a usage error and exits 2 with CE_REFUSED_USAGE")

    observed = sorted({row["observedCode"] for row in rows})
    return {
        "schema": SCHEMA_CONTROLS,
        "code": CODE_OK,
        "controls": rows,
        "codesCovered": observed,
        "coversEveryCode": set(observed) >= set(REFUSAL_CODES) | {CODE_OK},
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _payload(result: CheckResult) -> dict[str, Any]:
    return {
        "schema": SCHEMA_ENFORCEMENT,
        "code": result.findings[0].code if result.findings else CODE_OK,
        "verdict": "REFUSED" if result.refused() else "PASS",
        "refusals": [
            {"code": finding.code, "artefact": finding.artefact, "detail": finding.detail}
            for finding in result.findings
        ],
        "population": result.population,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check that the transparency policy is still enforced."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    check_parser = subparsers.add_parser("check", help="run every enforcement check")
    check_parser.add_argument("--registry", default=str(REGISTRY_PATH))
    check_parser.add_argument("--publication", default=str(PUBLICATION_PATH))
    check_parser.add_argument("--claims", default=str(CLAIMS_PATH))
    check_parser.add_argument("--schema", default=str(SCHEMA_PATH))
    check_parser.add_argument("--nonclaims", default=str(NONCLAIMS_PATH))
    check_parser.add_argument("--gate", default=str(GATE_PATH))
    check_parser.add_argument("--enforcement", default=str(ENFORCEMENT_PATH))
    check_parser.add_argument("--document", default=str(DOCUMENT_PATH))
    check_parser.add_argument("--addendum", default=str(ADDENDUM_PATH))
    check_parser.add_argument("--json", action="store_true", help="emit one JSON document")
    controls_parser = subparsers.add_parser("controls", help="run the B8 controls")
    controls_parser.add_argument("--json", action="store_true", help="emit one JSON document")

    try:
        arguments = parser.parse_args(sys.argv[1:] if argv is None else list(argv))
    except SystemExit as exc:
        if exc.code == 0:
            return EXIT_OK
        print(f"code={CODE_USAGE} continuous_enforcement: invalid command line")
        return EXIT_USAGE

    if arguments.command == "controls":
        record = controls_record()
        if arguments.json:
            print(pretty(record).decode("utf-8"), end="")
        else:
            for row in record["controls"]:
                print(f"ce: control {row['id']} expected={row['expectedCode']} "
                      f"observed={row['observedCode']}")
            print(f"code={record['code']} controls={len(record['controls'])} "
                  f"codes={len(record['codesCovered'])} "
                  f"coversEveryCode={str(record['coversEveryCode']).lower()}")
        return EXIT_OK if record["coversEveryCode"] else EXIT_REFUSED

    result = check(
        registry=arguments.registry,
        publication=arguments.publication,
        claims=arguments.claims,
        schema=arguments.schema,
        nonclaims=arguments.nonclaims,
        gate=arguments.gate,
        enforcement=arguments.enforcement,
        document=arguments.document,
        addendum=arguments.addendum,
    )
    if arguments.json:
        print(pretty(_payload(result)).decode("utf-8"), end="")
    else:
        for finding in result.findings:
            print(finding.line())
        population = result.population
        print(
            f"code={CODE_OK if not result.findings else result.findings[0].code} "
            f"claims={population.get('claimCount', 0)} "
            f"withTransparency={population.get('claimsWithTransparency', 0)} "
            f"refusals={len(result.findings)}"
        )
    return EXIT_REFUSED if result.refused() else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
