#!/usr/bin/env python3
"""protocol_audit.py -- what is pinned, what is installed, and what is refused (B0).

Why this tool exists
--------------------
Addendum B pins a stack.  It pins ``rekor-tiles`` tags, three C2SP
specifications, an entry-representation change, a post-quantum recommendation and
one recorded service-configuration finding.  A pinned stack is *not* a running
transparency service.  The inference this item exists to refuse is:

    "the addendum names v2.4.2, therefore this tree has a Rekor v2 log"

Nothing in this tree installs, executes or contacts a Rekor instance.  The
registry records each pinned component, the clause that pins it, the artefact
digest (or an explicit ``null`` with the reason there is no recorded digest), the
features the clause establishes, and four separate presence facts: ``pinned``,
``installed``, ``executable`` and the check that establishes them.  The
service-configuration record states what the tree *does* have (DSSE/PAE, in-toto
statements, the offline bundle validator, the key-lifecycle evaluator, the strict
reader, independent verification) and what that support is not.

The rules
---------
1. **A version is sourced or it is refused.**  Every ``version``,
   ``releaseDate``, ``upstreamCommit`` and ``digest`` must appear verbatim in the
   cited clause of ``docs/ETP-ADDENDUM-B.md``.  A version the clause does not
   carry is ``PA_REFUSED_UNSOURCED_VERSION``; a digest that is not in the clause
   is ``PA_REFUSED_INVENTED_DIGEST``.  A ``null`` digest is admitted only with a
   written reason, and a ``null`` version only for a recorded finding.
2. **An installed component is checked.**  ``installed: true`` or
   ``executable: true`` without a ``checkedBy`` that resolves to a recorded
   command whose result is a path is ``PA_REFUSED_UNCHECKED_PRESENCE``.
3. **A feature is sourced.**  Every supported and unsupported feature names a
   permitted clause; a missing clause is ``PA_REFUSED_UNSOURCED_FEATURE``, an
   unknown one is ``PA_REFUSED_CLAUSE_UNKNOWN``.
4. **No service is claimed.**  An entry that claims a reachable service, or a
   record that says a service is reachable, is ``PA_REFUSED_SERVICE_CLAIM``
   unless a check establishes an executable service.  None exists here.
5. **A witness is not asserted.**  A witness class marked available, or a witness
   population above zero, is ``PA_REFUSED_WITNESS_CLAIM`` unless a recorded check
   establishes it.  No witness exists at any ``n``.
6. **A member is not omitted.**  A required component, client-support module,
   witness class or trust assumption that is absent is
   ``PA_REFUSED_MISSING_MEMBER``.
7. **A claim carries its evidence.**  A ``claimsMade`` entry with
   ``established: true`` must name an evidence path that exists.  It may not be
   a service claim: no transparency service is reachable from this tree.
8. **An observation is re-read.**  A declared observed count is resolved against
   the record it names; a count that no longer matches is
   ``PA_REFUSED_OBSERVATION_DRIFT``.  The point is that the service
   configuration is measured from the tree, not typed.

What this tool does not do
--------------------------
It does not fetch anything.  It has no network path: every fact is read from a
tracked file, and presence is decided by ``command -v`` (through
``shutil.which``) and by tracked-path search.  It does not install, start or
configure a log, a witness, a timestamp authority or a client.  It does not
verify a signature, a checkpoint, an inclusion proof or a timestamp; those are
B1-B6 and are ``NOT_RUN``.  A registry entry passing this tool is a sourced
*record*, not a deployment.

Usage
-----
    python3 forensics/tools/protocol_audit.py registry [--registry PATH]
    python3 forensics/tools/protocol_audit.py audit    [--registry PATH] [--service PATH]
    python3 forensics/tools/protocol_audit.py claims   [--service PATH]

Exit status: 0 when every check passes, 1 when a code fires, 2 on a usage error.
The code is always printed (``codes=NONE`` for a clean run).

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Iterable

TOOLS = Path(__file__).resolve().parent
REPO_ROOT = TOOLS.parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import harden  # noqa: E402

MODEL_ID = "b0/v1"
REGISTRY_SCHEMA = "openssl-rs/b0/registry/1"
SERVICE_SCHEMA = "openssl-rs/b0/service-configuration/1"

ADDENDUM = "docs/ETP-ADDENDUM-B.md"
FREEZE = "evidence/a17/FREEZE-forward.json"
DEFAULT_REGISTRY = REPO_ROOT / "evidence/b0/REGISTRY.json"
DEFAULT_SERVICE = REPO_ROOT / "evidence/b0/SERVICE-CONFIGURATION.json"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

# ---------------------------------------------------------------------------
# Refusals.  A code is stable: this document, the normative document, the
# receipt and the tests cite it verbatim.
# ---------------------------------------------------------------------------
PA_REFUSED_UNSOURCED_VERSION = "PA_REFUSED_UNSOURCED_VERSION"
PA_REFUSED_INVENTED_DIGEST = "PA_REFUSED_INVENTED_DIGEST"
PA_REFUSED_UNCHECKED_PRESENCE = "PA_REFUSED_UNCHECKED_PRESENCE"
PA_REFUSED_UNSOURCED_FEATURE = "PA_REFUSED_UNSOURCED_FEATURE"
PA_REFUSED_SERVICE_CLAIM = "PA_REFUSED_SERVICE_CLAIM"
PA_REFUSED_MISSING_MEMBER = "PA_REFUSED_MISSING_MEMBER"
PA_REFUSED_CLAUSE_UNKNOWN = "PA_REFUSED_CLAUSE_UNKNOWN"
PA_REFUSED_WITNESS_CLAIM = "PA_REFUSED_WITNESS_CLAIM"
PA_REFUSED_ENTRY_INCOMPLETE = "PA_REFUSED_ENTRY_INCOMPLETE"
PA_REFUSED_DIGEST_UNSTATED = "PA_REFUSED_DIGEST_UNSTATED"
PA_REFUSED_UNEVIDENCED_CLAIM = "PA_REFUSED_UNEVIDENCED_CLAIM"
PA_REFUSED_OBSERVATION_DRIFT = "PA_REFUSED_OBSERVATION_DRIFT"
PA_REFUSED_USAGE = "PA_REFUSED_USAGE"

REFUSAL_CODES = (
    PA_REFUSED_UNSOURCED_VERSION,
    PA_REFUSED_INVENTED_DIGEST,
    PA_REFUSED_UNCHECKED_PRESENCE,
    PA_REFUSED_UNSOURCED_FEATURE,
    PA_REFUSED_SERVICE_CLAIM,
    PA_REFUSED_MISSING_MEMBER,
    PA_REFUSED_CLAUSE_UNKNOWN,
    PA_REFUSED_WITNESS_CLAIM,
    PA_REFUSED_ENTRY_INCOMPLETE,
    PA_REFUSED_DIGEST_UNSTATED,
    PA_REFUSED_UNEVIDENCED_CLAIM,
    PA_REFUSED_OBSERVATION_DRIFT,
)
INVOCATION_CODES = (PA_REFUSED_USAGE,)

REFUSALS: dict[str, dict[str, str]] = {
    PA_REFUSED_UNSOURCED_VERSION: {
        "condition": (
            "a version, release date or upstream commit is absent with no reason, "
            "or does not appear verbatim in the cited clause"
        ),
        "prevents": "that a version is remembered, inferred or invented rather than read from the record that pins it",
    },
    PA_REFUSED_INVENTED_DIGEST: {
        "condition": (
            "a digest is present but is not `sha256:` plus 64 lowercase hex "
            "characters, or does not appear verbatim in the cited clause"
        ),
        "prevents": "that an unrecorded digest is presented as the identity of an artefact",
    },
    PA_REFUSED_UNCHECKED_PRESENCE: {
        "condition": (
            "installed or executable is true and checkedBy is absent, names no "
            "recorded check, or resolves to a check whose result is absent"
        ),
        "prevents": "that an installed or executable component is asserted without a check that establishes it",
    },
    PA_REFUSED_UNSOURCED_FEATURE: {
        "condition": "a supported or unsupported feature has no clause, or a named support has no implementation",
        "prevents": "that a capability is claimed without a record that admits it",
    },
    PA_REFUSED_SERVICE_CLAIM: {
        "condition": (
            "an entry or record claims a reachable transparency service, a "
            "service is reachable at top level, a tension is resolved, or a trust "
            "assumption is marked met"
        ),
        "prevents": "that a pinned version is read as a working service, or that an unmet trust path is read as met",
    },
    PA_REFUSED_MISSING_MEMBER: {
        "condition": "a required component, client-support member, witness class, trust assumption or freeze member is absent",
        "prevents": "that an omission reads as completeness",
    },
    PA_REFUSED_CLAUSE_UNKNOWN: {
        "condition": "a source clause is not one this item may cite, or has no extractable text",
        "prevents": "that an unread or mistyped clause is accepted as the source of an entry",
    },
    PA_REFUSED_WITNESS_CLAIM: {
        "condition": "a witness class is available, or a witness population is above zero, without a recorded check",
        "prevents": "that a witness is asserted at some n when none has been admitted",
    },
    PA_REFUSED_ENTRY_INCOMPLETE: {
        "condition": "an entry lacks a required field, has the wrong type, or carries an unknown role, kind or state",
        "prevents": "that a partial entry is read as a complete registry or service record",
    },
    PA_REFUSED_DIGEST_UNSTATED: {
        "condition": "a digest is null and no reason is recorded",
        "prevents": "that an omitted digest is indistinguishable from one that was never looked for",
    },
    PA_REFUSED_UNEVIDENCED_CLAIM: {
        "condition": "a claimsMade entry is established but names no existing evidence path",
        "prevents": "that an established claim carries no record a reader can open",
    },
    PA_REFUSED_OBSERVATION_DRIFT: {
        "condition": "a declared observed value no longer equals the value at the record and pointer it names",
        "prevents": "that a typed count is read as a measurement of this tree",
    },
}

# Components this item must cover.  A missing id is `PA_REFUSED_MISSING_MEMBER`.
REQUIRED_COMPONENTS = (
    "rekor-tiles-v2.4.2",
    "rekor-tiles-v2.4.1",
    "rekor-tiles-v2.4.0",
    "rekor-tiles-v2.3.0",
    "rekor-tiles-v2.2.1",
    "rekor-tiles-v2.2.0",
    "rekor-tiles-v2.1.0",
    "rekor-tiles-v2.0.1",
    "rekor-tiles-v2.0.0",
    "c2sp-tlog-tiles-v1.0.0",
    "c2sp-tlog-checkpoint-v1.1.0",
    "c2sp-tlog-cosignature-v1.1.0",
    "dsse-entry-type-change-v2.3.0",
    "ml-dsa-44",
    "sigstore-signing-config-v1-endpoint",
)

# The clauses this item may cite.  A clause outside this set is refused even if
# a similarly named heading exists.
ALLOWED_CLAUSES = frozenset(
    {"B.3.1", "B.3.2", "B.3.3", "B.5", "B.10", "B.11", "B.26", "B.30"}
)

ROLES = frozenset(
    {"log", "client", "checkpoint", "cosignature", "timestamp", "bundle", "key-lifecycle"}
)
KINDS = frozenset({"release", "specification", "mechanism", "change", "finding"})
STATES = frozenset({"IMPLEMENTED", "IMPLEMENTED_WITH_LIMITS", "NOT_PRESENT"})

REQUIRED_CLIENT_SUPPORT = ("A9", "A10", "A11", "A12", "A16", "A18")
REQUIRED_WITNESSES = (
    "log-key",
    "checkpoint-cosignature",
    "witness-set",
    "rfc3161-tsa",
    "public-rekor-endpoint",
)
REQUIRED_TRUST = (
    "TA-B1",
    "TA-B2",
    "TA-B3",
    "TA-B4",
    "TA-B5",
    "TA-B6",
)
REQUIRED_TENSIONS = ("T1", "T2", "T3")
REQUIRED_CLAIM_KINDS = frozenset({"service", "implementation", "record"})

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_HEADING = re.compile(r"^(#{1,4})\s+(B\.\d+(?:\.\d+)?)\.?(?:\s|$)")


class AuditRefusal(Exception):
    """A record could not be read or structurally admitted."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def read_text(path: Path) -> str:
    if not path.exists():
        raise AuditRefusal(PA_REFUSED_MISSING_MEMBER, f"{path} is absent")
    return path.read_text(encoding="utf-8")


def read_json(repo: Path, path: Path) -> Any:
    if not path.exists():
        raise AuditRefusal(PA_REFUSED_MISSING_MEMBER, f"{path} is absent")
    try:
        return harden.loads(path.read_bytes())
    except harden.Refusal as exc:
        raise AuditRefusal(PA_REFUSED_ENTRY_INCOMPLETE, f"{path}: {exc}") from exc


def clause_text(document: str, clause: str) -> str | None:
    """Return the text of a numbered clause, or None.

    The slice ends at the next heading of the same or a higher level, so a
    ``###`` subclause ends at the next ``##`` and a ``##`` clause at the next
    ``##``.
    """
    lines = document.splitlines()
    start = -1
    level = 0
    for index, line in enumerate(lines):
        match = _HEADING.match(line)
        if match and match.group(2) == clause:
            start = index
            level = len(match.group(1))
            break
    if start < 0:
        return None
    body: list[str] = []
    for line in lines[start + 1 :]:
        match = _HEADING.match(line)
        if match and len(match.group(1)) <= level:
            break
        body.append(line)
    text = "\n".join(body).strip()
    return text or None


def resolve_pointer(document: Any, pointer: str) -> Any:
    """Resolve a JSON pointer without a leading slash.  Raises AuditRefusal."""
    node = document
    for part in pointer.split("/"):
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            raise AuditRefusal(
                PA_REFUSED_OBSERVATION_DRIFT,
                f"pointer {pointer!r} does not resolve",
            )
    return node


def _resolved(result: Any) -> bool:
    """A check result establishes presence only when it is a path or record."""
    return (
        isinstance(result, str)
        and result.strip() != ""
        and result.strip().lower() not in {"absent", "not found", "none"}
        and (result.startswith("/") or result.startswith("record:"))
    )


def _non_empty(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _finding(code: str, detail: str) -> tuple[str, str]:
    return (code, detail)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def check_registry(
    registry: Any,
    repo: Path,
    document: str | None = None,
    *,
    live: bool = True,
) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if document is None:
        document = read_text(repo / ADDENDUM)
    if not isinstance(registry, dict):
        return [_finding(PA_REFUSED_ENTRY_INCOMPLETE, "the registry is not a JSON object")]
    if registry.get("schema") != REGISTRY_SCHEMA:
        findings.append(
            _finding(PA_REFUSED_ENTRY_INCOMPLETE, "the registry schema is not " + REGISTRY_SCHEMA)
        )
    if registry.get("item") != "B0":
        findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, "the registry item is not B0"))
    if registry.get("model") != MODEL_ID:
        findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, "the registry model is not " + MODEL_ID))
    if registry.get("serviceReachable") is True:
        findings.append(
            _finding(
                PA_REFUSED_SERVICE_CLAIM,
                "the registry declares serviceReachable=true; no executable transparency service exists here",
            )
        )

    checks = registry.get("presenceCheck")
    checks_by_id: dict[str, dict[str, Any]] = {}
    if not isinstance(checks, dict) or not isinstance(checks.get("checks"), list):
        findings.append(
            _finding(PA_REFUSED_ENTRY_INCOMPLETE, "presenceCheck.checks is absent or not a list")
        )
    else:
        for row in checks["checks"]:
            if not isinstance(row, dict) or not _non_empty(row.get("id")):
                findings.append(
                    _finding(PA_REFUSED_ENTRY_INCOMPLETE, "a presence check has no id")
                )
                continue
            if not _non_empty(row.get("command")) or not isinstance(row.get("result"), str):
                findings.append(
                    _finding(
                        PA_REFUSED_ENTRY_INCOMPLETE,
                        f"presence check {row['id']} has no command or result",
                    )
                )
            checks_by_id[row["id"]] = row

    components = registry.get("components")
    if not isinstance(components, list) or not components:
        return findings + [
            _finding(PA_REFUSED_MISSING_MEMBER, "the registry has no components")
        ]

    by_id: dict[str, dict[str, Any]] = {}
    for component in components:
        if isinstance(component, dict) and _non_empty(component.get("id")):
            if component["id"] in by_id:
                findings.append(
                    _finding(
                        PA_REFUSED_ENTRY_INCOMPLETE,
                        f"the component id {component['id']} is recorded twice",
                    )
                )
            by_id[component["id"]] = component

    for required in REQUIRED_COMPONENTS:
        if required not in by_id:
            findings.append(
                _finding(PA_REFUSED_MISSING_MEMBER, f"the required component {required} is absent")
            )

    for component in components:
        findings.extend(
            _check_component(component, document, checks_by_id, repo, live=live)
        )

    summary = registry.get("summary")
    if not isinstance(summary, dict):
        findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, "the registry has no summary"))
    else:
        pinned = sum(1 for c in by_id.values() if (c.get("presence") or {}).get("pinned") is True)
        installed = sum(
            1 for c in by_id.values() if (c.get("presence") or {}).get("installed") is True
        )
        executable = sum(
            1 for c in by_id.values() if (c.get("presence") or {}).get("executable") is True
        )
        for key, derived in (
            ("components", len(by_id)),
            ("pinned", pinned),
            ("installed", installed),
            ("executable", executable),
        ):
            if summary.get(key) != derived:
                findings.append(
                    _finding(
                        PA_REFUSED_OBSERVATION_DRIFT,
                        f"summary.{key} says {summary.get(key)!r}, the entries say {derived}",
                    )
                )
        if summary.get("servicesReachable") not in (0, None):
            findings.append(
                _finding(
                    PA_REFUSED_SERVICE_CLAIM,
                    f"summary.servicesReachable says {summary.get('servicesReachable')!r}",
                )
            )
    return findings


def _check_component(
    component: Any,
    document: str,
    checks_by_id: dict[str, dict[str, Any]],
    repo: Path,
    *,
    live: bool,
) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if not isinstance(component, dict):
        return [_finding(PA_REFUSED_ENTRY_INCOMPLETE, "a component is not an object")]
    cid = component.get("id") if _non_empty(component.get("id")) else "<no id>"

    if not _non_empty(component.get("name")):
        findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{cid}: no name"))
    if component.get("kind") not in KINDS:
        findings.append(
            _finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{cid}: kind {component.get('kind')!r} is unknown")
        )
    roles = component.get("role")
    if (
        not isinstance(roles, list)
        or not roles
        or any(not isinstance(r, str) or r not in ROLES for r in roles)
    ):
        findings.append(
            _finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{cid}: role is absent or not a known role")
        )

    source = component.get("source")
    if not isinstance(source, dict):
        findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{cid}: no source clause"))
        return findings
    clause = source.get("clause")
    text: str | None = None
    if clause not in ALLOWED_CLAUSES:
        findings.append(
            _finding(PA_REFUSED_CLAUSE_UNKNOWN, f"{cid}: clause {clause!r} is not one this item may cite")
        )
    else:
        text = clause_text(document, clause)
        if text is None:
            findings.append(
                _finding(PA_REFUSED_CLAUSE_UNKNOWN, f"{cid}: clause {clause} has no text")
            )
    if source.get("path") != ADDENDUM:
        findings.append(
            _finding(
                PA_REFUSED_CLAUSE_UNKNOWN,
                f"{cid}: source path {source.get('path')!r} is not {ADDENDUM}",
            )
        )

    findings.extend(_check_sourced(cid, component, text))
    findings.extend(_check_features(cid, component, document))
    findings.extend(_check_presence(cid, component, checks_by_id, repo, live=live))
    return findings


def _check_sourced(cid: str, component: dict[str, Any], text: str | None) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    version = component.get("version")
    if version is None:
        if not _non_empty(component.get("versionNullReason")):
            findings.append(
                _finding(
                    PA_REFUSED_UNSOURCED_VERSION,
                    f"{cid}: version is null and versionNullReason is absent",
                )
            )
    elif not _non_empty(version) or (text is not None and version not in text):
        findings.append(
            _finding(
                PA_REFUSED_UNSOURCED_VERSION,
                f"{cid}: version {version!r} does not appear in the cited clause",
            )
        )

    for field, reason_field in (
        ("releaseDate", "releaseDateNullReason"),
        ("upstreamCommit", "upstreamCommitNullReason"),
        ("observedDate", "observedDateNullReason"),
    ):
        value = component.get(field)
        if value is None:
            if field in component or component.get(reason_field):
                if not _non_empty(component.get(reason_field)):
                    findings.append(
                        _finding(
                            PA_REFUSED_UNSOURCED_VERSION,
                            f"{cid}: {field} is null and {reason_field} is absent",
                        )
                    )
            continue
        if not _non_empty(value) or (text is not None and value not in text):
            findings.append(
                _finding(
                    PA_REFUSED_UNSOURCED_VERSION,
                    f"{cid}: {field} {value!r} does not appear in the cited clause",
                )
            )

    artefact = component.get("artefact")
    if not isinstance(artefact, dict):
        findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{cid}: no artefact object"))
        return findings
    if not _non_empty(artefact.get("kind")) or not _non_empty(artefact.get("name")):
        findings.append(
            _finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{cid}: the artefact has no kind or name")
        )
    digest = artefact.get("digest")
    if digest is None:
        if not _non_empty(artefact.get("digestNullReason")):
            findings.append(
                _finding(
                    PA_REFUSED_DIGEST_UNSTATED,
                    f"{cid}: the digest is null and digestNullReason is absent",
                )
            )
    elif not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        findings.append(
            _finding(
                PA_REFUSED_INVENTED_DIGEST,
                f"{cid}: digest {digest!r} is not sha256: plus 64 lowercase hex characters",
            )
        )
    elif text is not None and digest not in text:
        findings.append(
            _finding(
                PA_REFUSED_INVENTED_DIGEST,
                f"{cid}: digest {digest!r} does not appear in the cited clause",
            )
        )
    return findings


def _check_features(
    cid: str, component: dict[str, Any], document: str
) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for field in ("supportedFeatures", "unsupportedFeatures"):
        features = component.get(field)
        if not isinstance(features, list):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{cid}: {field} is not a list"))
            continue
        for feature in features:
            if not isinstance(feature, dict) or not _non_empty(feature.get("feature")):
                findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{cid}: a {field} entry has no feature"))
                continue
            clause = feature.get("clause")
            if clause is None:
                findings.append(
                    _finding(
                        PA_REFUSED_UNSOURCED_FEATURE,
                        f"{cid}: feature {feature['feature'][:48]!r} has no clause",
                    )
                )
            elif clause not in ALLOWED_CLAUSES:
                findings.append(
                    _finding(
                        PA_REFUSED_CLAUSE_UNKNOWN,
                        f"{cid}: feature {feature['feature'][:48]!r} cites clause {clause!r}",
                    )
                )
            elif clause_text(document, clause) is None:
                findings.append(
                    _finding(
                        PA_REFUSED_CLAUSE_UNKNOWN,
                        f"{cid}: feature {feature['feature'][:48]!r} cites a clause with no text",
                    )
                )
    return findings


def _check_presence(
    cid: str,
    component: dict[str, Any],
    checks_by_id: dict[str, dict[str, Any]],
    repo: Path,
    *,
    live: bool,
) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    presence = component.get("presence")
    if not isinstance(presence, dict):
        findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{cid}: no presence object"))
        return findings
    for field in ("pinned", "installed", "executable"):
        if not isinstance(presence.get(field), bool):
            findings.append(
                _finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{cid}: presence.{field} is not a boolean")
            )

    checked_by = presence.get("checkedBy")
    positive = presence.get("installed") is True or presence.get("executable") is True
    if positive:
        if not _non_empty(checked_by):
            findings.append(
                _finding(
                    PA_REFUSED_UNCHECKED_PRESENCE,
                    f"{cid}: installed/executable is true and checkedBy is absent",
                )
            )
        elif checked_by not in checks_by_id:
            findings.append(
                _finding(
                    PA_REFUSED_UNCHECKED_PRESENCE,
                    f"{cid}: checkedBy {checked_by!r} names no recorded check",
                )
            )
        elif not _resolved(checks_by_id[checked_by].get("result")):
            findings.append(
                _finding(
                    PA_REFUSED_UNCHECKED_PRESENCE,
                    f"{cid}: checkedBy {checked_by!r} records {checks_by_id[checked_by].get('result')!r}, not a path",
                )
            )
        elif live:
            binary = presence.get("binary")
            if _non_empty(binary) and shutil.which(binary) is None:
                findings.append(
                    _finding(
                        PA_REFUSED_UNCHECKED_PRESENCE,
                        f"{cid}: the record claims {binary!r} is installed and the live check finds it absent",
                    )
                )
    elif _non_empty(checked_by) and checked_by not in checks_by_id:
        findings.append(
            _finding(
                PA_REFUSED_ENTRY_INCOMPLETE,
                f"{cid}: checkedBy {checked_by!r} names no recorded check",
            )
        )

    if component.get("serviceClaim") is True:
        executable = presence.get("executable") is True
        established = (
            executable
            and _non_empty(checked_by)
            and checked_by in checks_by_id
            and _resolved(checks_by_id[checked_by].get("result"))
        )
        if not established:
            findings.append(
                _finding(
                    PA_REFUSED_SERVICE_CLAIM,
                    f"{cid}: serviceClaim is true and no check establishes an executable service",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Service configuration
# ---------------------------------------------------------------------------


def check_service(
    service: Any,
    registry: Any,
    repo: Path,
    document: str | None = None,
) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if document is None:
        document = read_text(repo / ADDENDUM)
    if not isinstance(service, dict):
        return [_finding(PA_REFUSED_ENTRY_INCOMPLETE, "the service record is not a JSON object")]
    if service.get("schema") != SERVICE_SCHEMA:
        findings.append(
            _finding(PA_REFUSED_ENTRY_INCOMPLETE, "the service schema is not " + SERVICE_SCHEMA)
        )
    if service.get("item") != "B0":
        findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, "the service item is not B0"))

    findings.extend(_check_client_support(service.get("clientSupport"), repo))
    findings.extend(_check_service_finding(service.get("serviceConfigurationFinding"), document))
    findings.extend(_check_tensions(service.get("tensions"), document))
    findings.extend(_check_claims(service.get("claimsMade"), repo))
    findings.extend(_check_witnesses(service.get("witnesses"), registry, repo))
    findings.extend(_check_trust(service.get("trustAssumptions"), repo))
    if not isinstance(service.get("nonClaims"), list) or not service["nonClaims"]:
        findings.append(_finding(PA_REFUSED_MISSING_MEMBER, "the service record has no non-claims"))
    return findings


def _check_client_support(support: Any, repo: Path) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if not isinstance(support, list) or not support:
        return [_finding(PA_REFUSED_MISSING_MEMBER, "clientSupport is absent or empty")]
    by_item: dict[str, dict[str, Any]] = {}
    for entry in support:
        if not isinstance(entry, dict) or not _non_empty(entry.get("item")):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, "a clientSupport entry has no item"))
            continue
        by_item[entry["item"]] = entry

    for required in REQUIRED_CLIENT_SUPPORT:
        if required not in by_item:
            findings.append(
                _finding(PA_REFUSED_MISSING_MEMBER, f"the client-support member {required} is absent")
            )

    for item, entry in by_item.items():
        module = entry.get("module")
        doc = entry.get("doc")
        if not _non_empty(module) or not (repo / str(module)).exists():
            findings.append(
                _finding(PA_REFUSED_MISSING_MEMBER, f"{item}: module {module!r} is absent")
            )
            continue
        if not _non_empty(doc) or not (repo / str(doc)).exists():
            findings.append(
                _finding(PA_REFUSED_MISSING_MEMBER, f"{item}: document {doc!r} is absent")
            )
        if entry.get("state") not in STATES:
            findings.append(
                _finding(
                    PA_REFUSED_ENTRY_INCOMPLETE,
                    f"{item}: state {entry.get('state')!r} is not a known state",
                )
            )
        if not _non_empty(entry.get("supports")):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{item}: no supports statement"))
        if not _non_empty(entry.get("refusalPrefix")):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{item}: no refusal prefix"))
        source = (repo / str(module)).read_text(encoding="utf-8")
        codes = entry.get("refusalCodes")
        if not isinstance(codes, list) or not codes:
            findings.append(
                _finding(PA_REFUSED_MISSING_MEMBER, f"{item}: no refusal codes are recorded")
            )
        else:
            for code in codes:
                if not _non_empty(code) or code not in source:
                    findings.append(
                        _finding(
                            PA_REFUSED_UNSOURCED_FEATURE,
                            f"{item}: the code {code!r} is not in {module}",
                        )
                    )
                elif entry.get("refusalPrefix") and not code.startswith(entry["refusalPrefix"]):
                    findings.append(
                        _finding(
                            PA_REFUSED_UNSOURCED_FEATURE,
                            f"{item}: {code!r} does not carry the recorded prefix",
                        )
                    )
        findings.extend(_check_observations(item, entry.get("observed"), repo))
        for limit in entry.get("limits") or []:
            if not _non_empty(limit):
                findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{item}: an empty limit"))
    return findings


def _check_observations(item: str, observed: Any, repo: Path) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if observed is None:
        return findings
    if not isinstance(observed, list) or not observed:
        return [_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{item}: observed is not a non-empty list")]
    for row in observed:
        if (
            not isinstance(row, dict)
            or not _non_empty(row.get("path"))
            or not _non_empty(row.get("pointer"))
            or "equals" not in row
        ):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{item}: a malformed observation"))
            continue
        path = repo / str(row["path"])
        if not path.exists():
            findings.append(
                _finding(PA_REFUSED_MISSING_MEMBER, f"{item}: observation path {row['path']!r} is absent")
            )
            continue
        try:
            record = read_json(repo, path)
            value = resolve_pointer(record, str(row["pointer"]))
        except AuditRefusal as exc:
            findings.append(_finding(exc.code, f"{item}: {exc.detail}"))
            continue
        if value != row["equals"]:
            findings.append(
                _finding(
                    PA_REFUSED_OBSERVATION_DRIFT,
                    f"{item}: {row['path']}#/{row['pointer']} is {value!r}, the record says {row['equals']!r}",
                )
            )
    return findings


def _check_service_finding(finding: Any, document: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if not isinstance(finding, dict):
        return [_finding(PA_REFUSED_MISSING_MEMBER, "serviceConfigurationFinding is absent")]
    clause = finding.get("clause")
    if clause not in ALLOWED_CLAUSES:
        findings.append(
            _finding(PA_REFUSED_CLAUSE_UNKNOWN, f"the finding cites clause {clause!r}")
        )
    text = clause_text(document, clause) if clause in ALLOWED_CLAUSES else None
    if text is None:
        findings.append(_finding(PA_REFUSED_CLAUSE_UNKNOWN, "the finding's clause has no text"))
    if not _non_empty(finding.get("finding")):
        findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, "the finding has no statement"))
    if not _non_empty(finding.get("whatItMeansForB1")):
        findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, "the finding has no consequence for B1"))
    observed = finding.get("observedDate")
    if observed is not None and (text is None or not _non_empty(observed) or observed not in text):
        findings.append(
            _finding(
                PA_REFUSED_UNSOURCED_VERSION,
                f"the finding's observed date {observed!r} is not in its clause",
            )
        )
    if finding.get("state") != "RECORDED":
        findings.append(
            _finding(
                PA_REFUSED_SERVICE_CLAIM,
                f"the finding state is {finding.get('state')!r}; this item does not verify it",
            )
        )
    if finding.get("verifiedHere") is True:
        findings.append(
            _finding(
                PA_REFUSED_SERVICE_CLAIM,
                "the finding declares verifiedHere=true; no service metadata was fetched",
            )
        )
    return findings


def _check_tensions(tensions: Any, document: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if not isinstance(tensions, list):
        return [_finding(PA_REFUSED_MISSING_MEMBER, "tensions is absent")]
    by_id: dict[str, dict[str, Any]] = {}
    for entry in tensions:
        if isinstance(entry, dict) and _non_empty(entry.get("id")):
            by_id[entry["id"]] = entry
    for required in REQUIRED_TENSIONS:
        if required not in by_id:
            findings.append(_finding(PA_REFUSED_MISSING_MEMBER, f"the tension {required} is absent"))
    for tid, entry in by_id.items():
        if entry.get("clause") != "B.3.3":
            findings.append(
                _finding(PA_REFUSED_CLAUSE_UNKNOWN, f"{tid}: a tension must cite B.3.3")
            )
        if not _non_empty(entry.get("tension")):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{tid}: no tension statement"))
        if not _non_empty(entry.get("consequence")):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{tid}: no consequence"))
        if entry.get("resolved") is True:
            findings.append(
                _finding(PA_REFUSED_SERVICE_CLAIM, f"{tid}: a recorded tension is not resolved here")
            )
    if clause_text(document, "B.3.3") is None:
        findings.append(_finding(PA_REFUSED_CLAUSE_UNKNOWN, "B.3.3 has no text"))
    return findings


def _check_claims(claims: Any, repo: Path) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if not isinstance(claims, list) or not claims:
        return [_finding(PA_REFUSED_MISSING_MEMBER, "claimsMade is absent or empty")]
    for claim in claims:
        if not isinstance(claim, dict) or not _non_empty(claim.get("id")):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, "a claim has no id"))
            continue
        cid = claim["id"]
        if not isinstance(claim.get("established"), bool):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{cid}: established is not a boolean"))
            continue
        if claim.get("kind") not in REQUIRED_CLAIM_KINDS:
            findings.append(
                _finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{cid}: kind {claim.get('kind')!r} is unknown")
            )
        if not _non_empty(claim.get("claim")):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{cid}: no claim statement"))
        if claim["established"]:
            if claim.get("kind") == "service":
                findings.append(
                    _finding(
                        PA_REFUSED_SERVICE_CLAIM,
                        f"{cid}: a service claim cannot be established from a pinned record",
                    )
                )
            evidence = claim.get("evidence")
            if not _non_empty(evidence) or not (repo / str(evidence)).exists():
                findings.append(
                    _finding(PA_REFUSED_UNEVIDENCED_CLAIM, f"{cid}: evidence {evidence!r} is absent")
                )
    service_claims = [c for c in claims if isinstance(c, dict) and c.get("kind") == "service"]
    if not service_claims:
        findings.append(
            _finding(PA_REFUSED_MISSING_MEMBER, "no service claim is recorded, so the non-claim is not visible")
        )
    return findings


def _check_witnesses(witnesses: Any, registry: Any, repo: Path) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if not isinstance(witnesses, dict):
        return [_finding(PA_REFUSED_MISSING_MEMBER, "witnesses is absent")]
    classes = witnesses.get("classes")
    if not isinstance(classes, list):
        return [_finding(PA_REFUSED_MISSING_MEMBER, "witnesses.classes is absent")]
    by_id: dict[str, dict[str, Any]] = {}
    for entry in classes:
        if isinstance(entry, dict) and _non_empty(entry.get("id")):
            by_id[entry["id"]] = entry
    for required in REQUIRED_WITNESSES:
        if required not in by_id:
            findings.append(
                _finding(PA_REFUSED_MISSING_MEMBER, f"the witness class {required} is absent")
            )
    checks_by_id: dict[str, Any] = {}
    if isinstance(registry, dict):
        check_block = registry.get("presenceCheck")
        if isinstance(check_block, dict) and isinstance(check_block.get("checks"), list):
            for row in check_block["checks"]:
                if isinstance(row, dict) and _non_empty(row.get("id")):
                    checks_by_id[row["id"]] = row
    for wid, entry in by_id.items():
        if not _non_empty(entry.get("primitive")):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{wid}: no primitive"))
        available = entry.get("available")
        if not isinstance(available, bool):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{wid}: available is not a boolean"))
            continue
        if available:
            checked = entry.get("checkedBy")
            record = entry.get("record")
            established = (
                _non_empty(checked)
                and checked in checks_by_id
                and _resolved(checks_by_id[checked].get("result"))
                and _non_empty(record)
                and (repo / str(record)).exists()
            )
            if not established:
                findings.append(
                    _finding(
                        PA_REFUSED_WITNESS_CLAIM,
                        f"{wid}: available=true with no recorded check and record establishing it",
                    )
                )
        elif not _non_empty(entry.get("checkedBy")):
            findings.append(
                _finding(
                    PA_REFUSED_ENTRY_INCOMPLETE,
                    f"{wid}: unavailable with no check that establishes the absence",
                )
            )
        elif not _non_empty(entry.get("record")) or not (repo / str(entry["record"])).exists():
            findings.append(
                _finding(PA_REFUSED_MISSING_MEMBER, f"{wid}: record {entry.get('record')!r} is absent")
            )
    population = witnesses.get("witnessSet")
    if not isinstance(population, dict):
        findings.append(_finding(PA_REFUSED_MISSING_MEMBER, "witnesses.witnessSet is absent"))
    else:
        for field in ("operators", "keys"):
            if population.get(field) != 0:
                findings.append(
                    _finding(
                        PA_REFUSED_WITNESS_CLAIM,
                        f"witnessSet.{field} is {population.get(field)!r}; no witness exists at any n",
                    )
                )
        if population.get("quorum") is not None:
            findings.append(
                _finding(
                    PA_REFUSED_WITNESS_CLAIM,
                    f"witnessSet.quorum is {population.get('quorum')!r}; a quorum is not admitted",
                )
            )
        if population.get("independent") is not False:
            findings.append(
                _finding(
                    PA_REFUSED_WITNESS_CLAIM,
                    "witnessSet.independent is not false; no independent operator exists",
                )
            )
    return findings


def _check_trust(trust: Any, repo: Path) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if not isinstance(trust, list):
        return [_finding(PA_REFUSED_MISSING_MEMBER, "trustAssumptions is absent")]
    by_id: dict[str, dict[str, Any]] = {}
    for entry in trust:
        if isinstance(entry, dict) and _non_empty(entry.get("id")):
            by_id[entry["id"]] = entry
    for required in REQUIRED_TRUST:
        if required not in by_id:
            findings.append(
                _finding(PA_REFUSED_MISSING_MEMBER, f"the trust assumption {required} is absent")
            )
    for tid, entry in by_id.items():
        if not _non_empty(entry.get("assumption")):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{tid}: no assumption"))
        if not _non_empty(entry.get("wouldEstablish")):
            findings.append(_finding(PA_REFUSED_ENTRY_INCOMPLETE, f"{tid}: no establishing action"))
        record = entry.get("record")
        if not _non_empty(record) or not (repo / str(record)).exists():
            findings.append(
                _finding(PA_REFUSED_MISSING_MEMBER, f"{tid}: record {record!r} is absent")
            )
        if entry.get("state") != "UNMET":
            findings.append(
                _finding(
                    PA_REFUSED_SERVICE_CLAIM,
                    f"{tid}: state is {entry.get('state')!r}; every B1-B6 trust assumption is unmet",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# The whole audit
# ---------------------------------------------------------------------------


def audit_records(
    repo: Path,
    registry_path: Path | None = None,
    service_path: Path | None = None,
    *,
    live: bool = True,
) -> tuple[dict[str, Any], dict[str, Any], list[tuple[str, str]]]:
    registry_path = registry_path or (repo / "evidence/b0/REGISTRY.json")
    service_path = service_path or (repo / "evidence/b0/SERVICE-CONFIGURATION.json")
    registry = read_json(repo, registry_path)
    service = read_json(repo, service_path)
    document = read_text(repo / ADDENDUM)
    findings = check_registry(registry, repo, document, live=live)
    findings += check_service(service, registry, repo, document)
    findings += check_freeze_members(repo)
    return registry, service, findings


def check_freeze_members(repo: Path) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    path = repo / FREEZE
    if not path.exists():
        return [_finding(PA_REFUSED_MISSING_MEMBER, f"{FREEZE} is absent")]
    freeze = read_json(repo, path)
    if not isinstance(freeze, dict) or not isinstance(freeze.get("members"), list):
        return [_finding(PA_REFUSED_MISSING_MEMBER, f"{FREEZE} has no members")]
    declared = {
        m.get("id"): m.get("path")
        for m in freeze["members"]
        if isinstance(m, dict) and _non_empty(m.get("id"))
    }
    for member in ("b0-registry", "b0-service-configuration"):
        if member not in declared:
            findings.append(
                _finding(PA_REFUSED_MISSING_MEMBER, f"the freeze does not declare {member}")
            )
            continue
        if not _non_empty(declared[member]) or not (repo / str(declared[member])).exists():
            findings.append(
                _finding(
                    PA_REFUSED_MISSING_MEMBER,
                    f"the freeze member {member} names {declared[member]!r}, which is absent",
                )
            )
    return findings


def _registry_rows(registry: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for component in registry.get("components") or []:
        if isinstance(component, dict):
            yield component


def _claim_rows(service: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for claim in service.get("claimsMade") or []:
        if isinstance(claim, dict):
            yield claim


def _print_codes(findings: list[tuple[str, str]]) -> None:
    for code, detail in findings:
        print(f"code={code} detail={detail}")
    codes = sorted({code for code, _ in findings})
    print(f"codes={','.join(codes) if codes else 'NONE'}")


def _load_for_cli(repo: Path, args: argparse.Namespace) -> tuple[Any, Any] | None:
    try:
        registry = read_json(repo, Path(args.registry))
        service = read_json(repo, Path(args.service))
    except AuditRefusal as exc:
        print(f"code={exc.code} detail={exc.detail}")
        return None
    return registry, service


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - exercised by a control
        self.print_usage(sys.stderr)
        print(f"code={PA_REFUSED_USAGE} detail={message}", file=sys.stderr)
        raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="what is pinned, what is installed, and what is refused (B0)")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("registry", "print the registry and validate it"),
        ("audit", "validate the registry, the service configuration and the freeze"),
        ("claims", "print every claim, witness and trust assumption"),
    ):
        sub = commands.add_parser(name, help=help_text)
        sub.add_argument("--registry", default=str(DEFAULT_REGISTRY))
        sub.add_argument("--service", default=str(DEFAULT_SERVICE))
        sub.add_argument("--repo-root", default=str(REPO_ROOT))
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    repo = Path(args.repo_root)

    loaded = _load_for_cli(repo, args)
    if loaded is None:
        return EXIT_REFUSED
    registry, service = loaded
    try:
        document = read_text(repo / ADDENDUM)
    except AuditRefusal as exc:
        print(f"code={exc.code} detail={exc.detail}")
        return EXIT_REFUSED

    if args.command == "registry":
        findings = check_registry(registry, repo, document)
        for component in _registry_rows(registry):
            presence = component.get("presence") or {}
            artefact = component.get("artefact") or {}
            print(
                f"component={component.get('id')} version={component.get('version')} "
                f"digest={artefact.get('digest')} source={(component.get('source') or {}).get('clause')} "
                f"pinned={presence.get('pinned')} installed={presence.get('installed')} "
                f"executable={presence.get('executable')}"
            )
        summary = registry.get("summary") or {}
        print(
            f"components={summary.get('components')} pinned={summary.get('pinned')} "
            f"installed={summary.get('installed')} executable={summary.get('executable')} "
            f"servicesReachable={summary.get('servicesReachable')}"
        )
        _print_codes(findings)
        return EXIT_OK if not findings else EXIT_REFUSED

    if args.command == "claims":
        findings = check_service(service, registry, repo, document)
        for claim in _claim_rows(service):
            print(
                f"claim={claim.get('id')} kind={claim.get('kind')} "
                f"established={claim.get('established')} evidence={claim.get('evidence')}"
            )
        witnesses = service.get("witnesses") or {}
        for entry in witnesses.get("classes") or []:
            print(
                f"witness={entry.get('id')} available={entry.get('available')} "
                f"record={entry.get('record')}"
            )
        for entry in service.get("trustAssumptions") or []:
            print(f"trust={entry.get('id')} state={entry.get('state')}")
        population = witnesses.get("witnessSet") or {}
        print(
            f"witnessSet operators={population.get('operators')} keys={population.get('keys')} "
            f"quorum={population.get('quorum')} independent={population.get('independent')}"
        )
        _print_codes(findings)
        return EXIT_OK if not findings else EXIT_REFUSED

    registry_findings = check_registry(registry, repo, document)
    service_findings = check_service(service, registry, repo, document)
    freeze_findings = check_freeze_members(repo)
    findings = registry_findings + service_findings + freeze_findings
    summary = registry.get("summary") or {}
    counts = (service.get("observed") or {})
    print(
        f"registry components={summary.get('components')} pinned={summary.get('pinned')} "
        f"installed={summary.get('installed')} executable={summary.get('executable')}"
    )
    print(
        f"service clientSupport={counts.get('clientSupport')} statements={counts.get('statements')} "
        f"envelopes={counts.get('envelopes')} bundles={counts.get('bundles')} "
        f"repositories={counts.get('repositories')} "
        f"independentlyVerified={counts.get('independentlyVerified')}"
    )
    finding = service.get("serviceConfigurationFinding") or {}
    print(
        f"finding={finding.get('id')} state={finding.get('state')} clause={finding.get('clause')} "
        f"observed={finding.get('observedDate')}"
    )
    print(f"tensions={len(service.get('tensions') or [])}")
    witnesses = (service.get("witnesses") or {}).get("classes") or []
    print(
        f"witnesses={len(witnesses)} "
        f"available={sum(1 for w in witnesses if isinstance(w, dict) and w.get('available') is True)}"
    )
    trust = service.get("trustAssumptions") or []
    print(
        f"trust={len(trust)} unmet={sum(1 for t in trust if isinstance(t, dict) and t.get('state') == 'UNMET')}"
    )
    _print_codes(findings)
    return EXIT_OK if not findings else EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
