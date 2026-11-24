#!/usr/bin/env python3
"""sarif_adapter.py -- deterministic SARIF 2.1.0 projection of native evidence records.

The profile this tool emits against is `docs/SARIF-PROFILE.md`. The tool does not
analyse code, does not decide whether a finding is true, and does not repair
anything: it projects the fields of a native record into a SARIF log, binding every
result to the candidate identity and the artefact digest the native finding was
bound to, and refusing rather than emitting a result it cannot attribute.

What it refuses
---------------
A missing native record, a missing candidate identity, a missing artefact digest
for a binary finding, a record whose own declared totals disagree with its rows, an
unknown native shape, and a document that fails the structural validator. A refusal
writes no output file and exits 2 with a stable `SARIF_REFUSED_*` code.

What it does not do
-------------------
It does not preserve the raw native output (A2), does not admit a population as
complete (A5), does not govern suppression (A6), and does not sign, attest or
timestamp anything (A9-A21). `docs/SARIF-PROFILE.md` §2 names where those attach.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import finding_identity

SARIF_VERSION = "2.1.0"
SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)
ADAPTER_NAME = "openssl-rs-sarif-adapter"
ADAPTER_VERSION = "1.0.0"

R_SOURCE_UNREADABLE = "SARIF_REFUSED_SOURCE_UNREADABLE"
R_MISSING_CANDIDATE = "SARIF_REFUSED_MISSING_CANDIDATE_IDENTITY"
R_MISSING_ARTIFACT_DIGEST = "SARIF_REFUSED_MISSING_ARTIFACT_DIGEST"
R_POPULATION = "SARIF_REFUSED_POPULATION_MISMATCH"
R_SHAPE = "SARIF_REFUSED_UNSUPPORTED_NATIVE_SHAPE"
R_EMISSION = "SARIF_REFUSED_EMISSION_INVALID"


class Refusal(Exception):
    """A refusal to emit. Carries the stable profile code."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# The closed rule registry (profile §5). A rule id is a class of finding.
# --------------------------------------------------------------------------

RULES = (
    {
        "id": "A1-SECRET-LEAKAGE-REPORTED",
        "name": "SecretLeakageReported",
        "short": "A recorded instrument result for a secret-bearing item is a leak.",
        "full": (
            "The secret register records an instrument result of LEAKAGE_REPORTED "
            "for this item. This is the register's recorded result, not a "
            "re-execution and not a severity estimate."
        ),
        "level": "error",
    },
    {
        "id": "A1-SECRET-CLEANSING-UNMET",
        "name": "SecretCleansingUnmet",
        "short": "A required cleansing obligation is recorded as not met.",
        "full": (
            "The entry requires cleansing of the recorded extent and the register "
            "records met=false. The register states the mechanism; it does not "
            "establish that the mechanism is unreachable or that the secret leaks."
        ),
        "level": "error",
    },
    {
        "id": "A1-SECRET-CONTROL-NO-EVIDENCE",
        "name": "SecretControlNoEvidence",
        "short": "A secret-dependent control has no recorded evidence.",
        "full": (
            "The register lists this item in "
            "secret_dependent_control_without_evidence. The entry's own non-claim "
            "states that NONE means no evidence was found in the admitted surfaces "
            "and is not evidence of absence."
        ),
        "level": "warning",
    },
    {
        "id": "A1-SECRET-CLASSIFICATION-RECORDED",
        "name": "SecretClassificationRecorded",
        "short": "The register records this item as public data or a declassification boundary.",
        "full": (
            "The entry is a classification record, not a defect. It is emitted so "
            "that the classification population is reconstructable from the SARIF."
        ),
        "level": "note",
    },
    {
        "id": "A1-SECRET-EVIDENCE-CONTRACT-ONLY",
        "name": "SecretEvidenceContractOnly",
        "short": "A secret-bearing entry's only recorded evidence is a source contract.",
        "full": (
            "The register records a source contract or a design note, not a test, "
            "timing or taint result. A class is not evidence."
        ),
        "level": "note",
    },
    {
        "id": "A1-TIMING-LEAKAGE-DETECTED",
        "name": "TimingLeakageDetected",
        "short": "A BN primitive has a recorded timing or taint leak verdict.",
        "full": (
            "The timing record reports ctgrind error and context counts and a "
            "dudect verdict for the primitive. A dudect t-statistic is not an "
            "attack and not a remote-timing claim; the record states its geometry."
        ),
        "level": "error",
    },
    {
        "id": "A1-TIMING-NOT-RUN",
        "name": "TimingNotRun",
        "short": "An analysis named by the timing record was not run.",
        "full": (
            "The record's not_run list names an analysis that was not executed. "
            "Not run is not a pass."
        ),
        "level": "warning",
    },
    {
        "id": "A1-UNSAFE-OBLIGATION-UNESTABLISHED",
        "name": "UnsafeObligationUnestablished",
        "short": "A caller obligation is recorded as not established.",
        "full": (
            "The unsafe-site inventory records CALLER_OBLIGATION_UNESTABLISHED. "
            "A lexical classification is not a proof; this row records the gap."
        ),
        "level": "error",
    },
    {
        "id": "A1-UNSAFE-OBLIGATION-VACUOUS",
        "name": "UnsafeObligationVacuous",
        "short": "A precondition or implementer obligation is recorded as vacuous or unmet.",
        "full": (
            "The inventory records VACUOUS_PRECONDITION or IMPLEMENTER_OBLIGATION. "
            "A SAFETY comment is the author's statement, not an established "
            "precondition."
        ),
        "level": "warning",
    },
    {
        "id": "A1-UNSAFE-OBLIGATION-DELEGATED",
        "name": "UnsafeObligationDelegated",
        "short": "An obligation is delegated to a caller or to the documented C ABI.",
        "full": (
            "The inventory records CITED_BY_CALLER or EXTERNAL_CALLER_CONTRACT. "
            "Citation is not proof; the row is emitted so the delegation remains "
            "visible."
        ),
        "level": "note",
    },
    {
        "id": "A1-UNSAFE-CONTRACT-ABSENT",
        "name": "UnsafeContractAbsent",
        "short": "An unsafe site has no contract text.",
        "full": (
            "The row's contract_state is absent. The recorded column value is kept "
            "in properties and is not emitted as a SARIF column."
        ),
        "level": "warning",
    },
    {
        "id": "A1-UNSAFE-SUPPRESSION-MEMBERS-ABSENT",
        "name": "UnsafeSuppressionMembersAbsent",
        "short": "An aggregate suppression count has no member rows.",
        "full": (
            "The inventory records a suppression total and a per-lint map, and no "
            "member row for any suppression. A6 cannot govern a suppression it "
            "cannot locate; this result names the limitation."
        ),
        "level": "warning",
    },
    {
        "id": "A1-ISA-BINARY-UNRESOLVED",
        "name": "IsaBinaryUnresolved",
        "short": "An unresolved indirect transfer in a built artefact.",
        "full": (
            "The closure receipt records a reachable unresolved indirect site at a "
            "function and call-site offset. No source line and no extent are "
            "recorded; none is emitted."
        ),
        "level": "warning",
    },
    {
        "id": "A1-ISA-POPULATION-TRUNCATED",
        "name": "IsaPopulationTruncated",
        "short": "A record population is bounded and the omitted members are not identified.",
        "full": (
            "The receipt names the sample, the population and the omitted count, "
            "and states that the omitted members are written to a sidecar rather "
            "than identified in the record. The bound is preserved verbatim."
        ),
        "level": "warning",
    },
    {
        "id": "A1-ELEMENT7-PREDICATE",
        "name": "Element7Predicate",
        "short": "The curl element-7 blocking predicate is not established.",
        "full": (
            "The closure receipt records the predicate status and its own counts. "
            "The predicate is emitted separately from the closure verdict because "
            "the two fields can disagree."
        ),
        "level": "error",
    },
    {
        "id": "A1-OBLIGATION-DISCHARGED",
        "name": "ObligationDischarged",
        "short": "A closure obligation the record marks DISCHARGED.",
        "full": (
            "The closure record marks the obligation DISCHARGED and names a "
            "discharging receipt. DISCHARGED means an existing committed receipt "
            "covers the exact site; the tool did not re-audit it."
        ),
        "level": "none",
    },
    {
        "id": "A1-OBLIGATION-DISPOSITION-SUPERSEDED",
        "name": "ObligationDispositionSuperseded",
        "short": "A conflicting disposition is marked superseded.",
        "full": (
            "The record marks this disposition superseded and names the boundary "
            "and receipt it came from. It is preserved as history and is not a "
            "current adjudication."
        ),
        "level": "note",
    },
    {
        "id": "A1-CLOSURE-VERDICT",
        "name": "ClosureVerdict",
        "short": "The closure receipt's own verdict block.",
        "full": (
            "The verdict block is emitted as a record-level condition. It is not a "
            "summary of the receipt's precision block."
        ),
        "level": "none",
    },
    {
        "id": "A1-ADJUDICATION-VERDICT",
        "name": "AdjudicationVerdict",
        "short": "An adjudication verdict on a consumer family.",
        "full": (
            "The adjudication records a verdict for named consumer families at a "
            "candidate. Failure of a graduation claim is not a finding of memory "
            "unsafety."
        ),
        "level": "error",
    },
    {
        "id": "A1-ADJUDICATION-REFUTATION",
        "name": "AdjudicationRefutation",
        "short": "One ordered refutation ground of an adjudication.",
        "full": (
            "The adjudication's ordered refutation text, emitted verbatim. The "
            "ordinal is the record's position and is not a stable identifier."
        ),
        "level": "error",
    },
    {
        "id": "A1-ADJUDICATION-MECHANISM",
        "name": "AdjudicationMechanism",
        "short": "One mechanism state in an adjudication.",
        "full": (
            "The adjudication records a verdict and an obligation count for this "
            "mechanism. A scoped SAFETY_DISCHARGED retains its caller "
            "preconditions."
        ),
        "level": "error",
    },
    {
        "id": "A1-ADJUDICATION-CROSS-CUTTING",
        "name": "AdjudicationCrossCutting",
        "short": "The adjudication's cross-cutting obligation block.",
        "full": (
            "The cross-cutting block is emitted verbatim as one record-level "
            "condition; the record does not decompose it into per-obligation rows."
        ),
        "level": "error",
    },
    {
        "id": "A1-RECONCILIATION-ROW",
        "name": "ReconciliationRow",
        "short": "One reviewer reconciliation row.",
        "full": (
            "A correction is emitted with the state it replaced and the state it "
            "assigned, so that what was believed is preserved."
        ),
        "level": "note",
    },
    {
        "id": "A1-RECONCILIATION-LIMIT",
        "name": "ReconciliationLimit",
        "short": "A reconciliation record declares an evidence level with gates not run.",
        "full": (
            "The record's limits block names the evidence level and what it does "
            "not claim. Deferred is not pass."
        ),
        "level": "warning",
    },
)

RULE_BY_ID = {r["id"]: r for r in RULES}

# Level/kind pairing required by SARIF 2.1.0 section 3.27.9.
_KIND_FOR_LEVEL = {
    "error": "fail",
    "warning": "fail",
    "note": "fail",
    "none": "informational",
}

# Profile section 4.4. Keys that must not appear as structural fields.
FORBIDDEN_KEYS = frozenset(
    {
        "conversion",
        "startTimeUtc",
        "endTimeUtc",
        "machine",
        "account",
        "processId",
        "workingDirectory",
        "environmentVariables",
        "stdin",
        "stdout",
        "stderr",
        "stdoutStderr",
        "suppressions",
        "baselineState",
        "baselineGuid",
        "rank",
        "fixes",
        "guid",
        "correlationGuid",
        "occurrenceCount",
        "taxa",
        "taxonomies",
        "snippet",
        "charOffset",
        "charLength",
        "endLine",
        "endColumn",
    }
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _digest_algorithm(digest: str) -> str:
    """Name the algorithm through the project-wide identity model.

    The model distinguishes a SHA-256 content digest from a Git object identifier
    (`sha1-git-object`) so a 40-hex commit id is not read as file bytes. The
    adapter keeps its own refusal code because that code is part of this tool's
    published interface.
    """
    try:
        return finding_identity.digest_algorithm(str(digest))
    except finding_identity.IdentityRefusal as exc:
        raise Refusal(
            R_MISSING_ARTIFACT_DIGEST,
            f"artefact digest is neither sha256 nor a git object id: {digest!r}",
        ) from exc


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _sha256_bytes(data: bytes) -> str:
    return finding_identity.digest_bytes(data)


def _canonical(value) -> str:
    return finding_identity.canonical_json(value)


def _require(mapping: dict, key: str, record: str, code: str = R_SHAPE):
    value = mapping.get(key)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise Refusal(code, f"{record}: required field {key!r} is absent or empty")
    return value


def _require_candidate(record: str, candidate: dict | None, keys: tuple[str, ...]) -> dict:
    """Extract the candidate identity verbatim and refuse if it is absent."""
    if not isinstance(candidate, dict):
        raise Refusal(R_MISSING_CANDIDATE, f"{record}: no candidate block")
    out: dict = {}
    for key in keys:
        value = candidate.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise Refusal(
                R_MISSING_CANDIDATE,
                f"{record}: candidate field {key!r} is absent or empty",
            )
        out[key] = value
    return out


def _load_json(repo_root: Path, record: str) -> tuple[dict, str]:
    path = repo_root / record
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise Refusal(R_SOURCE_UNREADABLE, f"{record}: {exc}") from exc
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal(R_SOURCE_UNREADABLE, f"{record}: {exc}") from exc
    if not isinstance(doc, dict):
        raise Refusal(R_SOURCE_UNREADABLE, f"{record}: top level is not an object")
    return doc, _sha256_bytes(data)


def _artifact_uri(path: str) -> str:
    if path.startswith("/") or ".." in path.split("/") or ":" in path:
        raise Refusal(R_SHAPE, f"artefact reference is not a relative path: {path!r}")
    return path


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

def finding(
    *,
    rule: str,
    key_class: str,
    key_fields: dict,
    message: str,
    level: str,
    level_basis: str,
    record: str,
    record_sha256: str,
    locator: str,
    candidate: dict,
    subject_uri: str | None,
    subject_digest: str | None,
    digest_scope: str,
    native_fields: dict,
    path: str | None = None,
    line: int | None = None,
    byte_offset: int | None = None,
    byte_length: int | None = None,
    address: int | None = None,
    address_kind: str = "instruction",
    related: list | None = None,
    limitations: list | None = None,
    extra_properties: dict | None = None,
) -> dict:
    if rule not in RULE_BY_ID:
        raise Refusal(R_SHAPE, f"rule {rule!r} is not in the closed registry")
    if level not in _KIND_FOR_LEVEL:
        raise Refusal(R_SHAPE, f"level {level!r} is not a SARIF level")
    try:
        logical_key = finding_identity.logical_key(key_class, **key_fields)
    except finding_identity.IdentityRefusal as exc:
        raise Refusal(R_SHAPE, f"{record}: {locator}: {exc.detail}") from exc
    if subject_uri is None:
        subject_uri = record
        subject_digest = record_sha256
        digest_scope = "record"
    if subject_digest is None:
        raise Refusal(
            R_MISSING_ARTIFACT_DIGEST,
            f"{record}: finding {locator} has no artefact digest",
        )
    if digest_scope != "record" and subject_uri == record:
        raise Refusal(
            R_SHAPE,
            f"{record}: finding {locator} binds the record as a non-record artefact",
        )
    return {
        "rule": rule,
        "logical_key": logical_key,
        "key_class": key_class,
        "message": message,
        "level": level,
        "level_basis": level_basis,
        "record": record,
        "record_sha256": record_sha256,
        "locator": locator,
        "candidate": candidate,
        "subject": {
            "uri": _artifact_uri(subject_uri),
            "digest": subject_digest,
            "digest_scope": digest_scope,
            "algorithm": _digest_algorithm(str(subject_digest)),
        },
        "path": path,
        "line": line,
        "byte_offset": byte_offset,
        "byte_length": byte_length,
        "address": address,
        "address_kind": address_kind,
        "related": related or [],
        "limitations": limitations or [],
        "native_fields": native_fields,
        "extra_properties": extra_properties or {},
    }


# --------------------------------------------------------------------------
# Source projections. Each returns (record_meta, findings, projection)
# --------------------------------------------------------------------------

def _project_secrets(repo_root: Path) -> dict:
    record = "evidence/etp-t7/SECRETS.json"
    doc, sha = _load_json(repo_root, record)
    candidate = _require_candidate(record, doc.get("candidate"), ("commit", "branch"))
    entries = _require(doc, "entries", record)
    if not isinstance(entries, list) or not entries:
        raise Refusal(R_SHAPE, f"{record}: entries is empty")

    counts = doc.get("counts") or {}
    if sum(counts.values()) != len(entries):
        raise Refusal(
            R_POPULATION,
            f"{record}: counts sum {sum(counts.values())} != {len(entries)} entries",
        )
    computed: dict[str, int] = {}
    for entry in entries:
        computed[entry["class"]] = computed.get(entry["class"], 0) + 1
    if computed != counts:
        raise Refusal(R_POPULATION, f"{record}: counts disagree with the entry classes")

    def evidence_result(entry):
        ev = entry.get("evidence")
        return ev if isinstance(ev, str) else (ev or {}).get("result")

    computed_sdc = [
        e["id"]
        for e in entries
        if e["class"] == "SECRET_DEPENDENT_CONTROL" and evidence_result(e) == "NONE"
    ]
    if sorted(computed_sdc) != sorted(doc.get("secret_dependent_control_without_evidence") or []):
        raise Refusal(
            R_POPULATION,
            f"{record}: secret_dependent_control_without_evidence is not the computed set",
        )
    computed_unmet = [
        e["id"]
        for e in entries
        if e["cleansing_obligation"]["required"] and not e["cleansing_obligation"]["met"]
    ]
    if sorted(computed_unmet) != sorted(doc.get("secret_bearing_without_cleansing") or []):
        raise Refusal(
            R_POPULATION,
            f"{record}: secret_bearing_without_cleansing is not the computed set",
        )

    findings = []
    count_by_rule: dict[str, int] = {}
    for index, entry in enumerate(entries):
        result = evidence_result(entry)
        required = entry["cleansing_obligation"]["required"]
        met = entry["cleansing_obligation"]["met"]
        if result == "LEAKAGE_REPORTED":
            rule, level, basis = (
                "A1-SECRET-LEAKAGE-REPORTED",
                "error",
                "native-evidence-result-LEAKAGE_REPORTED",
            )
            message = (
                f"{entry['item']} ({entry['source'].get('symbol') or entry['id']}): "
                f"the recorded {entry['evidence'].get('kind')} result is "
                f"LEAKAGE_REPORTED. Native note: {entry.get('note', '')}".rstrip()
            )
        elif required and not met:
            rule, level, basis = (
                "A1-SECRET-CLEANSING-UNMET",
                "error",
                "native-cleansing-required-and-met-false",
            )
            message = (
                f"{entry['item']} ({entry['source'].get('symbol') or entry['id']}): "
                f"cleansing of {entry['cleansing_obligation']['extent']} is required "
                f"and is recorded as not met ({entry['cleansing_obligation']['mechanism']})."
            )
        elif result == "NONE":
            rule, level, basis = (
                "A1-SECRET-CONTROL-NO-EVIDENCE",
                "warning",
                "native-evidence-result-NONE",
            )
            message = (
                f"{entry['item']} ({entry['source'].get('symbol') or entry['id']}): "
                "no evidence is recorded for this secret-dependent control; the "
                "register lists it in secret_dependent_control_without_evidence."
            )
        elif entry["class"] in ("PUBLIC_DATA", "DECLASSIFICATION_BOUNDARY"):
            rule, level, basis = (
                "A1-SECRET-CLASSIFICATION-RECORDED",
                "note",
                "native-classification-entry",
            )
            message = (
                f"{entry['item']} ({entry['source'].get('symbol') or entry['id']}): "
                f"recorded as {entry['class']}."
            )
        else:
            rule, level, basis = (
                "A1-SECRET-EVIDENCE-CONTRACT-ONLY",
                "note",
                "native-evidence-contract-or-design-only",
            )
            evidence = entry.get("evidence")
            kind = evidence.get("kind") if isinstance(evidence, dict) else evidence
            reference = evidence.get("reference") if isinstance(evidence, dict) else None
            message = (
                f"{entry['item']} ({entry['source'].get('symbol') or entry['id']}): "
                f"the only recorded evidence is {kind}"
                + (f" ({reference})" if reference else "")
                + f", result {result}."
            )
        count_by_rule[rule] = count_by_rule.get(rule, 0) + 1
        findings.append(
            finding(
                rule=rule,
                key_class="register-entry",
                key_fields={"id": entry["id"]},
                message=message,
                level=level,
                level_basis=basis,
                record=record,
                record_sha256=sha,
                locator=f"entries[{index}]",
                candidate=candidate,
                subject_uri=entry["source"]["path"],
                subject_digest=candidate["commit"],
                digest_scope="candidate-commit",
                path=entry["source"]["path"],
                line=entry["source"].get("line"),
                native_fields={
                    key: entry[key]
                    for key in (
                        "id",
                        "item",
                        "class",
                        "owner",
                        "source",
                        "cleansing_obligation",
                        "evidence",
                        "note",
                    )
                    if key in entry
                },
            )
        )

    return {
        "record": record,
        "sha256": sha,
        "schema": doc.get("schema"),
        "candidate": candidate,
        "findings": findings,
        "projection": {
            "nativePopulation": {"entries": len(entries), "counts": counts},
            "projected": count_by_rule,
            "notProjected": [
                {
                    "block": "non_claims",
                    "count": len(doc.get("non_claims") or []),
                    "reason": "carried verbatim at run.properties.a1.nativeNonClaims",
                }
            ],
            "sumMatchesPopulation": True,
        },
        "non_claims": doc.get("non_claims") or [],
    }


def _project_timing(repo_root: Path) -> dict:
    record = "evidence/timing-bn-findings.json"
    doc, sha = _load_json(repo_root, record)
    candidate_raw = doc.get("candidate")
    candidate = _require_candidate(
        record, candidate_raw, ("source_head", "branch")
    )
    libcrypto = _require(candidate_raw, "libcrypto", record)
    candidate["libcrypto_sha256"] = _require(libcrypto, "sha256", record)
    if libcrypto.get("build_id"):
        candidate["libcrypto_build_id"] = libcrypto["build_id"]

    primitives = _require(doc, "primitives", record)
    ctgrind = _require(doc, "ctgrind", record)
    dudect = _require(doc, "dudect", record)
    for name in primitives:
        if name not in ctgrind or name not in dudect:
            raise Refusal(
                R_SHAPE, f"{record}: primitive {name!r} has no ctgrind or dudect block"
            )

    dso = Path(libcrypto.get("path") or "libcrypto.so.3").name
    dso_digest = candidate["libcrypto_sha256"]

    findings = []
    count_by_rule: dict[str, int] = {}
    for name in sorted(primitives):
        ct = ctgrind[name]
        du = dudect[name]
        pr = primitives[name]
        offset = int(str(pr["libcrypto_offset"]), 16)
        size = int(pr["size"])
        file_line = str(ct.get("file_line", ""))
        line_available = not file_line.startswith("NOT AVAILABLE")

        related = []
        sites = ct.get("sites") or ct.get("representative_sites") or []
        for site in sites:
            if not isinstance(site, dict) or "offset" not in site:
                continue
            site_offset = int(str(site["offset"]), 16)
            loc = {
                "physicalLocation": {
                    "artifactLocation": {"uri": dso, "index": None},
                    "address": {
                        "absoluteAddress": site_offset,
                        "kind": "instruction",
                    },
                    "region": {"byteOffset": site_offset},
                },
                "properties": {
                    "a1": {
                        "locationPrecision": "byte-offset-in-artifact",
                        "lineInfoAvailable": False,
                        "extentRecorded": False,
                        "native": {"fields": dict(site)},
                    }
                },
            }
            if site.get("function"):
                loc["logicalLocations"] = [
                    {
                        "name": str(site["function"]),
                        "fullyQualifiedName": str(site["function"]),
                        "kind": "function",
                    }
                ]
            loc["message"] = {
                "text": f"ctgrind recorded site {site['offset']}"
                + (f" ({site['instr']})" if site.get("instr") else "")
            }
            related.append(loc)

        limitations = [
            "the finding is a machine-code finding: no source line, column or "
            "file path is recorded for the primitive's branch sites",
            "the recorded location is a byte offset in the named shared object; "
            "offsets are not stable across builds",
        ]
        if not line_available:
            limitations.append(f"native file_line: {file_line}")

        count_by_rule["A1-TIMING-LEAKAGE-DETECTED"] = (
            count_by_rule.get("A1-TIMING-LEAKAGE-DETECTED", 0) + 1
        )
        findings.append(
            finding(
                rule="A1-TIMING-LEAKAGE-DETECTED",
                key_class="primitive-name",
                key_fields={"name": name},
                message=(
                    f"{name}: ctgrind recorded {ct.get('errors')} taint errors over "
                    f"{ct.get('contexts')} contexts; dudect verdict "
                    f"{du.get('verdict')} with t values {du.get('t_values')}. "
                    f"Native dudect text: {du.get('dudect_text', '')}. "
                    f"Native file_line: {file_line}".rstrip()
                ),
                level="error",
                level_basis="native-timing-verdict-LEAKAGE_DETECTED",
                record=record,
                record_sha256=sha,
                locator=f"primitives.{name}",
                candidate=candidate,
                subject_uri=dso,
                subject_digest=dso_digest,
                digest_scope="artifact",
                byte_offset=offset,
                byte_length=size,
                address=offset,
                address_kind="function",
                related=related,
                limitations=limitations,
                native_fields={
                    "primitive": pr,
                    "ctgrind": {
                        k: ct[k]
                        for k in (
                            "errors",
                            "contexts",
                            "kinds",
                            "function",
                            "file_line",
                            "log",
                        )
                        if k in ct
                    },
                    "dudect": du,
                },
                extra_properties={
                    "lineInfoAvailable": line_available,
                    "functionExtentRecorded": True,
                },
            )
        )

    not_run = doc.get("not_run") or []
    for index, item in enumerate(not_run):
        count_by_rule["A1-TIMING-NOT-RUN"] = count_by_rule.get("A1-TIMING-NOT-RUN", 0) + 1
        findings.append(
            finding(
                rule="A1-TIMING-NOT-RUN",
                key_class="normalised-text",
                key_fields={"text": str(item)},
                message=f"Not run: {item}",
                level="warning",
                level_basis="native-not-run-list",
                record=record,
                record_sha256=sha,
                locator=f"not_run[{index}]",
                candidate=candidate,
                subject_uri=None,
                subject_digest=None,
                digest_scope="record",
                native_fields={"item": item},
                extra_properties={"locationKind": "record-condition"},
            )
        )

    return {
        "record": record,
        "sha256": sha,
        "schema": doc.get("schema"),
        "candidate": candidate,
        "findings": findings,
        "projection": {
            "nativePopulation": {
                "primitives": len(primitives),
                "not_run": len(not_run),
            },
            "projected": count_by_rule,
            "notProjected": [
                {
                    "block": "controls",
                    "count": len(doc.get("controls") or {}),
                    "reason": "instrument negative/positive controls; not findings",
                },
                {
                    "block": "reachability",
                    "count": len(doc.get("reachability") or {}),
                    "reason": "static may-bound reachability measurement; not a finding population",
                },
            ],
            "sumMatchesPopulation": True,
        },
        "non_claims": doc.get("non_claims") or [],
    }


def _decode_site_row(row: list, columns: list, tables: dict, vocab: dict) -> dict:
    literal = {"id", "line", "column", "contract_sha256"}
    decoded = {}
    for column, value in zip(columns, row):
        if column in literal:
            decoded[column] = value
        elif column in tables:
            decoded[column] = tables[column][value]
        elif column in vocab:
            decoded[column] = vocab[column][value]
        else:
            # A column with no table or vocabulary carries a literal value of its
            # own encoding (for example a bitmask). It is passed through verbatim
            # and no claim is made about its meaning.
            decoded[column] = value
    return decoded


def _project_safety(repo_root: Path) -> dict:
    record = "evidence/etp-t4/SAFETY-SITES.json"
    doc, sha = _load_json(repo_root, record)
    identity = _require(doc, "identity", record)
    candidate = _require_candidate(
        record, identity, ("commit", "branch", "source_tree_sha256", "scanner_sha256")
    )
    candidate["scanner"] = identity.get("scanner")

    sites = _require(doc, "sites", record)
    rows = sites["rows"]
    columns = sites["columns"]
    tables = sites["tables"]
    vocabulary = sites["vocabularies"]
    summary = _require(doc, "summary", record)

    if len(rows) != summary.get("sites"):
        raise Refusal(
            R_POPULATION,
            f"{record}: {len(rows)} site rows vs declared {summary.get('sites')}",
        )

    site_digest = candidate["source_tree_sha256"]
    decoded_rows = []
    absent_rows = []
    for index, row in enumerate(rows):
        decoded = _decode_site_row(row, columns, tables, vocabulary)
        decoded["__index__"] = index
        decoded_rows.append(decoded)
        if decoded["contract_state"] == "absent":
            absent_rows.append(decoded)
    if len(absent_rows) != summary.get("contract_absent"):
        raise Refusal(
            R_POPULATION,
            f"{record}: {len(absent_rows)} contract_state=absent rows vs declared "
            f"{summary.get('contract_absent')}",
        )

    vacuity = doc.get("vacuity") or {}
    vacuity_findings = vacuity.get("findings") or []
    vacuity_summary = vacuity.get("summary") or {}
    status_counts: dict[str, int] = {}
    for item in vacuity_findings:
        status_counts[item["status"]] = status_counts.get(item["status"], 0) + 1
    for status, count in status_counts.items():
        declared = vacuity_summary.get(status.lower())
        if declared is not None and declared != count:
            raise Refusal(
                R_POPULATION,
                f"{record}: vacuity status {status} has {count} rows vs declared {declared}",
            )

    findings = []
    count_by_rule: dict[str, int] = {}
    rule_by_status = {
        "CALLER_OBLIGATION_UNESTABLISHED": (
            "A1-UNSAFE-OBLIGATION-UNESTABLISHED",
            "error",
        ),
        "VACUOUS_PRECONDITION": ("A1-UNSAFE-OBLIGATION-VACUOUS", "warning"),
        "IMPLEMENTER_OBLIGATION": ("A1-UNSAFE-OBLIGATION-VACUOUS", "warning"),
        "CITED_BY_CALLER": ("A1-UNSAFE-OBLIGATION-DELEGATED", "note"),
        "EXTERNAL_CALLER_CONTRACT": ("A1-UNSAFE-OBLIGATION-DELEGATED", "note"),
    }
    for index, item in enumerate(vacuity_findings):
        status = item["status"]
        if status not in rule_by_status:
            raise Refusal(
                R_SHAPE, f"{record}: unknown vacuity status {status!r}"
            )
        rule, level = rule_by_status[status]
        count_by_rule[rule] = count_by_rule.get(rule, 0) + 1
        findings.append(
            finding(
                rule=rule,
                key_class="path-symbol-status",
                key_fields={
                    "path": item["path"],
                    "symbol": item["symbol"],
                    "status": status,
                },
                message=(
                    f"{status}: {item['detail']}. Site {item['site']} at "
                    f"{item['path']}:{item['line']} ({item['symbol']})."
                ),
                level=level,
                level_basis=f"native-vacuity-status-{status}",
                record=record,
                record_sha256=sha,
                locator=f"vacuity.findings[{index}]",
                candidate=candidate,
                subject_uri=item["path"],
                subject_digest=site_digest,
                digest_scope="source-tree",
                path=item["path"],
                line=item["line"],
                native_fields={
                    key: item[key]
                    for key in (
                        "site",
                        "path",
                        "line",
                        "symbol",
                        "status",
                        "scope",
                        "detail",
                        "production_callers",
                        "test_callers",
                        "witness",
                    )
                    if key in item
                },
            )
        )

    for decoded in absent_rows:
        index = decoded.pop("__index__")
        count_by_rule["A1-UNSAFE-CONTRACT-ABSENT"] = (
            count_by_rule.get("A1-UNSAFE-CONTRACT-ABSENT", 0) + 1
        )
        findings.append(
            finding(
                rule="A1-UNSAFE-CONTRACT-ABSENT",
                key_class="path-symbol-class",
                key_fields={
                    "path": decoded["path"],
                    "symbol": decoded["symbol"],
                    "class": decoded["class"],
                },
                message=(
                    f"No contract text is recorded for this {decoded['class']} site "
                    f"{decoded['symbol']} at {decoded['path']}:{decoded['line']}; "
                    "contract_state is 'absent'."
                ),
                level="warning",
                level_basis="native-contract-state-absent",
                record=record,
                record_sha256=sha,
                locator=f"sites.rows[{index}]",
                candidate=candidate,
                subject_uri=decoded["path"],
                subject_digest=site_digest,
                digest_scope="source-tree",
                path=decoded["path"],
                line=decoded["line"],
                native_fields=decoded,
                extra_properties={"columnUnit": "not-recorded"},
                limitations=[
                    "the recorded column is preserved in properties and is not "
                    "emitted as a SARIF column because its unit is not recorded"
                ],
            )
        )

    suppressions = doc.get("suppressions") or {}
    count_by_rule["A1-UNSAFE-SUPPRESSION-MEMBERS-ABSENT"] = 1
    findings.append(
        finding(
            rule="A1-UNSAFE-SUPPRESSION-MEMBERS-ABSENT",
            key_class="literal",
            key_fields={"value": "suppressions"},
            message=(
                f"The native record reports {suppressions.get('total')} suppressions "
                "by lint and records no member row for any suppression, so no "
                "suppression location can be emitted."
            ),
            level="warning",
            level_basis="native-aggregate-without-members",
            record=record,
            record_sha256=sha,
            locator="suppressions",
            candidate=candidate,
            subject_uri=None,
            subject_digest=None,
            digest_scope="record",
            native_fields={"total": suppressions.get("total"), "by_lint": suppressions.get("by_lint")},
            extra_properties={
                "locationKind": "record-condition",
                "membersRecorded": False,
            },
            limitations=["no member location is recorded by the native record"],
        )
    )

    return {
        "record": record,
        "sha256": sha,
        "schema": doc.get("schema"),
        "candidate": candidate,
        "findings": findings,
        "projection": {
            "nativePopulation": {
                "sites": summary.get("sites"),
                "vacuity_findings": len(vacuity_findings),
                "contract_absent": summary.get("contract_absent"),
                "suppressions": suppressions.get("total"),
            },
            "projected": count_by_rule,
            "notProjected": [
                {
                    "block": "sites.rows",
                    "count": len(rows),
                    "reason": (
                        "lexical unsafe-site census, not a finding population; the "
                        "projected unsafe-boundary populations are vacuity.findings "
                        "and the contract_state=absent rows"
                    ),
                },
                {
                    "block": "operations.rows",
                    "count": len((doc.get("operations") or {}).get("rows") or []),
                    "reason": "named raw-operation rows; a separate population",
                },
                {
                    "block": "contracts.entries",
                    "count": len(((doc.get("contracts") or {}).get("entries")) or {}),
                    "reason": "contract text dictionary referenced by row prefix; not findings",
                },
                {
                    "block": "assertions.ignored",
                    "count": summary.get("ignored_tests"),
                    "reason": "ignored-test census; suppression governance is A6",
                },
            ],
            "sumMatchesPopulation": True,
        },
        "non_claims": doc.get("non_claims") or [],
    }


def _project_curl(repo_root: Path) -> dict:
    record = "evidence/closure-curl-049.json"
    doc, sha = _load_json(repo_root, record)
    source_identity = _require(doc, "source_identity", record)
    candidate = _require_candidate(
        record, source_identity, ("repository_head", "branch")
    )
    candidate_identity = _require(doc, "candidate_identity", record)
    dso_digests = {
        "libcrypto.so.3": _require(candidate_identity, "libcrypto_so_3_sha256", record),
        "libssl.so.3": _require(candidate_identity, "libssl_so_3_sha256", record),
    }
    candidate["libcrypto_so_3_sha256"] = dso_digests["libcrypto.so.3"]
    candidate["libssl_so_3_sha256"] = dso_digests["libssl.so.3"]

    precision = _require(doc, "precision", record)
    totals = precision.get("totals") or {}
    bound = precision.get("residual_sites_bound") or {}
    residual = precision.get("residual_sites") or []
    obligations = _require(doc, "obligations", record)
    counts = _require(doc, "counts", record)

    if counts.get("reachable_production_obligations") != len(obligations):
        raise Refusal(
            R_POPULATION,
            f"{record}: {len(obligations)} obligations vs declared "
            f"{counts.get('reachable_production_obligations')}",
        )
    if bound.get("sample_size") != len(residual):
        raise Refusal(
            R_POPULATION,
            f"{record}: {len(residual)} residual rows vs declared sample_size "
            f"{bound.get('sample_size')}",
        )
    if bound.get("population_size") != totals.get("reachable_unresolved_sites"):
        raise Refusal(
            R_POPULATION,
            f"{record}: residual bound population {bound.get('population_size')} vs "
            f"totals {totals.get('reachable_unresolved_sites')}",
        )
    if bound.get("omitted_members") != (
        bound.get("population_size", 0) - bound.get("sample_size", 0)
    ):
        raise Refusal(
            R_POPULATION, f"{record}: omitted_members is not population - sample"
        )

    findings = []
    count_by_rule: dict[str, int] = {}
    digest = candidate["repository_head"]

    for index, obligation in enumerate(obligations):
        status = obligation.get("status")
        if status != "DISCHARGED":
            raise Refusal(
                R_SHAPE,
                f"{record}: obligation {obligation.get('id')!r} has status "
                f"{status!r}; the A1 projection covers DISCHARGED and refuses to "
                "level an unmodelled state",
            )
        count_by_rule["A1-OBLIGATION-DISCHARGED"] = (
            count_by_rule.get("A1-OBLIGATION-DISCHARGED", 0) + 1
        )
        receipt = obligation.get("discharge_receipt")
        receipt_text = receipt if isinstance(receipt, str) else _canonical(receipt)
        findings.append(
            finding(
                rule="A1-OBLIGATION-DISCHARGED",
                key_class="stable-id",
                key_fields={"id": obligation["stable_id"]},
                message=(
                    f"{obligation['item']} ({obligation['file']}:{obligation['line']}): "
                    f"closure status DISCHARGED under mechanism "
                    f"{obligation.get('mechanism')}; discharging receipt "
                    f"{receipt_text}."
                ),
                level="none",
                level_basis="native-status-DISCHARGED",
                record=record,
                record_sha256=sha,
                locator=f"obligations[{index}]",
                candidate=candidate,
                subject_uri=obligation["file"],
                subject_digest=digest,
                digest_scope="candidate-commit",
                path=obligation["file"],
                line=obligation["line"],
                native_fields={
                    key: obligation[key]
                    for key in (
                        "id",
                        "stable_id",
                        "file",
                        "line",
                        "kind",
                        "item",
                        "partition",
                        "contract",
                        "mechanism",
                        "status",
                        "discharge_receipt",
                        "site_boundary",
                    )
                    if key in obligation
                },
                extra_properties={
                    "nonClaim": (
                        "DISCHARGED means an existing committed receipt covers the "
                        "exact site; the projection did not re-audit, re-run or "
                        "independently review that receipt"
                    )
                },
            )
        )
        for j, conflict in enumerate(obligation.get("disposition_conflicts") or []):
            if conflict.get("superseded") is not True:
                continue
            count_by_rule["A1-OBLIGATION-DISPOSITION-SUPERSEDED"] = (
                count_by_rule.get("A1-OBLIGATION-DISPOSITION-SUPERSEDED", 0) + 1
            )
            findings.append(
                finding(
                    rule="A1-OBLIGATION-DISPOSITION-SUPERSEDED",
                    key_class="obligation-boundary-receipt",
                    key_fields={
                        "obligation": obligation["stable_id"],
                        "boundary": conflict.get("boundary"),
                        "receipt": conflict.get("receipt"),
                    },
                    message=(
                        f"Superseded disposition for {obligation['id']}: boundary "
                        f"{conflict.get('boundary')} receipt {conflict.get('receipt')} "
                        f"keyword {conflict.get('keyword')} is marked superseded and "
                        "is not a current adjudication."
                    ),
                    level="note",
                    level_basis="native-superseded-true",
                    record=record,
                    record_sha256=sha,
                    locator=(
                        f"obligations[{index}].disposition_conflicts[{j}]"
                    ),
                    candidate=candidate,
                    subject_uri=obligation["file"],
                    subject_digest=digest,
                    digest_scope="candidate-commit",
                    path=obligation["file"],
                    line=obligation["line"],
                    native_fields=dict(conflict),
                    extra_properties={
                        "superseded": True,
                        "supersededDisposition": conflict.get("disposition")
                        or conflict.get("keyword"),
                    },
                )
            )

    for index, site in enumerate(residual):
        dso = site.get("dso")
        if dso not in dso_digests:
            raise Refusal(
                R_MISSING_ARTIFACT_DIGEST,
                f"{record}: residual site {index} names {dso!r} with no recorded digest",
            )
        function = int(str(site["function"]), 16)
        call_site = int(str(site["call_site"]), 16)
        count_by_rule["A1-ISA-BINARY-UNRESOLVED"] = (
            count_by_rule.get("A1-ISA-BINARY-UNRESOLVED", 0) + 1
        )
        findings.append(
            finding(
                rule="A1-ISA-BINARY-UNRESOLVED",
                key_class="dso-class-reason",
                key_fields={
                    "dso": dso,
                    "class": site["class"],
                    "reason": site["reason"],
                },
                message=(
                    f"Unresolved indirect transfer in {dso}: function "
                    f"{site['function']} call site {site['call_site']} "
                    f"({site.get('text', '')}); native reason: {site['reason']}."
                ),
                level="warning",
                level_basis="native-unresolved-indirect-site",
                record=record,
                record_sha256=sha,
                locator=f"precision.residual_sites[{index}]",
                candidate=candidate,
                subject_uri=dso,
                subject_digest=dso_digests[dso],
                digest_scope="artifact",
                byte_offset=call_site,
                address=function,
                address_kind="function",
                native_fields={
                    key: site[key]
                    for key in ("dso", "function", "call_site", "reason", "class", "text")
                    if key in site
                },
                extra_properties={"extentRecorded": False},
                limitations=[
                    "no source line, column or symbol name is recorded for this site",
                    "the recorded location is a byte offset in the named shared "
                    "object; offsets are not stable across builds",
                ],
            )
        )

    count_by_rule["A1-ISA-POPULATION-TRUNCATED"] = 1
    findings.append(
        finding(
            rule="A1-ISA-POPULATION-TRUNCATED",
            key_class="field-path",
            key_fields={"json_path": "precision.residual_sites"},
            message=(
                f"precision.residual_sites records {bound.get('sample_size')} of "
                f"{bound.get('population_size')} members; {bound.get('omitted_members')} "
                "omitted members are not identified in this record "
                f"(omitted_members_recorded={bound.get('omitted_members_recorded')})."
            ),
            level="warning",
            level_basis="native-population-bounded",
            record=record,
            record_sha256=sha,
            locator="precision.residual_sites_bound",
            candidate=candidate,
            subject_uri=None,
            subject_digest=None,
            digest_scope="record",
            native_fields={
                "status": bound.get("status"),
                "sample_size": bound.get("sample_size"),
                "population_size": bound.get("population_size"),
                "omitted_members": bound.get("omitted_members"),
                "omitted_members_recorded": bound.get("omitted_members_recorded"),
                "omitted_members_note": bound.get("omitted_members_note"),
                "selection_rule": bound.get("selection_rule"),
            },
            extra_properties={"locationKind": "record-condition"},
        )
    )

    predicate = _require(precision, "predicate_element_7", record)
    count_by_rule["A1-ELEMENT7-PREDICATE"] = 1
    findings.append(
        finding(
            rule="A1-ELEMENT7-PREDICATE",
            key_class="field-path",
            key_fields={"json_path": "precision.predicate_element_7"},
            message=(
                f"curl element 7 predicate: {predicate.get('status')} "
                f"(established={predicate.get('established')}). Native basis: "
                f"{predicate.get('basis')}. Reachable unresolved sites "
                f"{predicate.get('reachable_unresolved_sites')}; target-bounded "
                f"{predicate.get('target_bounded_unresolved_sites')}."
            ),
            level="error",
            level_basis="native-predicate-FAIL",
            record=record,
            record_sha256=sha,
            locator="precision.predicate_element_7",
            candidate=candidate,
            subject_uri=None,
            subject_digest=None,
            digest_scope="record",
            native_fields=dict(predicate),
            extra_properties={"locationKind": "record-condition"},
        )
    )

    verdict = _require(doc, "verdict", record)
    count_by_rule["A1-CLOSURE-VERDICT"] = 1
    findings.append(
        finding(
            rule="A1-CLOSURE-VERDICT",
            key_class="literal",
            key_fields={"value": "verdict"},
            message=(
                f"Closure verdict: {verdict.get('state')}; safe_compatible="
                f"{verdict.get('safe_compatible')}. Native reason: "
                f"{verdict.get('reason')}."
            ),
            level="none",
            level_basis="native-verdict-record",
            record=record,
            record_sha256=sha,
            locator="verdict",
            candidate=candidate,
            subject_uri=None,
            subject_digest=None,
            digest_scope="record",
            native_fields=dict(verdict),
            extra_properties={"locationKind": "record-condition"},
        )
    )

    return {
        "record": record,
        "sha256": sha,
        "schema": doc.get("schema"),
        "candidate": candidate,
        "findings": findings,
        "projection": {
            "nativePopulation": {
                "obligations": len(obligations),
                "residual_sites_sample": len(residual),
                "residual_sites_population": totals.get("reachable_unresolved_sites"),
                "refusals": len(doc.get("refusals") or []),
            },
            "projected": count_by_rule,
            "notProjected": [
                {
                    "block": "graph",
                    "count": None,
                    "reason": "upper-bound call-graph measurement; not a finding population",
                },
                {
                    "block": "precision.witness blocks",
                    "count": sum(
                        len(v)
                        for v in (
                            precision.get("e7bs_witnesses") or [],
                            precision.get("pbe_outparam_witnesses") or [],
                            precision.get("method_table_witnesses") or [],
                        )
                    ),
                    "reason": "witness rows for already-bounded sites; a separate population",
                },
                {
                    "block": "edge_provenance",
                    "count": None,
                    "reason": "admissibility chain of the graph records; not findings",
                },
                {
                    "block": "non_claims",
                    "count": len(doc.get("non_claims") or []),
                    "reason": "carried verbatim at run.properties.a1.nativeNonClaims",
                },
            ],
            "sumMatchesPopulation": True,
        },
        "non_claims": doc.get("non_claims") or [],
    }


def _project_adjudication(repo_root: Path) -> dict:
    record = "evidence/b85c-adjudication.json"
    doc, sha = _load_json(repo_root, record)
    candidate = _require_candidate(
        record,
        doc,
        ("evidence_source_head", "head_at_adjudication", "src_content_sha256"),
    )
    if doc.get("source_content_commit"):
        candidate["source_content_commit"] = doc["source_content_commit"]
    freeze = doc.get("freeze") or {}
    if freeze.get("sha256"):
        candidate["freeze_sha256"] = freeze["sha256"]

    verdict = _require(doc, "verdict", record)
    mechanisms = _require(
        _require(doc, "item4_mechanisms", record), "per_mechanism", record
    )
    refutations = _require(doc, "ordered_refutations", record)
    cross_cutting = _require(
        doc["item4_mechanisms"], "cross_cutting", record
    )

    findings = []
    count_by_rule: dict[str, int] = {}
    families = verdict.get("for") or []
    count_by_rule["A1-ADJUDICATION-VERDICT"] = 1
    findings.append(
        finding(
            rule="A1-ADJUDICATION-VERDICT",
            key_class="literal",
            key_fields={"value": "verdict"},
            message=(
                f"Adjudication verdict for {', '.join(families)}: "
                f"{verdict.get('state')}. Native reason: {verdict.get('reason')}"
            ),
            level="error",
            level_basis="native-verdict-NOT_ESTABLISHED",
            record=record,
            record_sha256=sha,
            locator="verdict",
            candidate=candidate,
            subject_uri=None,
            subject_digest=None,
            digest_scope="record",
            native_fields={
                "state": verdict.get("state"),
                "for": families,
                "reason": verdict.get("reason"),
            },
            extra_properties={"locationKind": "record-condition"},
            limitations=[
                "the adjudication is about consumer families at a candidate, not "
                "about a code location"
            ],
        )
    )

    for index, text in enumerate(refutations):
        count_by_rule["A1-ADJUDICATION-REFUTATION"] = (
            count_by_rule.get("A1-ADJUDICATION-REFUTATION", 0) + 1
        )
        findings.append(
            finding(
                rule="A1-ADJUDICATION-REFUTATION",
                key_class="refutation",
                key_fields={"text": str(text), "digest_chars": 16},
                message=str(text),
                level="error",
                level_basis="native-ordered-refutation",
                record=record,
                record_sha256=sha,
                locator=f"ordered_refutations[{index}]",
                candidate=candidate,
                subject_uri=None,
                subject_digest=None,
                digest_scope="record",
                native_fields={"ordinal": index, "text": text},
                extra_properties={"locationKind": "record-condition"},
            )
        )

    for name in sorted(mechanisms):
        entry = mechanisms[name]
        state = str(entry.get("verdict", ""))
        if state.startswith("NOT_ESTABLISHED"):
            level, basis = "error", "native-mechanism-NOT_ESTABLISHED"
        elif state.startswith("SAFETY_DISCHARGED"):
            level, basis = "note", "native-mechanism-SAFETY_DISCHARGED-scoped"
        else:
            raise Refusal(
                R_SHAPE, f"{record}: unknown mechanism verdict {state!r} for {name!r}"
            )
        count_by_rule["A1-ADJUDICATION-MECHANISM"] = (
            count_by_rule.get("A1-ADJUDICATION-MECHANISM", 0) + 1
        )
        findings.append(
            finding(
                rule="A1-ADJUDICATION-MECHANISM",
                key_class="mechanism",
                key_fields={"name": name},
                message=(
                    f"Mechanism {name}: {state} over {entry.get('obligations')} "
                    "obligations."
                ),
                level=level,
                level_basis=basis,
                record=record,
                record_sha256=sha,
                locator=f"item4_mechanisms.per_mechanism.{name}",
                candidate=candidate,
                subject_uri=None,
                subject_digest=None,
                digest_scope="record",
                native_fields=dict(entry),
                extra_properties={"locationKind": "record-condition"},
            )
        )

    count_by_rule["A1-ADJUDICATION-CROSS-CUTTING"] = 1
    findings.append(
        finding(
            rule="A1-ADJUDICATION-CROSS-CUTTING",
            key_class="field-path",
            key_fields={"json_path": "item4_mechanisms.cross_cutting"},
            message=f"Cross-cutting obligations: {cross_cutting}",
            level="error",
            level_basis="native-cross-cutting-NOT_ESTABLISHED",
            record=record,
            record_sha256=sha,
            locator="item4_mechanisms.cross_cutting",
            candidate=candidate,
            subject_uri=None,
            subject_digest=None,
            digest_scope="record",
            native_fields={"text": cross_cutting},
            extra_properties={"locationKind": "record-condition"},
        )
    )

    return {
        "record": record,
        "sha256": sha,
        "schema": doc.get("schema"),
        "candidate": candidate,
        "findings": findings,
        "projection": {
            "nativePopulation": {
                "ordered_refutations": len(refutations),
                "mechanisms": len(mechanisms),
                "ordered_items": 5,
            },
            "projected": count_by_rule,
            "notProjected": [
                {
                    "block": "item1..item5",
                    "count": 5,
                    "reason": (
                        "prose summaries that restate the structured per-mechanism "
                        "and refutation rows; assigning them a level would require "
                        "interpretation the record does not supply"
                    ),
                },
                {
                    "block": "non_claims",
                    "count": len(doc.get("non_claims") or []),
                    "reason": "carried verbatim at run.properties.a1.nativeNonClaims",
                },
            ],
            "sumMatchesPopulation": True,
        },
        "non_claims": doc.get("non_claims") or [],
    }


def _project_reconciliation(repo_root: Path) -> dict:
    record = "evidence/b85c-row-reconciliation.json"
    doc, sha = _load_json(repo_root, record)
    candidate = _require_candidate(record, doc, ("source_candidate",))
    if doc.get("head_at_review"):
        candidate["head_at_review"] = doc["head_at_review"]
    if doc.get("branch"):
        candidate["branch"] = doc["branch"]

    rows = _require(doc, "rows", record)
    if not rows:
        raise Refusal(R_SHAPE, f"{record}: rows is empty")

    findings = []
    count_by_rule: dict[str, int] = {}
    for index, row in enumerate(rows):
        decision = _require(row, "decision", record)
        obligation = row.get("obligation") or row.get("ledger_pointer")
        count_by_rule["A1-RECONCILIATION-ROW"] = (
            count_by_rule.get("A1-RECONCILIATION-ROW", 0) + 1
        )
        findings.append(
            finding(
                rule="A1-RECONCILIATION-ROW",
                key_class="obligation-decision",
                key_fields={"obligation": obligation, "decision": decision},
                message=(
                    f"Reconciliation row {row.get('ledger_pointer')}: obligation "
                    f"{obligation}; decision {decision}; old_state "
                    f"{row.get('old_state')}; new_state {row.get('new_state')}."
                ),
                level="note",
                level_basis="native-reconciliation-row",
                record=record,
                record_sha256=sha,
                locator=f"rows[{index}]",
                candidate=candidate,
                subject_uri=None,
                subject_digest=None,
                digest_scope="record",
                native_fields={
                    key: row[key]
                    for key in (
                        "ledger_pointer",
                        "obligation",
                        "ledger_claim",
                        "decision",
                        "why_not_discharge_wrong",
                        "old_state",
                        "new_state",
                        "evidence_level",
                        "retained",
                        "note",
                    )
                    if key in row
                },
                extra_properties={"locationKind": "record-condition"},
            )
        )

    limits = doc.get("limits") or {}
    evidence_level = limits.get("evidence_level")
    if evidence_level:
        count_by_rule["A1-RECONCILIATION-LIMIT"] = 1
        findings.append(
            finding(
                rule="A1-RECONCILIATION-LIMIT",
                key_class="literal",
                key_fields={"value": "limits"},
                message=(
                    f"Reconciliation evidence level: {evidence_level}. Native not "
                    f"claimed: {limits.get('not_claimed', '')}".rstrip()
                ),
                level="warning",
                level_basis="native-declared-evidence-level",
                record=record,
                record_sha256=sha,
                locator="limits",
                candidate=candidate,
                subject_uri=None,
                subject_digest=None,
                digest_scope="record",
                native_fields=dict(limits),
                extra_properties={"locationKind": "record-condition"},
            )
        )

    return {
        "record": record,
        "sha256": sha,
        "schema": doc.get("schema"),
        "candidate": candidate,
        "findings": findings,
        "projection": {
            "nativePopulation": {"rows": len(rows)},
            "projected": count_by_rule,
            "notProjected": [
                {
                    "block": "conflict / cross_check / closure_evidence_quality_note",
                    "count": 3,
                    "reason": "reviewer narrative around the reconciled rows; not finding rows",
                }
            ],
            "sumMatchesPopulation": True,
        },
        "non_claims": [],
    }


SOURCES = {
    "reconciliation": _project_reconciliation,
    "adjudication": _project_adjudication,
    "curl": _project_curl,
    "safety": _project_safety,
    "secrets": _project_secrets,
    "timing": _project_timing,
}


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------

def _artifact_entry(uri: str, digest: str | None, digest_scope: str, roles: list) -> dict:
    entry = {"location": {"uri": uri}, "roles": roles}
    if digest is not None:
        entry["hashes"] = {"sha-256": digest}
    entry["properties"] = {"a1": {"digestScope": digest_scope}}
    return entry


def _identity_for_item(item: dict) -> finding_identity.Finding:
    """Bind a projected finding to the model's three identities."""
    subject = item["subject"]
    try:
        binding = finding_identity.Binding(
            subject["uri"], str(subject["digest"]), subject["digest_scope"]
        )
        region = finding_identity.Region.from_native(
            path=item["path"],
            line=item["line"],
            byte_offset=item["byte_offset"],
            address=item["address"],
            locator=item["locator"],
        )
        return finding_identity.Finding(
            rule_id=item["rule"],
            logical_key=item["logical_key"],
            binding=binding,
            region=region,
            candidate=item["candidate"],
            key_class=item["key_class"],
            native_locator=item["locator"],
        )
    except finding_identity.IdentityRefusal as exc:
        raise Refusal(R_EMISSION, f"{item['record']}: {exc.detail}") from exc


def _build_result(item: dict, rule_index: dict, artifact_index: dict) -> dict:
    subject = item["subject"]
    identity = _identity_for_item(item)

    result = {
        "ruleId": item["rule"],
        "ruleIndex": rule_index[item["rule"]],
        "kind": _KIND_FOR_LEVEL[item["level"]],
        "level": item["level"],
        "message": {"text": item["message"]},
        "partialFingerprints": {
            finding_identity.WIRE_KEYS["rule"]: identity.rule_fingerprint,
            finding_identity.WIRE_KEYS["logical"]: identity.logical_fingerprint,
            finding_identity.WIRE_KEYS["exact"]: identity.exact_fingerprint,
        },
        "properties": {
            "a1": {
                "candidate": item["candidate"],
                "artifact": {
                    "uri": subject["uri"],
                    "digestScope": subject["digest_scope"],
                    "algorithm": subject["algorithm"],
                    "digest": subject["digest"],
                },
                "native": {
                    "record": item["record"],
                    "recordSha256": item["record_sha256"],
                    "locator": item["locator"],
                    "fields": item["native_fields"],
                },
                "levelBasis": item["level_basis"],
                "logicalKey": item["logical_key"],
            }
        },
    }
    if item["limitations"]:
        result["properties"]["a1"]["limitations"] = list(item["limitations"])
    for key, value in item["extra_properties"].items():
        result["properties"]["a1"][key] = value

    locations = []
    if item["path"] is not None and item["line"] is not None:
        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": item["path"],
                        "uriBaseId": "SRCROOT",
                        "index": artifact_index[item["path"]],
                    },
                    "region": {"startLine": item["line"]},
                },
                "message": {
                    "text": (
                        "line-only region: the native record does not record a "
                        "column or an extent for this finding"
                    )
                },
            }
        )
        result["properties"]["a1"]["locationPrecision"] = "line"
    elif item["byte_offset"] is not None:
        physical = {
            "artifactLocation": {
                "uri": subject["uri"],
                "index": artifact_index[subject["uri"]],
            },
            "region": {"byteOffset": item["byte_offset"]},
            "address": {
                "absoluteAddress": item["address"],
                "kind": item["address_kind"],
            },
        }
        if item["byte_length"] is not None:
            physical["region"]["byteLength"] = item["byte_length"]
            physical["address"]["length"] = item["byte_length"]
        locations.append(
            {
                "physicalLocation": physical,
                "message": {
                    "text": (
                        "binary region: a byte offset in the named artefact; no "
                        "source line and no extent are recorded unless "
                        "extentRecorded is true"
                    )
                },
            }
        )
        result["properties"]["a1"]["locationPrecision"] = (
            "function-offset-and-extent"
            if item["byte_length"] is not None
            else "byte-offset-in-artifact"
        )
        result["properties"]["a1"]["lineInfoAvailable"] = False
    else:
        result["properties"]["a1"]["locationKind"] = "record-condition"

    if locations:
        result["locations"] = locations
    if item["related"]:
        # Resolve artifact indices for related locations in this run.
        related = []
        for rel in item["related"]:
            rel = json.loads(json.dumps(rel))
            rel_location = rel["physicalLocation"].get("artifactLocation") or {}
            if "index" in rel_location:
                rel_location["index"] = artifact_index[subject["uri"]]
            related.append(rel)
        result["relatedLocations"] = related
    return result


def _run_for(meta: dict, adapter_digest: str) -> dict:
    record = meta["record"]
    findings = meta["findings"]

    artifact_specs: dict[str, tuple] = {
        record: (meta["sha256"], "record", ["conversionSource"])
    }
    for item in findings:
        subject = item["subject"]
        if subject["uri"] == record:
            continue
        digest = subject["digest"] if subject["digest_scope"] == "artifact" else None
        artifact_specs[subject["uri"]] = (digest, subject["digest_scope"], ["analysisTarget"])

    artifacts = [
        _artifact_entry(uri, spec[0], spec[1], spec[2])
        for uri, spec in sorted(artifact_specs.items())
    ]
    artifact_index = {entry["location"]["uri"]: i for i, entry in enumerate(artifacts)}

    used_rules = sorted({item["rule"] for item in findings})
    rule_index = {rid: i for i, rid in enumerate(used_rules)}
    rules = []
    for rid in used_rules:
        rule = RULE_BY_ID[rid]
        rules.append(
            {
                "id": rule["id"],
                "name": rule["name"],
                "shortDescription": {"text": rule["short"]},
                "fullDescription": {"text": rule["full"]},
                "defaultConfiguration": {"level": rule["level"]},
            }
        )

    results = [
        _build_result(item, rule_index, artifact_index)
        for item in findings
    ]
    results.sort(
        key=lambda r: (
            r["ruleId"],
            r["partialFingerprints"]["a1Exact/v1"],
            r["partialFingerprints"]["a1Logical/v1"],
            r["properties"]["a1"]["native"]["record"],
            r["properties"]["a1"]["native"]["locator"],
            r["message"]["text"],
        )
    )

    identity_records = [identity_from_result(result) for result in results]
    collision_report = finding_identity.collision_report(identity_records, "exact")
    collision_list = [
        {
            "fingerprint": group["fingerprint"],
            "ruleId": group["ruleIds"][0],
            "locators": [member["nativeLocator"] for member in group["members"]],
            "count": group["count"],
        }
        for group in collision_report["groups"]
    ]

    rule_counts: dict[str, int] = {}
    level_counts: dict[str, int] = {}
    for result in results:
        rule_counts[result["ruleId"]] = rule_counts.get(result["ruleId"], 0) + 1
        level_counts[result["level"]] = level_counts.get(result["level"], 0) + 1

    projection = dict(meta["projection"])
    projection["projected"] = dict(sorted(rule_counts.items()))
    projection["projectedTotal"] = len(results)
    projection["notProjected"] = sorted(
        projection.get("notProjected") or [], key=lambda entry: entry["block"]
    )

    return {
        "tool": {
            "driver": {
                "name": ADAPTER_NAME,
                "fullName": f"{ADAPTER_NAME} {ADAPTER_VERSION}",
                "semanticVersion": ADAPTER_VERSION,
                "version": ADAPTER_VERSION,
                "fullDescription": {
                    "text": (
                        "Projects the fields of the native record "
                        f"{record} into SARIF 2.1.0 under docs/SARIF-PROFILE.md."
                    )
                },
                "rules": rules,
            }
        },
        "invocations": [{"executionSuccessful": True, "exitCode": 0}],
        "columnKind": "unicodeCodePoints",
        "originalUriBaseIds": {
            "SRCROOT": {
                "uri": "file:///",
                "description": {
                    "text": (
                        "Repository root. URIs are relative references; the base "
                        "is a placeholder and is not interpreted as a host path."
                    )
                },
            }
        },
        "artifacts": artifacts,
        "results": results,
        "properties": {
            "a1": {
                "record": {"path": record, "sha256": meta["sha256"], "schema": meta["schema"]},
                "candidate": meta["candidate"],
                "projection": projection,
                "levelCounts": dict(sorted(level_counts.items())),
                "adapter": {
                    "path": "forensics/tools/sarif_adapter.py",
                    "sha256": adapter_digest,
                },
                "fingerprintCollisions": len(collision_list),
                "fingerprintCollisionList": collision_list,
                "nativeNonClaims": list(meta.get("non_claims") or []),
                "consumerRules": [
                    "a fingerprint never authorises reuse across artefacts",
                    "a fingerprint never authorises reuse across candidates",
                    "equal fingerprints are identity, not state or verdict",
                    "a collision is treated as a set, never merged or dropped",
                    "absence of a result is not absence of a defect; completeness is A5",
                    "level is a native disposition class, not a severity or probability",
                    "kind=informational does not mean safe, fixed or discharged",
                    "a record-level verdict does not summarise the rest of the record",
                ],
            }
        },
    }


def build_document(repo_root: Path, sources: list[str] | None = None) -> dict:
    """Build the SARIF document. Raises Refusal on any refusal condition."""
    repo_root = Path(repo_root)
    adapter_path = Path(__file__).resolve()
    try:
        adapter_digest = _sha256_bytes(adapter_path.read_bytes())
    except OSError as exc:
        raise Refusal(R_SOURCE_UNREADABLE, f"adapter source: {exc}") from exc

    names = sources or sorted(SOURCES)
    metas = []
    for name in names:
        if name not in SOURCES:
            raise Refusal(R_SHAPE, f"unknown source {name!r}")
        metas.append(SOURCES[name](repo_root))
    metas.sort(key=lambda meta: meta["record"])

    runs = [_run_for(meta, adapter_digest) for meta in metas]
    document = {
        "version": SARIF_VERSION,
        "$schema": SCHEMA_URI,
        "runs": runs,
    }
    validate_emission(
        document,
        native_populations={meta["record"]: len(meta["findings"]) for meta in metas},
    )
    return document


# --------------------------------------------------------------------------
# Structural validation (profile section 13)
# --------------------------------------------------------------------------

def _walk_forbidden(node, path="") -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "properties":
                # Property bags may carry native field names of any spelling.
                continue
            if key in FORBIDDEN_KEYS:
                raise Refusal(
                    R_EMISSION, f"forbidden field {key!r} at {path or '<root>'}"
                )
            _walk_forbidden(value, f"{path}/{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            _walk_forbidden(value, f"{path}/{i}")


def _check_uri(uri: str, where: str) -> None:
    if not isinstance(uri, str) or not uri:
        raise Refusal(R_EMISSION, f"{where}: missing artifact uri")
    if uri.startswith("/") or ".." in uri.split("/") or ":" in uri:
        raise Refusal(R_EMISSION, f"{where}: non-relative artifact uri {uri!r}")


def _counts_by(results: list, key: str) -> dict:
    counts: dict = {}
    for result in results:
        value = result.get(key)
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def validate_emission(document: dict, native_populations: dict[str, int] | None = None) -> None:
    """Refuse a document that violates the profile's structural rules.

    The emission's population statement is checked, not trusted.  The result
    count must equal ``properties.a1.projection.projectedTotal``, the
    per-rule ``projection.projected`` tallies and the per-level
    ``levelCounts`` tallies must equal the results actually present, and when
    the caller supplies ``native_populations`` (record path -> the number of
    findings the native record projects) the result count must equal the
    record's own population.  A dropped or added result therefore cannot pass
    while its declared totals still describe the original emission.

    Every population refusal uses ``SARIF_REFUSED_POPULATION_MISMATCH``.
    """
    _walk_forbidden(document)

    if document.get("version") != SARIF_VERSION:
        raise Refusal(R_EMISSION, "version is not '2.1.0'")
    if document.get("$schema") != SCHEMA_URI:
        raise Refusal(R_EMISSION, "$schema is not the Errata 01 schema URI")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise Refusal(R_EMISSION, "runs is not a non-empty array")

    previous_record = None
    for run_index, run in enumerate(runs):
        where = f"runs[{run_index}]"
        driver = (run.get("tool") or {}).get("driver") or {}
        if not driver.get("name"):
            raise Refusal(R_EMISSION, f"{where}: tool.driver.name is absent")
        invocations = run.get("invocations") or []
        if not invocations or invocations[0].get("executionSuccessful") is not True:
            raise Refusal(R_EMISSION, f"{where}: invocation executionSuccessful is not true")
        if run.get("columnKind") not in ("utf16CodeUnits", "unicodeCodePoints"):
            raise Refusal(R_EMISSION, f"{where}: columnKind is missing or unknown")

        props = (run.get("properties") or {}).get("a1") or {}
        record = (props.get("record") or {}).get("path")
        if not record:
            raise Refusal(R_EMISSION, f"{where}: properties.a1.record.path is absent")
        if previous_record is not None and record <= previous_record:
            raise Refusal(R_EMISSION, f"{where}: runs are not in record-path order")
        previous_record = record
        if not props.get("candidate"):
            raise Refusal(R_EMISSION, f"{where}: properties.a1.candidate is absent")
        for field in ("projection", "consumerRules", "fingerprintCollisions", "adapter"):
            if field not in props:
                raise Refusal(R_EMISSION, f"{where}: properties.a1.{field} is absent")

        artifacts = run.get("artifacts") or []
        uris = []
        for i, artifact in enumerate(artifacts):
            uri = (artifact.get("location") or {}).get("uri")
            _check_uri(uri, f"{where}/artifacts[{i}]")
            uris.append(uri)
            digest = (artifact.get("hashes") or {}).get("sha-256")
            if digest is not None and not _HEX64.match(str(digest)):
                raise Refusal(R_EMISSION, f"{where}/artifacts[{i}]: digest is not sha256 hex")
        if uris != sorted(uris):
            raise Refusal(R_EMISSION, f"{where}: artifacts are not sorted by uri")
        if record not in uris:
            raise Refusal(R_EMISSION, f"{where}: the native record is not in artifacts")

        rules = driver.get("rules") or []
        rule_ids = [rule.get("id") for rule in rules]
        if rule_ids != sorted(rule_ids):
            raise Refusal(R_EMISSION, f"{where}: rules are not sorted by id")
        for rule in rules:
            if rule.get("id") not in RULE_BY_ID:
                raise Refusal(R_EMISSION, f"{where}: rule {rule.get('id')!r} is not registered")

        results = run.get("results")
        if not isinstance(results, list):
            raise Refusal(R_EMISSION, f"{where}: results is absent")
        for i, result in enumerate(results):
            if not isinstance(result, dict):
                raise Refusal(R_EMISSION, f"{where}/results[{i}]: result is not an object")

        projection = props.get("projection")
        if not isinstance(projection, dict):
            raise Refusal(R_EMISSION, f"{where}: properties.a1.projection is absent")
        declared_total = projection.get("projectedTotal")
        if isinstance(declared_total, bool) or not isinstance(declared_total, int):
            raise Refusal(
                R_POPULATION,
                f"{where}: projection.projectedTotal is not an integer",
            )
        if declared_total != len(results):
            raise Refusal(
                R_POPULATION,
                f"{where}: projection.projectedTotal is {declared_total} but "
                f"run.results has {len(results)}",
            )
        projected = projection.get("projected")
        if not isinstance(projected, dict):
            raise Refusal(R_POPULATION, f"{where}: projection.projected is absent")
        for key, value in projected.items():
            if not isinstance(key, str) or isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise Refusal(
                    R_EMISSION,
                    f"{where}: projection.projected[{key!r}] is not a non-negative integer",
                )
        actual_rules = _counts_by(results, "ruleId")
        declared_rules = dict(sorted(projected.items()))
        if sum(declared_rules.values()) != len(results):
            raise Refusal(
                R_POPULATION,
                f"{where}: projection.projected sums to "
                f"{sum(declared_rules.values())} but run.results has {len(results)}",
            )
        if declared_rules != actual_rules:
            raise Refusal(
                R_POPULATION,
                f"{where}: projection.projected {declared_rules} does not match "
                f"the emitted results {actual_rules}",
            )
        level_counts = props.get("levelCounts")
        if level_counts is not None:
            if not isinstance(level_counts, dict):
                raise Refusal(R_EMISSION, f"{where}: levelCounts is not an object")
            for key, value in level_counts.items():
                if not isinstance(key, str) or isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise Refusal(
                        R_EMISSION,
                        f"{where}: levelCounts[{key!r}] is not a non-negative integer",
                    )
            actual_levels = _counts_by(results, "level")
            declared_levels = dict(sorted(level_counts.items()))
            if declared_levels != actual_levels:
                raise Refusal(
                    R_POPULATION,
                    f"{where}: levelCounts {declared_levels} does not match the "
                    f"emitted results {actual_levels}",
                )
        if native_populations is not None:
            expected_native = native_populations.get(record)
            if isinstance(expected_native, bool) or not isinstance(expected_native, int):
                raise Refusal(
                    R_POPULATION,
                    f"{where}: no native population was supplied for {record!r}",
                )
            if expected_native != len(results):
                raise Refusal(
                    R_POPULATION,
                    f"{where}: {record} projects {expected_native} native findings "
                    f"but the run emits {len(results)} results",
                )

        for i, result in enumerate(results):
            rwhere = f"{where}/results[{i}]"
            rid = result.get("ruleId")
            index = result.get("ruleIndex")
            if rid not in rule_ids:
                raise Refusal(R_EMISSION, f"{rwhere}: ruleId {rid!r} is not in the run")
            if not isinstance(index, int) or not 0 <= index < len(rules):
                raise Refusal(R_EMISSION, f"{rwhere}: ruleIndex out of range")
            if rules[index].get("id") != rid:
                raise Refusal(R_EMISSION, f"{rwhere}: ruleIndex does not name ruleId")
            level = result.get("level")
            kind = result.get("kind")
            if level not in _KIND_FOR_LEVEL:
                raise Refusal(R_EMISSION, f"{rwhere}: level {level!r} is unknown")
            if kind != _KIND_FOR_LEVEL[level]:
                raise Refusal(R_EMISSION, f"{rwhere}: kind {kind!r} does not match level")
            if not ((result.get("message") or {}).get("text")):
                raise Refusal(R_EMISSION, f"{rwhere}: message.text is absent")

            fingerprints = result.get("partialFingerprints") or {}
            if set(fingerprints) != {"a1Rule/v1", "a1Logical/v1", "a1Exact/v1"}:
                raise Refusal(R_EMISSION, f"{rwhere}: partialFingerprints keys are wrong")
            for key, value in fingerprints.items():
                if not _HEX64.match(str(value)):
                    raise Refusal(R_EMISSION, f"{rwhere}: {key} is not sha256 hex")

            a1 = (result.get("properties") or {}).get("a1") or {}
            if not a1.get("candidate"):
                raise Refusal(R_EMISSION, f"{rwhere}: candidate is absent")
            artifact = a1.get("artifact") or {}
            if not artifact.get("uri") or not artifact.get("digestScope"):
                raise Refusal(R_EMISSION, f"{rwhere}: artifact binding is incomplete")
            algorithm = artifact.get("algorithm")
            digest = str(artifact.get("digest", ""))
            if algorithm == "sha-256":
                if not _HEX64.match(digest):
                    raise Refusal(R_EMISSION, f"{rwhere}: artifact digest is not sha256 hex")
            elif algorithm == "sha1-git-object":
                if not _HEX40.match(digest):
                    raise Refusal(R_EMISSION, f"{rwhere}: git object id is not 40 hex")
            else:
                raise Refusal(R_EMISSION, f"{rwhere}: unknown artifact digest algorithm")
            native = a1.get("native") or {}
            for field in ("record", "recordSha256", "locator", "fields"):
                if field not in native:
                    raise Refusal(R_EMISSION, f"{rwhere}: native.{field} is absent")
            if native["record"] != record:
                raise Refusal(R_EMISSION, f"{rwhere}: native.record is not the run record")
            if a1.get("levelBasis") in (None, ""):
                raise Refusal(R_EMISSION, f"{rwhere}: levelBasis is absent")
            if artifact["uri"] not in uris:
                raise Refusal(
                    R_EMISSION, f"{rwhere}: artifact {artifact['uri']!r} is not in run.artifacts"
                )

            for location in result.get("locations") or []:
                physical = location.get("physicalLocation") or {}
                region = physical.get("region") or {}
                has_line = "startLine" in region
                has_byte = "byteOffset" in region
                if not (has_line or has_byte):
                    raise Refusal(R_EMISSION, f"{rwhere}: region has neither startLine nor byteOffset")
                if has_line and has_byte:
                    raise Refusal(R_EMISSION, f"{rwhere}: region mixes text and binary properties")
                if has_line and "startLine" not in region:
                    raise Refusal(R_EMISSION, f"{rwhere}: text region without startLine")
                loc = physical.get("artifactLocation") or {}
                if loc.get("uri") not in uris:
                    raise Refusal(R_EMISSION, f"{rwhere}: location artifact is not listed")
                if "index" in loc and not (0 <= loc["index"] < len(uris)):
                    raise Refusal(R_EMISSION, f"{rwhere}: artifact index out of range")
                address = physical.get("address") or {}
                if address and not isinstance(address.get("absoluteAddress"), int):
                    raise Refusal(R_EMISSION, f"{rwhere}: address absoluteAddress is not an integer")
                if "byteLength" in region and address.get("length") != region["byteLength"]:
                    raise Refusal(R_EMISSION, f"{rwhere}: region and address lengths disagree")


# --------------------------------------------------------------------------
# Consumer helper
# --------------------------------------------------------------------------

def identity_from_result(result: dict) -> finding_identity.Finding:
    """Reconstruct the model's identity from an emitted SARIF result.

    The reconstruction is an integrity check, not a convenience: every recorded
    fingerprint must equal the model's recomputation from the result's own native
    fields, artefact binding and region. A result that fails the check is refused,
    because a consumer may not act on a fingerprint the model does not derive.
    """
    a1 = ((result.get("properties") or {}).get("a1")) or {}
    artifact = a1.get("artifact") or {}
    native = a1.get("native") or {}
    try:
        binding = finding_identity.Binding(
            str(artifact.get("uri", "")),
            str(artifact.get("digest", "")),
            str(artifact.get("digestScope", "")),
        )
        physical = ((result.get("locations") or [{}])[0]).get("physicalLocation") or {}
        region_data = physical.get("region") or {}
        address = (physical.get("address") or {}).get("absoluteAddress")
        if "startLine" in region_data:
            region = finding_identity.Region("source", line=region_data["startLine"])
        elif "byteOffset" in region_data:
            region = finding_identity.Region(
                "binary", byte_offset=region_data["byteOffset"], address=address
            )
        else:
            region = finding_identity.Region("record", locator=str(native["locator"]))
        finding = finding_identity.Finding(
            rule_id=str(result["ruleId"]),
            logical_key=str(a1["logicalKey"]),
            binding=binding,
            region=region,
            candidate=a1.get("candidate"),
            native_locator=str(native["locator"]),
        )
    except (KeyError, IndexError) as exc:
        raise Refusal(R_EMISSION, f"result is not reconstructable: {exc}") from exc
    except finding_identity.IdentityRefusal as exc:
        raise Refusal(R_EMISSION, f"result identity is not reconstructable: {exc.detail}") from exc

    recorded = result.get("partialFingerprints") or {}
    for wire_key, computed in finding.fingerprints.items():
        if recorded.get(wire_key) != computed:
            raise finding_identity.IdentityRefusal(
                finding_identity.FI_REFUSED_RECORDED_FINGERPRINT_MISMATCH,
                f"{result.get('ruleId')}: recorded {wire_key} does not match the "
                "model's recomputation",
            )
    return finding


def fingerprints_interchangeable(left: dict, right: dict) -> bool:
    """True only when two results are the same occurrence in the same artefact.

    The profile forbids treating fingerprints as interchangeable across
    artefacts: equal rule and logical identities are not enough, and equal exact
    identities in different artefacts are impossible by construction. The check
    is made by the identity model, which also verifies that each result's recorded
    fingerprints are the ones its own fields derive.
    """
    left_identity = identity_from_result(left)
    right_identity = identity_from_result(right)
    return (
        left_identity.fingerprints == right_identity.fingerprints
        and left_identity.binding == right_identity.binding
        and left_identity.candidate_token == right_identity.candidate_token
    )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _serialise(document: dict) -> bytes:
    return (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Project native evidence records into SARIF 2.1.0 under "
            "docs/SARIF-PROFILE.md."
        )
    )
    parser.add_argument("--repo-root", default=".", help="repository root")
    parser.add_argument("--out", help="output SARIF path")
    parser.add_argument(
        "--source",
        action="append",
        choices=sorted(SOURCES),
        help="project only this source (repeatable)",
    )
    parser.add_argument(
        "--print-summary",
        action="store_true",
        help="print per-run result and level counts to stderr",
    )
    args = parser.parse_args(argv)

    try:
        document = build_document(Path(args.repo_root), args.source)
    except Refusal as refusal:
        print(f"{refusal.code}: {refusal.detail}", file=sys.stderr)
        return 2

    payload = _serialise(document)

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        temp = out.with_suffix(out.suffix + ".tmp")
        try:
            temp.write_bytes(payload)
            temp.replace(out)
        finally:
            if temp.exists():
                temp.unlink()

    if args.print_summary:
        for run in document["runs"]:
            props = run["properties"]["a1"]
            counts = props["projection"]["projected"]
            print(
                f"{props['record']['path']}: {len(run['results'])} results "
                f"{json.dumps(counts, sort_keys=True)} "
                f"levels={json.dumps(props['levelCounts'], sort_keys=True)}",
                file=sys.stderr,
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
