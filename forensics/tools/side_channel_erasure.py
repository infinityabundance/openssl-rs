#!/usr/bin/env python3
"""ETP-T7 side-channel and erasure validator.

Three checks are implemented here:

* the secret-classification register (`SECRETS.json`) is structurally sound and
  every cited source location exists with its stated token nearby;
* the erasure audit (`ERASURE-AUDIT.json`) is structurally sound, every finding
  refers to a register entry, and every register entry whose cleansing
  obligation is unmet is covered by a finding;
* the preregistration document carries the required fields and a usable
  geometry, control set, exclusion set and stopping conditions.

It also adjudicates a small typed-claim document against six refusal rules. A
claim that over-states its evidence is refused by name; the rule number and the
missing element are reported. `--self-test` runs one positive and one negative
control per rule and a set of register/audit mutation controls.

Run inside the court:

    python3 forensics/tools/side_channel_erasure.py validate --repo-root .
    python3 forensics/tools/side_channel_erasure.py check-claims --claims FILE
    python3 forensics/tools/side_channel_erasure.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CLASSES = [
    "PUBLIC_DATA",
    "SECRET_DATA",
    "SECRET_DEPENDENT_CONTROL",
    "CLEANSING_REQUIRED",
    "DECLASSIFICATION_BOUNDARY",
]
EVIDENCE_KINDS = {
    "ctgrind",
    "dudect",
    "test",
    "branch-audit",
    "source-contract",
    "design-note",
    "source-audit",
}
ERASURE_CLASSES = [
    "FREED_WITHOUT_CLEANSING",
    "LENGTH_ONLY_CLEANSE",
    "FAILURE_PATH_WITHOUT_CLEANSING",
    "LOST_CLEAR_FREE_ARM",
]
SEVERITIES = ["HIGH", "MEDIUM", "LOW"]
STATUSES = ["PROSPECTIVE", "RECONSTRUCTED_POST_HOC"]

SECRETS_SCHEMA = "openssl-rs/etp-t7/secrets/1"
ERASURE_SCHEMA = "openssl-rs/etp-t7/erasure-audit/1"
PREREG_SCHEMA = "openssl-rs/etp-t7/preregistration/1"

# Claim refusal codes, one per required rule.
R1 = "CT_T_WITHOUT_PREREGISTERED_GEOMETRY"
R2 = "CTGRIND_WITHOUT_HARNESS_IDENTITY_TAINT"
R3 = "DEBUG_BINARY_GENERALISED_TO_RELEASE"
R4 = "SECRET_DEPENDENT_CONTROL_WITHOUT_EVIDENCE"
R5 = "EXCLUSIONS_CHANGED_AFTER_RUN"
R6 = "DUDECT_STATE_1_TREATED_AS_PROOF"


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _check_source(source: dict, repo_root: Path) -> list[tuple[str, str]]:
    problems: list[tuple[str, str]] = []
    for key in ("path", "line", "symbol", "token"):
        if key not in source:
            problems.append(("SE_MISSING_SOURCE", f"source is missing {key!r}"))
    if problems:
        return problems
    path = repo_root / source["path"]
    if not path.is_file():
        return [("SE_MISSING_SOURCE", f"{source['path']} does not exist")]
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    line = source["line"]
    if not isinstance(line, int) or not 1 <= line <= len(lines):
        return [("SE_MISSING_SOURCE", f"{source['path']}:{line} is outside the file")]
    window = "\n".join(lines[max(0, line - 4):line + 3])
    if source["token"] not in window:
        return [
            (
                "SE_SOURCE_TOKEN",
                f"{source['path']}:{line} does not contain {source['token']!r} within 3 lines",
            )
        ]
    return problems


def validate_secrets(doc: dict, repo_root: Path) -> list[tuple[str, str]]:
    problems: list[tuple[str, str]] = []
    if doc.get("schema") != SECRETS_SCHEMA:
        problems.append(("SE_BAD_SCHEMA", f"schema is {doc.get('schema')!r}"))
    entries = doc.get("entries")
    if not isinstance(entries, list) or not entries:
        return problems + [("SE_BAD_SCHEMA", "entries must be a non-empty list")]

    seen: set[str] = set()
    for entry in entries:
        ident = entry.get("id")
        if not isinstance(ident, str) or not ident:
            problems.append(("SE_DUPLICATE_ID", "an entry has no id"))
            continue
        if ident in seen:
            problems.append(("SE_DUPLICATE_ID", f"duplicate id {ident}"))
        seen.add(ident)
        cls = entry.get("class")
        if cls not in CLASSES:
            problems.append(("SE_UNKNOWN_CLASS", f"{ident}: class {cls!r}"))
        for key in ("item", "owner", "note"):
            if not isinstance(entry.get(key), str) or not entry[key]:
                problems.append(("SE_BAD_SCHEMA", f"{ident}: missing {key}"))
        problems.extend((code, f"{ident}: {msg}") for code, msg in _check_source(entry.get("source", {}), repo_root))
        obligation = entry.get("cleansing_obligation")
        if not isinstance(obligation, dict):
            problems.append(("SE_BAD_SCHEMA", f"{ident}: cleansing_obligation must be an object"))
        else:
            for key, kind in (("required", bool), ("extent", str), ("mechanism", str), ("met", bool)):
                if not isinstance(obligation.get(key), kind):
                    problems.append(("SE_BAD_SCHEMA", f"{ident}: cleansing_obligation.{key}"))
        evidence = entry.get("evidence")
        if evidence != "NONE":
            if not isinstance(evidence, dict):
                problems.append(("SE_BAD_SCHEMA", f"{ident}: evidence must be 'NONE' or an object"))
            else:
                if evidence.get("kind") not in EVIDENCE_KINDS:
                    problems.append(("SE_EVIDENCE_KIND", f"{ident}: evidence.kind {evidence.get('kind')!r}"))
                if not isinstance(evidence.get("reference"), str) or not evidence["reference"]:
                    problems.append(("SE_BAD_SCHEMA", f"{ident}: evidence.reference"))
                if not isinstance(evidence.get("result"), str) or not evidence["result"]:
                    problems.append(("SE_BAD_SCHEMA", f"{ident}: evidence.result"))

    counts = {cls: sum(1 for entry in entries if entry.get("class") == cls) for cls in CLASSES}
    if doc.get("counts") != counts:
        problems.append(("SE_COUNT_MISMATCH", f"declared {doc.get('counts')!r}, derived {counts!r}"))

    sdc_none = [
        entry["id"]
        for entry in entries
        if entry.get("class") == "SECRET_DEPENDENT_CONTROL" and entry.get("evidence") == "NONE"
    ]
    if doc.get("secret_dependent_control_without_evidence") != sdc_none:
        problems.append(
            (
                "SE_DERIVED_MISMATCH",
                "secret_dependent_control_without_evidence does not match the entries",
            )
        )

    unmet = [
        entry["id"]
        for entry in entries
        if (entry.get("cleansing_obligation") or {}).get("required") is True
        and (entry.get("cleansing_obligation") or {}).get("met") is False
    ]
    if doc.get("secret_bearing_without_cleansing") != unmet:
        problems.append(
            ("SE_DERIVED_MISMATCH", "secret_bearing_without_cleansing does not match the entries")
        )
    return problems


def validate_erasure(doc: dict, secrets: dict, repo_root: Path) -> list[tuple[str, str]]:
    problems: list[tuple[str, str]] = []
    if doc.get("schema") != ERASURE_SCHEMA:
        problems.append(("ER_BAD_SCHEMA", f"schema is {doc.get('schema')!r}"))
    findings = doc.get("findings")
    if not isinstance(findings, list) or not findings:
        return problems + [("ER_BAD_SCHEMA", "findings must be a non-empty list")]

    secret_ids = {entry.get("id") for entry in secrets.get("entries", [])}
    seen: set[str] = set()
    referenced: set[str] = set()
    for finding in findings:
        ident = finding.get("id")
        if not isinstance(ident, str) or not ident or ident in seen:
            problems.append(("ER_BAD_SCHEMA", f"bad or duplicate finding id {ident!r}"))
            continue
        seen.add(ident)
        if finding.get("class") not in ERASURE_CLASSES:
            problems.append(("ER_BAD_CLASS", f"{ident}: class {finding.get('class')!r}"))
        if finding.get("severity") not in SEVERITIES:
            problems.append(("ER_BAD_SEVERITY", f"{ident}: severity {finding.get('severity')!r}"))
        for key in ("item", "impact", "authority_behaviour", "repair"):
            if not isinstance(finding.get(key), str) or not finding[key]:
                problems.append(("ER_MISSING_REPAIR" if key == "repair" else "ER_BAD_SCHEMA", f"{ident}: {key}"))
        if finding.get("repaired") is not False:
            problems.append(
                ("ER_BAD_SCHEMA", f"{ident}: this item records gaps and must set repaired=false")
            )
        problems.extend((code, f"{ident}: {msg}") for code, msg in _check_source(finding.get("source", {}), repo_root))
        refs = finding.get("secrets")
        if not isinstance(refs, list) or not refs:
            problems.append(("ER_UNKNOWN_SECRET_REF", f"{ident}: no secret references"))
        else:
            for ref in refs:
                if ref not in secret_ids:
                    problems.append(("ER_UNKNOWN_SECRET_REF", f"{ident}: {ref!r} is not in SECRETS"))
                referenced.add(ref)
        evidence = finding.get("evidence")
        if not isinstance(evidence, dict) or evidence.get("kind") not in EVIDENCE_KINDS:
            problems.append(("ER_BAD_SCHEMA", f"{ident}: evidence.kind"))

    for entry in secrets.get("entries", []):
        obligation = entry.get("cleansing_obligation") or {}
        if obligation.get("required") is True and obligation.get("met") is False:
            if entry.get("id") not in referenced:
                problems.append(
                    ("ER_UNCOVERED_OBLIGATION", f"{entry.get('id')} is unmet but no finding cites it")
                )

    summary = doc.get("summary") or {}
    by_class = {cls: sum(1 for finding in findings if finding.get("class") == cls) for cls in ERASURE_CLASSES}
    by_sev = {sev: sum(1 for finding in findings if finding.get("severity") == sev) for sev in SEVERITIES}
    expected = {
        "findings_by_class": by_class,
        "findings_by_severity": by_sev,
        "findings": len(findings),
        "repaired": sum(1 for finding in findings if finding.get("repaired") is True),
        "clear_free_arms_lost": sum(
            1 for finding in findings if finding.get("class") == "LOST_CLEAR_FREE_ARM"
        ),
        "clear_free_arms_checked": len(doc.get("survived_clear_free_arms") or []),
    }
    for key, value in expected.items():
        if summary.get(key) != value:
            problems.append(("ER_SUMMARY_MISMATCH", f"summary.{key}: declared {summary.get(key)!r}, derived {value!r}"))

    for entry in doc.get("survived_clear_free_arms") or []:
        problems.extend(
            (code, f"{entry.get('id')}: {msg}")
            for code, msg in _check_source(entry.get("source", {}), repo_root)
        )
    for entry in doc.get("observations") or []:
        problems.extend(
            (code, f"{entry.get('id')}: {msg}")
            for code, msg in _check_source(entry.get("source", {}), repo_root)
        )
        if not isinstance(entry.get("observation"), str) or not entry["observation"]:
            problems.append(("ER_BAD_SCHEMA", f"{entry.get('id')}: observation"))
    return problems


def validate_prereg(doc: dict) -> list[tuple[str, str]]:
    problems: list[tuple[str, str]] = []
    if doc.get("schema") != PREREG_SCHEMA:
        problems.append(("PR_BAD_SCHEMA", f"schema is {doc.get('schema')!r}"))
    template = doc.get("template")
    if not isinstance(template, dict) or not template.get("required_fields"):
        problems.append(("PR_BAD_SCHEMA", "template.required_fields is required"))
        required: list[str] = []
    else:
        required = template["required_fields"]
    instances = doc.get("instances")
    if not isinstance(instances, list) or not instances:
        return problems + [("PR_BAD_SCHEMA", "instances must be a non-empty list")]
    for instance in instances:
        ident = instance.get("id")
        for key in required:
            if key not in instance:
                problems.append(("PR_MISSING_FIELD", f"{ident}: missing {key}"))
        if instance.get("status") not in STATUSES:
            problems.append(("PR_BAD_STATUS", f"{ident}: status {instance.get('status')!r}"))
        if instance.get("receipt_adapter") not in ("native_v1", "dudect_modes_v1"):
            problems.append(("PR_BAD_SCHEMA", f"{ident}: receipt_adapter"))
        geometry = instance.get("geometry") or {}
        for key in ("per_batch", "max_batches", "runs"):
            value = geometry.get(key)
            if not isinstance(value, int) or value < 1:
                problems.append(("PR_BAD_GEOMETRY", f"{ident}: geometry.{key} must be a positive integer"))
        statistic = instance.get("statistic") or {}
        if not isinstance(statistic.get("per_batch_threshold"), (int, float)):
            problems.append(("PR_BAD_SCHEMA", f"{ident}: statistic.per_batch_threshold"))
        controls = instance.get("controls") or {}
        for key in ("positive", "negative"):
            if not isinstance(controls.get(key), str) or not controls[key]:
                problems.append(("PR_BAD_SCHEMA", f"{ident}: controls.{key}"))
        exclusion_ids = instance.get("exclusion_rule_ids")
        if not isinstance(exclusion_ids, list) or not exclusion_ids:
            problems.append(("PR_BAD_SCHEMA", f"{ident}: exclusion_rule_ids"))
        if not isinstance(instance.get("exclusion_rules"), list) or not instance["exclusion_rules"]:
            problems.append(("PR_BAD_SCHEMA", f"{ident}: exclusion_rules"))
        if not isinstance(instance.get("stopping_conditions"), list) or not instance["stopping_conditions"]:
            problems.append(("PR_BAD_SCHEMA", f"{ident}: stopping_conditions"))
        null_meaning = instance.get("null_result_meaning") or {}
        if not null_meaning.get("means") or not null_meaning.get("does_not_mean"):
            problems.append(("PR_BAD_SCHEMA", f"{ident}: null_result_meaning"))
        if instance.get("status") == "PROSPECTIVE" and not instance.get("registered_at"):
            problems.append(("PR_BAD_SCHEMA", f"{ident}: a prospective instance needs registered_at"))
    return problems


def _claims(doc: dict) -> list[dict]:
    claims = doc.get("claims")
    if not isinstance(claims, list):
        raise ValueError("claims document has no claims list")
    return claims


def _sdc_indexes(secrets: dict) -> tuple[set[str], set[str]]:
    with_evidence: set[str] = set()
    without_evidence: set[str] = set()
    for entry in secrets.get("entries", []):
        if entry.get("class") != "SECRET_DEPENDENT_CONTROL":
            continue
        if entry.get("evidence") == "NONE":
            without_evidence.add(entry["id"])
        else:
            with_evidence.add(entry["id"])
    return with_evidence, without_evidence


def _is_constant_time_assertion(claim: dict) -> bool:
    text = (claim.get("statement") or "").lower()
    return (
        claim.get("kind") in ("constant_time", "constant-time")
        or "constant-time" in text
        or "constant time" in text
    )


def check_claim(
    claim: dict,
    secrets: dict,
    prereg: dict,
) -> list[tuple[str, str]]:
    refusals: list[tuple[str, str]] = []
    evidence = claim.get("evidence") or {}
    scope = claim.get("scope") or {}
    statement = claim.get("statement") or ""

    has_t = any(key in evidence for key in ("t_statistic", "t", "max_abs_t"))
    if _is_constant_time_assertion(claim) and has_t:
        missing = [
            key
            for key in ("preregistration_id", "geometry", "criterion")
            if not evidence.get(key)
        ]
        if missing:
            refusals.append(
                (R1, f"{claim.get('id')}: a t statistic without {', '.join(missing)}")
            )

    if evidence.get("kind") == "ctgrind":
        missing = [
            key
            for key in ("harness", "binary_identity", "tainted_inputs")
            if not evidence.get(key)
        ]
        if "tainted_inputs" in evidence and isinstance(evidence["tainted_inputs"], list) and not evidence["tainted_inputs"]:
            missing.append("tainted_inputs")
        if missing:
            refusals.append(
                (R2, f"{claim.get('id')}: ctgrind claim without {', '.join(sorted(set(missing)))}")
            )

    artefact = (scope.get("artefact") or "").lower()
    debug_artefact = artefact in ("debug", "debug_test_binary", "test_binary", "debug-profile test binary")
    if debug_artefact and (
        scope.get("target") == "release"
        or scope.get("generalises_to_release") is True
        or "release artefact" in statement.lower()
        or "release build" in statement.lower()
    ):
        refusals.append(
            (R3, f"{claim.get('id')}: a debug test binary generalised to the release artefact")
        )

    mechanism = claim.get("mechanism_ref")
    if mechanism:
        with_evidence, without_evidence = _sdc_indexes(secrets)
        if mechanism in without_evidence and _is_constant_time_assertion(claim):
            refusals.append(
                (
                    R4,
                    f"{claim.get('id')}: mechanism {mechanism} is SECRET_DEPENDENT_CONTROL with evidence NONE",
                )
            )
        if mechanism in without_evidence and claim.get("kind") in ("mechanism_safe", "erasure_discharged"):
            refusals.append(
                (
                    R4,
                    f"{claim.get('id')}: mechanism {mechanism} is SECRET_DEPENDENT_CONTROL with evidence NONE",
                )
            )

    if evidence.get("exclusions_changed_after_run") is True:
        refusals.append((R5, f"{claim.get('id')}: the exclusion set changed after the run"))
    prereg_id = evidence.get("preregistration_id") or claim.get("preregistration_id")
    if prereg_id and "exclusions" in evidence:
        instance = next(
            (item for item in prereg.get("instances", []) if item.get("id") == prereg_id),
            None,
        )
        if instance is None:
            refusals.append((R5, f"{claim.get('id')}: unknown preregistration {prereg_id}"))
        else:
            expected = set(instance.get("exclusion_rule_ids") or [])
            actual = set(evidence.get("exclusions") or [])
            if expected and actual != expected:
                refusals.append(
                    (
                        R5,
                        f"{claim.get('id')}: exclusions {sorted(actual)} do not match {sorted(expected)}",
                    )
                )

    if (
        evidence.get("kind") == "dudect"
        and evidence.get("state") == 1
        and (
            str(evidence.get("verdict", "")).upper()
            in ("SAFE", "CONSTANT_TIME", "CONSTANT-TIME", "PASS", "NO_LEAKAGE")
            or _is_constant_time_assertion(claim)
        )
    ):
        refusals.append(
            (
                R6,
                f"{claim.get('id')}: dudect state 1 is treated as proof rather than absence of evidence",
            )
        )
    return refusals


def check_claims(doc: dict, secrets: dict, prereg: dict) -> list[tuple[str, str]]:
    refusals: list[tuple[str, str]] = []
    for claim in _claims(doc):
        refusals.extend(check_claim(claim, secrets, prereg))
    return refusals


def _self_test(repo_root: Path) -> int:
    secrets = load_json(repo_root / "evidence/etp-t7/SECRETS.json")
    erasure = load_json(repo_root / "evidence/etp-t7/ERASURE-AUDIT.json")
    prereg = load_json(repo_root / "evidence/etp-t7/PREREGISTRATION.json")

    failures = 0

    def expect(name: str, got: list[tuple[str, str]], code: str | None) -> None:
        nonlocal failures
        codes = [item[0] for item in got]
        if code is None:
            ok = not got
            detail = "accepted" if ok else f"unexpectedly refused: {got}"
        else:
            ok = code in codes
            detail = f"refused {codes}" if ok else f"did not refuse with {code}: {codes}"
        print(f"CONTROL {name}: {'PASS' if ok else 'FAIL'} ({detail})")
        if not ok:
            failures += 1

    base_claim = {
        "id": "C",
        "kind": "constant_time",
        "statement": "The measured operation is constant-time.",
        "evidence": {
            "kind": "statistical",
            "t_statistic": 1.2,
            "preregistration_id": "ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1",
            "geometry": {"per_batch": 10000, "max_batches": 3},
            "criterion": {"threshold": 10},
            "exclusions": ["EX-1", "EX-2", "EX-3", "EX-4", "EX-5"],
        },
        "scope": {"artefact": "release"},
    }
    # R1 is exercised with a statistical instrument that is not dudect, because
    # R6 independently refuses a constant-time claim built on dudect state 1.
    positive = json.loads(json.dumps(base_claim))
    positive["id"] = "PC-1"
    expect("R1 positive (preregistered geometry and criterion)", check_claim(positive, secrets, prereg), None)

    nc1 = json.loads(json.dumps(base_claim))
    nc1["evidence"].pop("geometry")
    nc1["evidence"].pop("criterion")
    nc1["evidence"].pop("preregistration_id")
    nc1["id"] = "NC-1"
    expect("R1 negative (t without geometry)", check_claim(nc1, secrets, prereg), R1)

    ctgrind_ok = {
        "id": "PC-2",
        "kind": "ctgrind_finding",
        "statement": "A secret-dependent branch was reported in the signing interior.",
        "evidence": {
            "kind": "ctgrind",
            "harness": "courts/phase18/timing/ct_bn.c",
            "binary_identity": "sha256:abc",
            "tainted_inputs": ["nonce", "private scalar"],
        },
        "scope": {"artefact": "test_binary"},
    }
    expect("R2 positive (harness, identity, tainted inputs)", check_claim(ctgrind_ok, secrets, prereg), None)
    nc2 = json.loads(json.dumps(ctgrind_ok))
    nc2["evidence"].pop("tainted_inputs")
    nc2["id"] = "NC-2"
    expect("R2 negative (ctgrind without tainted inputs)", check_claim(nc2, secrets, prereg), R2)

    release_ok = {
        "id": "PC-3",
        "kind": "release_claim",
        "statement": "The release artefact is the measured artefact.",
        "evidence": {"kind": "source-contract", "reference": "x", "result": "OK"},
        "scope": {"artefact": "release", "target": "release"},
    }
    expect("R3 positive (release artefact)", check_claim(release_ok, secrets, prereg), None)
    nc3 = {
        "id": "NC-3",
        "kind": "release_claim",
        "statement": "The release artefact is constant-time.",
        "evidence": {"kind": "source-contract", "reference": "x", "result": "OK"},
        "scope": {"artefact": "debug_test_binary", "target": "release", "generalises_to_release": True},
    }
    expect("R3 negative (debug binary generalised to release)", check_claim(nc3, secrets, prereg), R3)

    mechanism_ok = {
        "id": "PC-4",
        "kind": "mechanism_safe",
        "statement": "The ladder has no secret-dependent address.",
        "evidence": {"kind": "ctgrind", "harness": "h", "binary_identity": "b", "tainted_inputs": ["exponent"]},
        "mechanism_ref": "LADDER-BIT",
        "scope": {"artefact": "test_binary"},
    }
    expect("R4 positive (mechanism with evidence)", check_claim(mechanism_ok, secrets, prereg), None)
    nc4 = {
        "id": "NC-4",
        "kind": "constant_time",
        "statement": "The AES S-box lookup is constant-time.",
        "evidence": {"kind": "source-contract", "reference": "x", "result": "OK"},
        "mechanism_ref": "AES-SBOX",
        "scope": {"artefact": "release"},
    }
    expect("R4 negative (S-D-C with evidence NONE)", check_claim(nc4, secrets, prereg), R4)

    exclusion_ok = json.loads(json.dumps(positive))
    exclusion_ok["id"] = "PC-5"
    expect("R5 positive (exclusions match)", check_claim(exclusion_ok, secrets, prereg), None)
    nc5 = json.loads(json.dumps(positive))
    nc5["id"] = "NC-5"
    nc5["evidence"]["exclusions"] = ["EX-1"]
    expect("R5 negative (exclusions changed)", check_claim(nc5, secrets, prereg), R5)

    dudect_ok = {
        "id": "PC-6",
        "kind": "observation",
        "statement": "No statistically detectable timing class was observed at this geometry.",
        "evidence": {"kind": "dudect", "state": 1, "verdict": "ABSENCE_OF_EVIDENCE_AT_GEOMETRY"},
        "scope": {"artefact": "release"},
    }
    expect("R6 positive (state 1 as absence of evidence)", check_claim(dudect_ok, secrets, prereg), None)
    nc6 = {
        "id": "NC-6",
        "kind": "constant_time",
        "statement": "The operation is constant-time.",
        "evidence": {"kind": "dudect", "state": 1, "verdict": "SAFE"},
        "scope": {"artefact": "release"},
    }
    expect("R6 negative (state 1 as proof)", check_claim(nc6, secrets, prereg), R6)

    expect("secrets register validates", validate_secrets(secrets, repo_root), None)
    expect("erasure audit validates", validate_erasure(erasure, secrets, repo_root), None)
    expect("preregistration validates", validate_prereg(prereg), None)

    mutated = json.loads(json.dumps(secrets))
    mutated["counts"]["SECRET_DATA"] += 1
    expect("count mutation refused", validate_secrets(mutated, repo_root), "SE_COUNT_MISMATCH")

    mutated = json.loads(json.dumps(secrets))
    mutated["entries"][0]["source"]["token"] = "this token is not in the file"
    expect("source-token mutation refused", validate_secrets(mutated, repo_root), "SE_SOURCE_TOKEN")

    mutated = json.loads(json.dumps(erasure))
    mutated["findings"][0]["secrets"] = ["NOT-A-SECRET-ID"]
    expect("unknown secret reference refused", validate_erasure(mutated, secrets, repo_root), "ER_UNKNOWN_SECRET_REF")

    mutated = json.loads(json.dumps(erasure))
    mutated["findings"][0]["repaired"] = True
    expect("repair claim refused", validate_erasure(mutated, secrets, repo_root), "ER_BAD_SCHEMA")

    mutated = json.loads(json.dumps(prereg))
    mutated["instances"][0]["geometry"]["per_batch"] = 0
    expect("bad geometry refused", validate_prereg(mutated), "PR_BAD_GEOMETRY")

    print(f"SELF-TEST {'PASS' if failures == 0 else 'FAIL'} failures={failures}")
    return 0 if failures == 0 else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=["validate", "check-claims"])
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--claims")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    if args.self_test:
        return _self_test(repo_root)
    if args.command == "validate":
        secrets = load_json(repo_root / "evidence/etp-t7/SECRETS.json")
        erasure = load_json(repo_root / "evidence/etp-t7/ERASURE-AUDIT.json")
        prereg = load_json(repo_root / "evidence/etp-t7/PREREGISTRATION.json")
        problems = []
        problems.extend(validate_secrets(secrets, repo_root))
        problems.extend(validate_erasure(erasure, secrets, repo_root))
        problems.extend(validate_prereg(prereg))
        if problems:
            for code, message in problems:
                print(f"{code}: {message}", file=sys.stderr)
            return 1
        print(
            json.dumps(
                {
                    "ok": True,
                    "entries": len(secrets["entries"]),
                    "counts": secrets["counts"],
                    "secret_dependent_control_without_evidence": secrets[
                        "secret_dependent_control_without_evidence"
                    ],
                    "erasure": erasure["summary"],
                    "preregistration_instances": [item["id"] for item in prereg["instances"]],
                },
                sort_keys=True,
            )
        )
        return 0
    if args.command == "check-claims":
        if not args.claims:
            print("check-claims needs --claims FILE", file=sys.stderr)
            return 2
        secrets = load_json(repo_root / "evidence/etp-t7/SECRETS.json")
        prereg = load_json(repo_root / "evidence/etp-t7/PREREGISTRATION.json")
        doc = load_json(Path(args.claims))
        refusals = check_claims(doc, secrets, prereg)
        for code, message in refusals:
            print(f"{code}: {message}", file=sys.stderr)
        if refusals:
            return 1
        print(f"CLAIMS ok ({len(_claims(doc))} accepted)")
        return 0
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
