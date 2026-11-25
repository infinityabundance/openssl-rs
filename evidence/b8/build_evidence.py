#!/usr/bin/env python3
"""Deterministic producer of the B8 records.

The enforcement is declared in ``forensics/tools/continuous_enforcement.py`` and
described in ``docs/CONTINUOUS-ENFORCEMENT.md``.  This producer reads the tool,
the claim schema and the claim document, runs the controls, and writes four
records:

    ENFORCEMENT.json   the gate item, what it refuses, where it is wired, the
                       before/after refusal counts;
    SCHEMA.json        the schema field, its closed enum and the population;
    PENDING.json       the two pending applications and the refused section-10 edit;
    CONTROLS.json      one control per refusal code.

    python3 evidence/b8/build_evidence.py [--out DIR] [--check]

The default output directory is this file's directory.  ``--out`` exists so the
gate can compare two runs; ``--check`` re-derives the records in memory and
compares them with the committed bytes.  No clock, environment variable or
absolute path is written, every array is built in a deterministic order, and two
runs over the same tree reproduce the same bytes.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import continuous_enforcement as ce  # noqa: E402

HERE = Path(__file__).resolve().parent
BASE_COMMIT = "2ed2cd79f"
TOOL = "forensics/tools/continuous_enforcement.py"
GATE = "forensics/tools/release_gate.py"
DOCUMENT = "docs/CONTINUOUS-ENFORCEMENT.md"
NONCLAIMS = "docs/TRANSPARENCY-NON-CLAIMS.md"
SCHEMA = "evidence/etp/claim.schema.json"
CLAIMS = "evidence/etp/claims.json"

#: The gate's refusals at ``BASE_COMMIT``, before item 10 existed, observed with
#: ``python3 forensics/tools/release_gate.py --json``.  The count is 35 rather
#: than the 34 the B8 task statement expected because this venue has no
#: ``valgrind``, so item 4 refuses ``valgrind-ctgrind`` with ``rc=127``.  The
#: record states the observed number and the reason for the difference.
BEFORE_TOTAL = 35
BEFORE_BY_RULE = {
    "RG_AUTHORISATION_REFUSED": 1,
    "RG_CLAIM_HISTORICAL_EVIDENCE": 11,
    "RG_CLAIM_UNCERTIFIABLE_EVIDENCE": 19,
    "RG_INSTRUMENT": 1,
    "RG_PACKAGE_MISSING": 1,
    "RG_POLICY_DENIED": 1,
    "RG_THRESHOLD_UNMET": 1,
}
BEFORE_NOTE = (
    "observed at 2ed2cd79f with item 10 absent; 35, not the expected 34, because "
    "this venue has no valgrind and item 4 refuses valgrind-ctgrind with rc=127"
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_apply_check(patch: Path) -> bool:
    run = subprocess.run(
        ["git", "--no-optional-locks", "apply", "--check", str(patch)],
        cwd=str(REPO),
        text=True,
        capture_output=True,
        timeout=120,
    )
    return run.returncode == 0


def enforcement_record() -> dict[str, Any]:
    """The gate item, its codes, its wiring and the observed/derived counts."""
    provisional = {"refusalCodes": list(ce.REFUSAL_CODES)}
    result = ce.check(enforcement_record=provisional)
    transparency_codes = [finding.code for finding in result.findings]
    by_rule = dict(BEFORE_BY_RULE)
    for code in transparency_codes:
        by_rule[code] = by_rule.get(code, 0) + 1
    return {
        "schema": ce.SCHEMA_ENFORCEMENT,
        "item": "B8",
        "baseCommit": BASE_COMMIT,
        "tool": TOOL,
        "document": DOCUMENT,
        "gate": GATE,
        "gateItem": {
            "number": 10,
            "function": "check_transparency",
            "wiredIn": "release_gate.py evaluate() after item 9",
            "docstringItem": "10. transparency",
            "required": True,
        },
        "gateItems": [
            {"id": number, "label": label, "symbol": symbol}
            for number, label, symbol in ce.GATE_ITEMS
        ],
        "positiveCode": ce.CODE_OK,
        "refusalCodes": list(ce.REFUSAL_CODES),
        "refusals": dict(ce.REFUSALS),
        "wiring": {
            "releaseGate": {
                "path": GATE,
                "item": 10,
                "function": "check_transparency",
                "toolInvocation": "continuous_enforcement.py check --json",
            },
            "claimSchema": {
                "path": SCHEMA,
                "field": "$defs/transparency",
                "requiredWhen": {"authority.kind": ce.TRANSPARENCY_REQUIRED_AUTHORITY},
            },
            "nonClaims": {"path": NONCLAIMS, "checkedBy": "CE_REFUSED_NONCLAIMS_ABSENT"},
            "enforcementRecord": {"path": "evidence/b8/ENFORCEMENT.json"},
            "agents": {
                "path": "forensics/etp8/agents-patch.diff",
                "state": "PENDING_MAINTAINER_APPLICATION",
            },
            "ci": {
                "path": "forensics/etp8/ci-transparency-job.patch",
                "state": "PENDING_CREDENTIAL",
            },
        },
        "refusalCounts": {
            "before": {
                "observedAt": BASE_COMMIT,
                "total": BEFORE_TOTAL,
                "byRule": BEFORE_BY_RULE,
                "note": BEFORE_NOTE,
            },
            "transparencyItem": {
                "findings": len(result.findings),
                "codes": sorted(set(transparency_codes)),
                "population": result.population,
            },
            "after": {
                "derivedFrom": "before + item 10's measured findings",
                "total": BEFORE_TOTAL + len(result.findings),
                "byRule": dict(sorted(by_rule.items())),
                "note": (
                    "the full gate was also re-run at the working tree and its "
                    "output is recorded in evidence/b8/RECEIPT.md; this record "
                    "reports the observed before count plus the item-10 delta "
                    "rather than claiming a second full observation it did not make"
                ),
            },
        },
        "digests": {
            "tool": _sha(REPO / TOOL),
            "gate": _sha(REPO / GATE),
            "schema": _sha(REPO / SCHEMA),
            "nonClaims": _sha(REPO / NONCLAIMS),
            "document": _sha(REPO / DOCUMENT),
        },
    }


def schema_record() -> dict[str, Any]:
    """The field, the closed enum and the (zero) population."""
    schema = ce.load_json(REPO / SCHEMA)
    fields, states = ce.transparency_definition(schema)
    block = schema["$defs"]["transparency"]
    profile = tuple(block["properties"]["profile"]["enum"])
    requirements: dict[str, list[str]] = {}
    for rule in block.get("allOf", []):
        state = rule.get("if", {}).get("properties", {}).get("state", {}).get("const")
        required = rule.get("then", {}).get("required")
        if isinstance(state, str) and isinstance(required, list):
            requirements[state] = required
    requirements.setdefault("NOT_ADMITTED", ["state"])
    document = ce.load_json(REPO / CLAIMS)
    claims = [row for row in document.get("claims", []) if isinstance(row, dict)]
    carrying = [row for row in claims if "transparency" in row]
    by_state: dict[str, int] = {}
    for row in carrying:
        state = row["transparency"].get("state") if isinstance(row["transparency"], dict) else None
        by_state[str(state)] = by_state.get(str(state), 0) + 1
    return {
        "schema": "openssl-rs/b8/schema/1",
        "item": "B8",
        "baseCommit": BASE_COMMIT,
        "path": SCHEMA,
        "definition": "$defs/transparency",
        "fields": list(fields),
        "stateEnum": list(states),
        "profileEnum": list(profile),
        "additionalProperties": block.get("additionalProperties", True),
        "freeText": False,
        "stateRequirements": dict(sorted(requirements.items())),
        "requiredWhen": {"authority.kind": ce.TRANSPARENCY_REQUIRED_AUTHORITY},
        "population": {
            "claims": len(claims),
            "carrying": len(carrying),
            "byState": dict(sorted(by_state.items())),
            "claimsRewritten": 0,
            "absenceCheck": "VACUOUS",
            "note": (
                "no committed claim carries the field, so the schema's "
                "absence requirement has no subject today. The check is "
                "vacuous, not a pass; no claim was rewritten to populate it."
            ),
        },
    }


def pending_record() -> dict[str, Any]:
    """The applications this batch may not make, with their state and reason."""
    agents = REPO / "forensics/etp8/agents-patch.diff"
    ci = REPO / "forensics/etp8/ci-transparency-job.patch"
    release_gates = REPO / "forensics/etp8/release-gates-section10-attempt.diff"
    return {
        "schema": "openssl-rs/b8/pending/1",
        "item": "B8",
        "baseCommit": BASE_COMMIT,
        "applications": [
            {
                "id": "agents-continuous-enforcement",
                "target": "AGENTS.md",
                "path": "forensics/etp8/agents-patch.diff",
                "state": "PENDING_MAINTAINER_APPLICATION",
                "reason": (
                    "AGENTS.md is the user's standing document; a conversion "
                    "batch does not edit it."
                ),
                "appliesToWorkingTree": _git_apply_check(agents),
                "sha256": _sha(agents),
            },
            {
                "id": "ci-transparency-job",
                "target": ".github/workflows/ci.yml",
                "path": "forensics/etp8/ci-transparency-job.patch",
                "state": "PENDING_CREDENTIAL",
                "reason": (
                    "the credential that pushes this branch is an OAuth app "
                    "without the workflow scope, and GitHub refuses a workflow "
                    "update from such a token, as recorded for "
                    "forensics/etp7/ci-assurance-job.patch."
                ),
                "appliesToWorkingTree": _git_apply_check(ci),
                "sha256": _sha(ci),
            },
            {
                "id": "release-gates-section10",
                "target": "docs/RELEASE_GATES.md section 10",
                "path": "forensics/etp8/release-gates-section10-attempt.diff",
                "state": "PENDING_MAINTAINER_APPLICATION",
                "reason": (
                    "forensics/tools/earned_trust.py refused the mapping with "
                    "ET_GATE_ITEM_DRIFT because evidence/etp-t14/ARTICLES.json "
                    "registers gate-1..gate-6 only; editing that record is "
                    "outside this item's write scope, and the checker was not "
                    "weakened. The edit was reverted with `git checkout`."
                ),
                "checkerOutput": (
                    "docs/RELEASE_GATES.md: ET_GATE_ITEM_DRIFT the gate table lists "
                    "['gate-1', 'gate-10', 'gate-2', 'gate-2b', 'gate-3', 'gate-4', "
                    "'gate-5', 'gate-6', 'gate-7', 'gate-8', 'gate-9'] but the record "
                    "registers ['gate-1', 'gate-2', 'gate-2b', 'gate-3', 'gate-4', "
                    "'gate-5', 'gate-6']"
                ),
                "appliesToWorkingTree": _git_apply_check(release_gates),
                "sha256": _sha(release_gates),
            },
        ],
    }


def build_records() -> dict[str, dict[str, Any]]:
    return {
        "ENFORCEMENT.json": enforcement_record(),
        "SCHEMA.json": schema_record(),
        "PENDING.json": pending_record(),
        "CONTROLS.json": ce.controls_record(),
    }


def write_records(records: dict[str, dict[str, Any]], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, record in records.items():
        (out / name).write_bytes(ce.pretty(record))


def check_records(records: dict[str, dict[str, Any]], out: Path) -> list[str]:
    problems = []
    for name, record in records.items():
        target = out / name
        if not target.is_file():
            problems.append(f"{name} is absent")
            continue
        if target.read_bytes() != ce.pretty(record):
            problems.append(f"{name} differs from the derived record")
    return problems


def summary(records: dict[str, dict[str, Any]]) -> str:
    enforcement = records["ENFORCEMENT.json"]
    schema = records["SCHEMA.json"]
    controls = records["CONTROLS.json"]
    counts = enforcement["refusalCounts"]
    return (
        f"code={ce.CODE_OK} b8: gateItems={len(enforcement['gateItems'])} "
        f"codes={len(enforcement['refusalCodes'])} "
        f"claims={schema['population']['claims']} "
        f"withTransparency={schema['population']['carrying']} "
        f"before={counts['before']['total']} after={counts['after']['total']} "
        f"controls={len(controls['controls'])} "
        f"codesCovered={len(controls['codesCovered'])} "
        f"coversEveryCode={str(controls['coversEveryCode']).lower()} "
        f"pending={len(records['PENDING.json']['applications'])}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Produce the B8 enforcement, schema, pending and control records."
    )
    parser.add_argument("--out", default=str(HERE), help="output directory (default: this directory)")
    parser.add_argument("--check", action="store_true",
                        help="compare the committed records with a fresh derivation")
    arguments = parser.parse_args(sys.argv[1:] if argv is None else list(argv))
    out = Path(arguments.out)
    records = build_records()
    if arguments.check:
        problems = check_records(records, out)
        if problems:
            print(f"code=CE_REFUSED_ENFORCEMENT_REGRESSION b8: {'; '.join(problems)}")
            return 1
        print(f"code={ce.CODE_OK} b8: check ok files={len(records)}")
        return 0
    write_records(records, out)
    print(summary(records))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
