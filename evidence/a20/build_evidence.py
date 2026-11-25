#!/usr/bin/env python3
"""Deterministic producer of the A20 records.

The policy is a declaration, not a computation: the producer writes the eight
obligations, their sources and their predicates, pins the result, evaluates it
against the recorded sources and writes the decision and the controls.  No
timestamp is written anywhere, every array is sorted by the writer, and two runs
over the same records reproduce the same bytes.

    python3 evidence/a20/build_evidence.py [--out DIR]

The default output directory is this file's directory.  ``--out`` exists so the
gate can compare two runs, and so a refusal can be inspected without touching the
committed records.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "forensics/tools"
sys.path.insert(0, str(TOOLS))

import policy_engine as pe  # noqa: E402

HERE = Path(__file__).resolve().parent
BASE_COMMIT = "f34e429f13aa3cc1566e1ecebc185a466765f321"
POLICY_ID = "release-policy"
POLICY_PATH = "evidence/a20/POLICY.json"
UPSTREAM = "P-CAMPAIGN"
MAINTAINER = "P-PRINCIPAL"


def source(tool: str, record: str, locator: str) -> dict[str, str]:
    return {"tool": tool, "record": record, "locator": locator}


def obligation(
    identifier: str,
    description: str,
    tool: str,
    record: str,
    locator: str,
    predicate: dict[str, Any],
    **extra: Any,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": identifier,
        "description": description,
        "required": True,
        "source": source(tool, record, locator),
        "predicate": predicate,
    }
    body.update(extra)
    return body


A5_STATES = [
    "ABSENT",
    "AGGREGATE_ONLY",
    "COMPLETE",
    "DEFERRED",
    "EMPTY",
    "SAMPLED",
    "TRUNCATED_BOUNDED",
    "UNKNOWN",
]


def build_policy() -> dict[str, Any]:
    """The release policy: a conjunction of eight obligations read from records."""
    obligations = [
        obligation(
            "A05.populations-admitted",
            "every recorded population is admitted at a state in the A5 vocabulary, "
            "and no declaration refused as stronger than its facts keeps the state it "
            "declared; COMPLETE is not required",
            "forensics/tools/completeness.py",
            "evidence/a5/ADMISSION.json",
            "/populations",
            {
                "op": "all",
                "of": [
                    {
                        "op": "all-in",
                        "path": "",
                        "field": "state",
                        "allowed": A5_STATES,
                    },
                    {
                        "op": "none",
                        "path": "",
                        "where": [
                            {"field": "refusal", "op": "present"},
                            {"field": "state", "op": "eq-field", "other": "declared"},
                        ],
                    },
                ],
            },
        ),
        obligation(
            "A06.suppression-member-identities",
            "no suppression record that declares itself ACTIVE is admitted without "
            "member identities",
            "forensics/tools/suppression_governance.py",
            "evidence/a6/SUPPRESSIONS.json",
            "/records",
            {
                "op": "none",
                "path": "",
                "where": [
                    {"field": "classification", "op": "eq", "value": "suppression"},
                    {"field": "declaredDisposition", "op": "eq", "value": "ACTIVE"},
                    {"field": "membersRecorded", "op": "eq", "value": False},
                ],
            },
        ),
        obligation(
            "A07.delta-resolution-conditions",
            "no delta claims RESOLVED unless its own conditions were met: a refused "
            "delta records no RESOLVED disposition, and a delta recording one carries "
            "no refusal code",
            "forensics/tools/baseline.py",
            "evidence/a7/DELTA.json",
            "/deltas",
            {
                "op": "all",
                "of": [
                    {
                        "op": "none",
                        "path": "",
                        "where": [
                            {"field": "admitted", "op": "eq", "value": False},
                            {"field": "counts.RESOLVED", "op": "gt", "value": 0},
                        ],
                    },
                    {
                        "op": "none",
                        "path": "",
                        "where": [
                            {"field": "codes", "op": "nonempty"},
                            {"field": "counts.RESOLVED", "op": "gt", "value": 0},
                        ],
                    },
                ],
            },
        ),
        obligation(
            "A12.independent-attestation",
            "at least one attestation is INDEPENDENTLY_VERIFIED by a verifier whose "
            "root of trust is outside the candidate",
            "forensics/tools/independent_verify.py",
            "evidence/a12/VERIFICATION.json",
            "/verifications",
            {
                "op": "count-at-least",
                "path": "",
                "where": [{"field": "independentlyVerified", "op": "truthy"}],
                "atLeast": 1,
            },
        ),
        obligation(
            "A14.release-authorised",
            "the release action is AUTHORISED under the recorded role authorisation "
            "decision",
            "forensics/tools/authorisation.py",
            "evidence/a14/AUTHORISATION.json",
            "/actions/release",
            {"op": "eq", "path": "/recorded/outcome", "value": "AUTHORISED"},
        ),
        obligation(
            "A15.release-threshold-met",
            "the release threshold is MET over distinct established trust domains",
            "forensics/tools/thresholds.py",
            "evidence/a15/EVALUATION.json",
            "/evaluations/release",
            {"op": "eq", "path": "/outcome", "value": "MET"},
        ),
        obligation(
            "A17.forward-freeze-closed",
            "the forward freeze is CLOSED and every required member is PRODUCED; the "
            "freeze record and the status record must agree about the freeze's state",
            "forensics/tools/omission.py",
            "evidence/a17/STATUS.json",
            "/forwardFreeze",
            {
                "op": "all",
                "of": [
                    {"op": "eq", "path": "/state", "value": "CLOSED"},
                    {"op": "eq", "path": "/closed", "value": True},
                ],
            },
            fact="A17/forward-freeze/state",
            corroboration=[
                {
                    "tool": "forensics/tools/omission.py",
                    "record": "evidence/a17/FREEZE-forward.json",
                    "locator": "",
                    "predicate": {"op": "eq", "path": "/state", "value": "CLOSED"},
                }
            ],
        ),
        obligation(
            "A19.retraction-propagated",
            "no retraction in the recorded scope leaves a dependent VALID",
            "forensics/tools/corrections.py",
            "evidence/a19/PROPAGATION.json",
            "/events",
            {
                "op": "none",
                "path": "",
                "where": [
                    {"field": "kind", "op": "eq", "value": "retract"},
                    {"field": "summary.valid", "op": "gt", "value": 0},
                ],
            },
        ),
    ]
    body: dict[str, Any] = {
        "schema": pe.POLICY_SCHEMA,
        "policyId": POLICY_ID,
        "version": 1,
        "default": "deny",
        "scores": False,
        "obligations": sorted(obligations, key=lambda item: item["id"]),
        "provenance": {
            "establishedBy": {"role": "maintainer", "identity": MAINTAINER},
            "recordedAt": "2026-11-24",
            "independentOfCandidate": False,
        },
    }
    body["digest"] = pe.policy_digest(body)
    return body


def build_pin(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": pe.PIN_SCHEMA,
        "policyId": policy["policyId"],
        "policyDigest": policy["digest"],
        "policyPath": POLICY_PATH,
        "pinnedAt": "2026-11-24",
        "pinnedBy": {"role": "maintainer", "identity": MAINTAINER},
        "candidate": {"commit": BASE_COMMIT, "producedBy": UPSTREAM},
        "note": (
            "the pin records the policy's digest and the party that pinned it; it is "
            "recorded separately from the policy so that amending the policy is "
            "detectable. It lives in the candidate tree, so a writer who can amend both "
            "is not detected without an external root (A12)."
        ),
    }


def build_decision(policy: dict[str, Any], pin: dict[str, Any]) -> dict[str, Any]:
    candidate, problems = pe.resolve_candidate(REPO, commit=BASE_COMMIT)
    if problems:
        raise SystemExit(f"a20: the candidate cannot be resolved: {problems}")
    return pe.evaluate(
        policy,
        pin,
        candidate,
        reader=pe.filesystem_reader(REPO),
        root=REPO,
        action="release",
        policy_path=POLICY_PATH,
        runs=2,
    )


def build_controls() -> dict[str, Any]:
    controls = pe.controls()
    by_code = {control["code"]: control for control in controls if control["code"]}
    missing = sorted(set(pe.REFUSAL_CODES) - set(by_code))
    unestablished = [control["id"] for control in controls if not control["established"]]
    positives = [control["id"] for control in controls if control["code"] is None]
    admitted = [control["id"] for control in controls if control["observed"]["decision"] == "ADMIT"]
    if missing:
        raise SystemExit(f"a20: no control for refusal code(s) {missing}")
    if unestablished:
        raise SystemExit(f"a20: control(s) did not establish their code: {unestablished}")
    if positives != admitted:
        raise SystemExit(
            f"a20: the positive control(s) {positives} did not reach ADMIT (reached {admitted})"
        )
    return {
        "schema": pe.CONTROLS_SCHEMA,
        "item": "A20",
        "policy": POLICY_PATH,
        "controls": controls,
        "totals": {
            "controls": len(controls),
            "refusalCodes": len(pe.REFUSAL_CODES),
            "coveredCodes": len(by_code),
            "positives": len(positives),
            "admitted": len(admitted),
        },
    }


def write(path: Path, value: Any) -> None:
    path.write_bytes(
        (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(HERE))
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    policy = build_policy()
    pin = build_pin(policy)
    decision = build_decision(policy, pin)
    controls = build_controls()

    write(out / "POLICY.json", policy)
    write(out / "POLICY-PIN.json", pin)
    write(out / "DECISION.json", decision)
    write(out / "CONTROLS.json", controls)

    print(
        "a20: "
        f"policy={policy['policyId']} digest={policy['digest'][:16]} "
        f"version={policy['version']} default={policy['default']} "
        f"scores={str(policy['scores']).lower()} obligations={len(policy['obligations'])} "
        f"pin={pin['policyDigest'][:16]} candidate={BASE_COMMIT[:9]} "
        f"decision={decision['decision']} codes="
        f"{','.join(decision['codes']) if decision['codes'] else 'NONE'} "
        f"met={len(decision['met'])} unmet={len(decision['unmet'])} "
        f"unknown={len(decision['unknown'])} "
        f"notApplicable={len(decision['notApplicable'])} "
        f"controls={controls['totals']['controls']} "
        f"codesCovered={controls['totals']['coveredCodes']}/{controls['totals']['refusalCodes']} "
        f"positives={controls['totals']['positives']} commit={BASE_COMMIT[:9]}"
    )
    print(f"a20: unmet = {','.join(decision['unmet']) if decision['unmet'] else 'NONE'}")
    return pe.EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
