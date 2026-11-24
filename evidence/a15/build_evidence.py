#!/usr/bin/env python3
"""build_evidence.py -- deterministic producer of the A15 records.

The producer reads the tracked records that establish the real state and writes
five documents:

  * ``DOMAINS.json``     -- the domain inventory (one same-party domain, no
                            external domain);
  * ``THRESHOLDS.json``  -- the declared k-of-n thresholds;
  * ``APPROVALS.json``   -- the real approvals (none that is verified and
                            externally domain-bound);
  * ``EVALUATION.json``  -- every threshold evaluated against the real approvals;
  * ``CONTROLS.json``    -- one control per refusal code, plus a positive control
                            in which k distinct synthetic domains reach ``MET``
                            and an alias control in which two labels resolve to
                            one domain and the count stays one.

Every value is derived from a literal in this file or from the bytes of a named
input record.  Two runs are byte-identical, and the committed files match a
fresh run; the test suite enforces both.

Usage:
    python3 evidence/a15/build_evidence.py [--out DIR] [--source-commit SHA]

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics/tools"
sys.path.insert(0, str(TOOLS))

import thresholds as th  # noqa: E402

BASE_COMMIT = "b099cd599b6728a7b7686a76b515ff0b67a7acc1"
BASE_COMMIT_SHORT = "b099cd599"
ITEM = "A15"
AS_OF = "2026-11-24"
AT = "2026-11-24"

A12_ROOTS = "evidence/a12/TRUST-ROOTS.json"
A14_ROLES = "evidence/a14/ROLES.json"
TOOL_PATH = "forensics/tools/thresholds.py"
DELEGATED_TOOL = "forensics/tools/authorisation.py"

SUBJECTS = {
    "release": "evidence/etp/claims.json",
    "claim-promotion": "evidence/etp/claims.json",
    "consumer-graduation": "evidence/SAFE-COMPATIBLE-openssh-b85c.json",
    "instrument-qualification": "evidence/etp3/instruments.json",
}

# The real declarations.  ``n`` is the quorum the policy contemplates; the
# available-domain count is measured from DOMAINS.json and is 0.
THRESHOLD_DECLARATIONS = (
    {
        "id": "release",
        "action": "release",
        "k": 2,
        "n": 3,
        "requiredRoles": ["release_authority", "adjudicator"],
        "scope": ["*"],
    },
    {
        "id": "claim-promotion",
        "action": "claim-promotion",
        "k": 1,
        "n": 2,
        "requiredRoles": ["adjudicator"],
        "scope": ["*"],
    },
    {
        "id": "consumer-graduation",
        "action": "consumer-graduation",
        "k": 2,
        "n": 3,
        "requiredRoles": ["adjudicator", "external_reproducer"],
        "scope": ["*"],
    },
    {
        "id": "instrument-qualification",
        "action": "instrument-qualification",
        "k": 1,
        "n": 2,
        "requiredRoles": ["instrument_reviewer"],
        "scope": ["*"],
    },
)


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def source_identity(commit: str) -> dict[str, Any]:
    inputs = [A12_ROOTS, A14_ROLES, *sorted(set(SUBJECTS.values()))]
    return {
        "baseCommit": commit,
        "baseCommitShort": commit[:9],
        "branch": "staging",
        "recordedAt": AS_OF,
        "tool": {"path": TOOL_PATH, "sha256": sha256_file(REPO_ROOT / TOOL_PATH)},
        "delegatedRoleTool": {
            "path": DELEGATED_TOOL,
            "sha256": sha256_file(REPO_ROOT / DELEGATED_TOOL),
        },
        "inputs": [
            {"path": path, "sha256": sha256_file(REPO_ROOT / path)}
            for path in inputs
        ],
    }


def write_json(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# The real records
# ---------------------------------------------------------------------------
def domains_document(identity: dict[str, Any]) -> dict[str, Any]:
    roots_digest = sha256_file(REPO_ROOT / A12_ROOTS)
    same_party = {
        "domainId": "openssl-rs:same-party",
        "kind": "same-party",
        "establishedBy": {"path": A12_ROOTS, "sha256": roots_digest},
        "independentOfCandidate": False,
        "note": (
            "A12's inventory records one root, the A10 test-only HMAC-SHA256 key: "
            "symmetric, trustDomain 'same-party', provenance inside the candidate. "
            "The record establishes that the domain exists; it does not establish "
            "independence, so independentOfCandidate is false."
        ),
    }
    return {
        "schema": th.DOMAINS_SCHEMA,
        "item": ITEM,
        "asOf": AS_OF,
        "candidateDomain": "openssl-rs",
        "domains": [same_party],
        "externalDomains": [],
        "externalDomainsNote": (
            "The inventory records no external trust domain. This is the measured "
            "state, not an omission: A12's only recorded root is the A10 test-only "
            "HMAC-SHA256 key, which is symmetric and same-party and therefore cannot "
            "establish a domain independent of the candidate. A threshold of k>=1 "
            "is unreachable while this list is empty."
        ),
        "sourceIdentity": identity,
    }


def thresholds_document(identity: dict[str, Any], domains: dict[str, Any]) -> dict[str, Any]:
    declared_by = {
        "identity": "P-CAMPAIGN",
        "role": "producer",
        "evidence": f"{A14_ROLES}#P-CAMPAIGN/producer",
        "independent": False,
        "note": (
            "declared by the project's undeclared producer party. A14 records "
            "maintainer: none, so no maintainer declared it; the declaration is "
            "same-party and is not evidence of an independent policy."
        ),
    }
    records = []
    for declaration in THRESHOLD_DECLARATIONS:
        subject = SUBJECTS[declaration["id"]]
        records.append({
            **declaration,
            "distinctDomains": True,
            "declaredAt": AS_OF,
            "declaredBy": declared_by,
            "artefactPath": subject,
            "artefactDigest": sha256_file(REPO_ROOT / subject),
            "asOf": AS_OF,
            "amendments": [],
            "record": "evidence/a15/THRESHOLDS.json",
        })
    return {
        "schema": th.THRESHOLDS_SCHEMA,
        "item": ITEM,
        "asOf": AS_OF,
        "thresholds": records,
        "domainsAvailable": th.available_domain_count(domains),
        "externalDomains": list(domains.get("externalDomains") or []),
        "note": (
            "Every threshold is declared but none is reachable: the domain inventory "
            "records 0 established external domains, so a k>=1 threshold cannot be met."
        ),
        "sourceIdentity": identity,
    }


def approvals_document(identity: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": th.APPROVALS_SCHEMA,
        "item": ITEM,
        "asOf": AS_OF,
        "approvals": [],
        "note": (
            "No approval is verified and externally domain-bound. No real signature "
            "exists (A14 records every attempt verified:false; A10/A12 record only a "
            "test-only symmetric key), and no external domain exists (DOMAINS.json). "
            "This is the measured state, not an omission."
        ),
        "sourceIdentity": identity,
    }


def evaluation_document(
    thresholds: dict[str, Any],
    domains: dict[str, Any],
    approvals: dict[str, Any],
    roles: list[dict[str, Any]],
    identity: dict[str, Any],
) -> dict[str, Any]:
    evaluations: dict[str, Any] = {}
    counts = {th.OUTCOME_MET: 0, th.OUTCOME_UNMET: 0,
              th.OUTCOME_UNREACHABLE: 0, th.OUTCOME_NOT_RUN: 0}
    for declaration in thresholds["thresholds"]:
        result = th.evaluate(
            declaration,
            approvals["approvals"],
            domains,
            roles,
            at=AT,
            artefact_digest=declaration["artefactDigest"],
        )
        evaluations[declaration["id"]] = result
        counts[result["outcome"]] = counts.get(result["outcome"], 0) + 1
    return {
        "schema": th.EVALUATION_SCHEMA,
        "item": ITEM,
        "asOf": AS_OF,
        "candidate": identity["baseCommit"],
        "approvals": approvals["approvals"],
        "aggregate": {
            "thresholds": len(evaluations),
            "met": counts[th.OUTCOME_MET],
            "unmet": counts[th.OUTCOME_UNMET],
            "unreachable": counts[th.OUTCOME_UNREACHABLE],
            "notRun": counts[th.OUTCOME_NOT_RUN],
            "distinctDomains": max(
                (result["distinctDomains"] for result in evaluations.values()), default=0
            ),
            "availableDomains": th.available_domain_count(domains),
            "realApprovals": len(approvals["approvals"]),
        },
        "evaluations": evaluations,
        "note": (
            "0 external trust domains means 0 thresholds can be met. Every threshold "
            "is UNREACHABLE because fewer than k established external domains exist. "
            "This is the honest result and is not worked around."
        ),
        "sourceIdentity": identity,
    }


# ---------------------------------------------------------------------------
# The synthetic controls.  Every fixture is labelled control-only.
# ---------------------------------------------------------------------------
CONTROL_DIGEST = "f" * 64
APPROVED_AT = "2026-06-01"
EXPIRES_AT = "2027-06-01"


def _domain(
    domain_id: str,
    *,
    kind: str = "external",
    path: str | None = None,
    digest: str | None = None,
    independent: bool = True,
) -> dict[str, Any]:
    return {
        "domainId": domain_id,
        "kind": kind,
        "establishedBy": {
            "path": path or f"control-only/establishments/{domain_id.split(':')[-1]}.json",
            "sha256": digest or hashlib.sha256(domain_id.encode()).hexdigest(),
        },
        "independentOfCandidate": independent,
    }


def _domains(*records: dict[str, Any]) -> dict[str, Any]:
    return {"candidateDomain": "openssl-rs", "domains": list(records)}


def _approval(
    identity: str,
    domain_id: str,
    role: str,
    *,
    verified: bool = True,
    digest: str = CONTROL_DIGEST,
    approved: str = APPROVED_AT,
    expires: str = EXPIRES_AT,
) -> dict[str, Any]:
    return {
        "identity": identity,
        "domainId": domain_id,
        "role": role,
        "signature": {"verified": verified, "basis": "control-only: no real key"},
        "artefactDigest": digest,
        "approvedAt": approved,
        "expiresAt": expires,
    }


def _roles() -> list[dict[str, Any]]:
    return [
        {"identity": "control-only-release", "party": "P-CONTROL-RELEASE",
         "role": "release_authority", "scope": ["*"], "grantedAt": "2026-01-01",
         "evidence": "control-only:release-authority"},
        {"identity": "control-only-release", "party": "P-CONTROL-RELEASE",
         "role": "adjudicator", "scope": ["*"], "grantedAt": "2026-01-01",
         "evidence": "control-only:release-adjudicator"},
        {"identity": "control-only-adjudicator", "party": "P-CONTROL-ADJ",
         "role": "adjudicator", "scope": ["*"], "grantedAt": "2026-01-01",
         "evidence": "control-only:adjudicator"},
        {"identity": "control-only-reproducer", "party": "P-CONTROL-REPRO",
         "role": "external_reproducer", "scope": ["*"], "grantedAt": "2026-01-01",
         "evidence": "control-only:external-reproducer"},
        {"identity": "control-only-reviewer", "party": "P-CONTROL-REVIEW",
         "role": "instrument_reviewer", "scope": ["*"], "grantedAt": "2026-01-01",
         "evidence": "control-only:instrument-reviewer"},
        {"identity": "control-only-producer", "party": "P-CONTROL-PRODUCER",
         "role": "producer", "scope": ["*"], "grantedAt": "2026-01-01",
         "evidence": "control-only:producer"},
    ]


def _threshold(
    *,
    k: int = 2,
    n: int = 3,
    declared: str = "2026-01-01",
    roles: list[str] | None = None,
    action: str = "release",
    amendments: list[dict[str, Any]] | None = None,
    digest: str = CONTROL_DIGEST,
) -> dict[str, Any]:
    return {
        "id": "control-only:threshold",
        "action": action,
        "k": k,
        "n": n,
        "requiredRoles": roles or ["release_authority", "adjudicator"],
        "distinctDomains": True,
        "declaredAt": declared,
        "declaredBy": "control-only:declarer",
        "artefactDigest": digest,
        "asOf": AT,
        "scope": ["*"],
        "amendments": amendments or [],
    }


def _control(
    control_id: str,
    code: str | None,
    threshold: dict[str, Any] | None,
    approvals: list[dict[str, Any]],
    domains: dict[str, Any],
    *,
    expected_outcome: str,
    expected_count: int = 0,
    note: str = "",
) -> dict[str, Any]:
    observed = th.evaluate(
        threshold,
        approvals,
        domains,
        _roles(),
        at=AT,
        artefact_digest=(threshold or {}).get("artefactDigest"),
    )
    return {
        "id": control_id,
        "controlOnly": True,
        "code": code,
        "note": note,
        "threshold": threshold,
        "approvals": approvals,
        "domains": domains,
        "roleAssignments": _roles(),
        "expected": {
            "outcome": expected_outcome,
            "code": code,
            "distinctDomains": expected_count,
        },
        "observed": {
            "outcome": observed["outcome"],
            "codes": observed["codes"],
            "distinctDomains": observed["distinctDomains"],
            "availableDomains": observed["availableDomains"],
            "detail": observed["detail"],
        },
    }


def controls_document(identity: dict[str, Any]) -> dict[str, Any]:
    alpha = _domain("control-only:alpha")
    beta = _domain("control-only:beta")
    gamma = _domain("control-only:gamma")
    alias = _domain(
        "control-only:alpha-alias",
        path=alpha["establishedBy"]["path"],
        digest=alpha["establishedBy"]["sha256"],
    )
    candidate = _domain(
        "control-only:candidate", kind="candidate", independent=False
    )
    self_asserted = {
        "domainId": "control-only:self",
        "kind": "external",
        "establishedBy": {},
        "independentOfCandidate": True,
    }

    base = _domains(alpha, beta, gamma)
    alias_domains = _domains(alpha, alias, beta)
    candidate_domains = _domains(candidate, beta, gamma)
    self_domains = _domains(self_asserted, beta, gamma)
    unreachable_domains = _domains(candidate, self_asserted)

    release = _approval("control-only-release", "control-only:alpha", "release_authority")
    adjudicator = _approval(
        "control-only-adjudicator", "control-only:beta", "adjudicator"
    )

    controls = [
        _control(
            "threshold-unrecorded",
            th.TH_REFUSED_THRESHOLD_UNRECORDED,
            None,
            [],
            base,
            expected_outcome=th.OUTCOME_NOT_RUN,
            note="no declaration; nothing is evaluated and NOT_RUN is not a pass",
        ),
        _control(
            "threshold-lowered-declared-late",
            th.TH_REFUSED_THRESHOLD_LOWERED,
            _threshold(declared="2026-08-01"),
            [release],
            base,
            expected_outcome=th.OUTCOME_UNMET,
            note="the declaration is dated after the earliest approval",
        ),
        _control(
            "threshold-lowered-amended",
            th.TH_REFUSED_THRESHOLD_LOWERED,
            _threshold(amendments=[
                {"at": "2026-06-01", "k": 1, "by": "control-only:declarer"}
            ]),
            [release],
            base,
            expected_outcome=th.OUTCOME_UNMET,
            note="the declaration was amended at the earliest approval",
        ),
        _control(
            "threshold-unreachable",
            th.TH_REFUSED_THRESHOLD_UNREACHABLE,
            _threshold(k=2),
            [],
            unreachable_domains,
            expected_outcome=th.OUTCOME_UNREACHABLE,
            note="0 established external domains and k=2",
        ),
        _control(
            "self-asserted-domain",
            th.TH_REFUSED_SELF_ASSERTED_DOMAIN,
            _threshold(k=2),
            [
                _approval("control-only-release", "control-only:self", "release_authority"),
                adjudicator,
            ],
            self_domains,
            expected_outcome=th.OUTCOME_UNMET,
            expected_count=1,
            note="the domain has no establishment record",
        ),
        _control(
            "domain-unrecorded",
            th.TH_REFUSED_DOMAIN_UNRECORDED,
            _threshold(k=2),
            [
                _approval(
                    "control-only-release", "control-only:missing", "release_authority"
                ),
                adjudicator,
            ],
            base,
            expected_outcome=th.OUTCOME_UNMET,
            expected_count=1,
            note="the approval names a label with no domain record",
        ),
        _control(
            "candidate-domain",
            th.TH_REFUSED_CANDIDATE_DOMAIN,
            _threshold(k=2),
            [
                _approval(
                    "control-only-release", "control-only:candidate", "release_authority"
                ),
                adjudicator,
            ],
            candidate_domains,
            expected_outcome=th.OUTCOME_UNMET,
            expected_count=1,
            note="the approval claims the candidate's own domain",
        ),
        _control(
            "alias-one-domain",
            th.TH_REFUSED_ALIASED,
            _threshold(k=2),
            [
                _approval("control-only-release", "control-only:alpha", "release_authority"),
                _approval("control-only-adjudicator", "control-only:alpha-alias", "adjudicator"),
            ],
            alias_domains,
            expected_outcome=th.OUTCOME_UNMET,
            expected_count=1,
            note="two labels share one establishment record; the count stays one",
        ),
        _control(
            "domain-duplicate",
            th.TH_REFUSED_DOMAIN_DUPLICATE,
            _threshold(k=2),
            [
                _approval("control-only-release", "control-only:beta", "release_authority"),
                _approval("control-only-adjudicator", "control-only:beta", "adjudicator"),
            ],
            base,
            expected_outcome=th.OUTCOME_UNMET,
            expected_count=1,
            note="one domain approves twice",
        ),
        _control(
            "unverified",
            th.TH_REFUSED_UNVERIFIED,
            _threshold(k=2),
            [
                _approval(
                    "control-only-release", "control-only:alpha", "release_authority",
                    verified=False,
                ),
                adjudicator,
            ],
            base,
            expected_outcome=th.OUTCOME_UNMET,
            expected_count=1,
            note="the signature is not verified",
        ),
        _control(
            "wrong-role",
            th.TH_REFUSED_WRONG_ROLE,
            _threshold(k=2),
            [
                _approval(
                    "control-only-producer", "control-only:alpha", "release_authority"
                ),
                adjudicator,
            ],
            base,
            expected_outcome=th.OUTCOME_UNMET,
            expected_count=1,
            note="the identity does not hold the role at the approval time under A14",
        ),
        _control(
            "stale-digest",
            th.TH_REFUSED_STALE_APPROVAL,
            _threshold(k=2),
            [
                _approval(
                    "control-only-release", "control-only:alpha", "release_authority",
                    digest="e" * 64,
                ),
                adjudicator,
            ],
            base,
            expected_outcome=th.OUTCOME_UNMET,
            expected_count=1,
            note="the artefact digest changed",
        ),
        _control(
            "stale-expired",
            th.TH_REFUSED_STALE_APPROVAL,
            _threshold(k=2),
            [
                _approval(
                    "control-only-release", "control-only:alpha", "release_authority",
                    expires="2026-05-01",
                ),
                adjudicator,
            ],
            base,
            expected_outcome=th.OUTCOME_UNMET,
            expected_count=1,
            note="the approval expired before the evaluation date",
        ),
        _control(
            "insufficient-domains",
            th.TH_REFUSED_INSUFFICIENT_DOMAINS,
            _threshold(k=2),
            [release],
            base,
            expected_outcome=th.OUTCOME_UNMET,
            expected_count=1,
            note="enough domains exist but only one qualifies",
        ),
        _control(
            "duplicate-identity",
            th.TH_REFUSED_DUPLICATE_IDENTITY,
            _threshold(k=2),
            [
                _approval("control-only-release", "control-only:alpha", "release_authority"),
                _approval("control-only-release", "control-only:beta", "adjudicator"),
            ],
            base,
            expected_outcome=th.OUTCOME_UNMET,
            expected_count=1,
            note="one identity under two domain labels contributes one domain",
        ),
    ]

    positive = _control(
        "positive-distinct-domains",
        None,
        _threshold(k=2),
        [release, adjudicator],
        base,
        expected_outcome=th.OUTCOME_MET,
        expected_count=2,
        note="two distinct synthetic domains reach MET; control-only, not a real action",
    )

    observed = positive["observed"]
    if observed["outcome"] != th.OUTCOME_MET or observed["distinctDomains"] != 2:
        raise SystemExit(
            "control positive-distinct-domains failed: "
            f"outcome={observed['outcome']} count={observed['distinctDomains']}"
        )
    for control in controls:
        expected_code = control["expected"]["code"]
        if expected_code not in control["observed"]["codes"]:
            raise SystemExit(
                f"control {control['id']} failed: {expected_code} not in "
                f"{control['observed']['codes']}"
            )
        if control["observed"]["outcome"] != control["expected"]["outcome"]:
            raise SystemExit(
                f"control {control['id']} failed: outcome "
                f"{control['observed']['outcome']} != {control['expected']['outcome']}"
            )
        if control["observed"]["distinctDomains"] != control["expected"]["distinctDomains"]:
            raise SystemExit(
                f"control {control['id']} failed: count "
                f"{control['observed']['distinctDomains']} != "
                f"{control['expected']['distinctDomains']}"
            )
    covered = {control["expected"]["code"] for control in controls}
    missing = sorted(set(th.CODE_ORDER) - covered)
    if missing:
        raise SystemExit(f"controls do not exercise every refusal code: {missing}")
    alias = next(item for item in controls if item["id"] == "alias-one-domain")
    if alias["observed"]["distinctDomains"] != 1:
        raise SystemExit("the alias control did not keep the count at one")

    return {
        "schema": th.CONTROLS_SCHEMA,
        "item": ITEM,
        "asOf": AS_OF,
        "controls": controls,
        "positive": positive,
        "summary": {
            "controls": len(controls),
            "positive": 1,
            "codes": list(th.CODE_ORDER),
            "allFired": True,
            "positiveOutcome": positive["observed"]["outcome"],
            "aliasCount": alias["observed"]["distinctDomains"],
            "controlOnly": True,
        },
        "note": (
            "Every fixture is control-only and is excluded from the real aggregate. "
            "The positive control establishes the counting procedure, not a real "
            "approval, a real domain or a real authorisation."
        ),
        "sourceIdentity": identity,
    }


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------
def build(commit: str = BASE_COMMIT) -> tuple[dict[str, Any], ...]:
    identity = source_identity(commit)
    domains = domains_document(identity)
    thresholds = thresholds_document(identity, domains)
    approvals = approvals_document(identity)
    roles = json.loads((REPO_ROOT / A14_ROLES).read_text(encoding="utf-8"))
    role_list = roles.get("assignments", []) if isinstance(roles, dict) else roles
    evaluation = evaluation_document(thresholds, domains, approvals, role_list, identity)
    if evaluation["aggregate"]["met"] != 0:
        raise SystemExit("the real aggregate must be 0 met thresholds")
    controls = controls_document(identity)
    return domains, thresholds, approvals, evaluation, controls


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(REPO_ROOT / "evidence/a15"))
    parser.add_argument("--source-commit", default=BASE_COMMIT)
    args = parser.parse_args(argv)

    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)
    documents = build(args.source_commit)
    names = ("DOMAINS.json", "THRESHOLDS.json", "APPROVALS.json",
             "EVALUATION.json", "CONTROLS.json")
    for name, document in zip(names, documents):
        write_json(output / name, document)
    evaluation = documents[3]["aggregate"]
    print(
        f"a15: domains={len(documents[0]['domains'])} "
        f"external={len(documents[0]['externalDomains'])} "
        f"thresholds={evaluation['thresholds']} met={evaluation['met']} "
        f"unreachable={evaluation['unreachable']} approvals={evaluation['realApprovals']} "
        f"controls={documents[4]['summary']['controls']} "
        f"commit={args.source_commit[:9]}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
