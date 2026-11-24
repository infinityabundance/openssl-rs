#!/usr/bin/env python3
"""Controls for forensics/tools/thresholds.py and the A15 records.

One control per refusal code, each of the five substitutions individually
refused (a self-asserted domain, an alias, a duplicate domain, the candidate's
domain and a wrong role), the no-lowering rule in both its forms, the
unreachable case, staleness on a changed artefact digest and on expiry, the real
records producing 0 met thresholds, the synthetic positive control reaching
``MET``, the alias control keeping the count at one, the deterministic producer,
the command line and document synchronisation.

Run directly (`python3 forensics/tools/tests/test_thresholds.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics/tools"
sys.path.insert(0, str(TOOLS))

import thresholds as th  # noqa: E402

EVIDENCE = REPO / "evidence/a15"
BUILDER = EVIDENCE / "build_evidence.py"
DOCUMENT = REPO / "docs/TRUST-THRESHOLDS.md"
FULL_COMMIT = "b099cd599b6728a7b7686a76b515ff0b67a7acc1"
AT = "2026-11-24"
DIGEST = "f" * 64


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_builder() -> Any:
    spec = importlib.util.spec_from_file_location("a15_builder", BUILDER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def domain(
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


def domains(*records: dict[str, Any]) -> dict[str, Any]:
    return {"candidateDomain": "openssl-rs", "domains": list(records)}


def roles() -> list[dict[str, Any]]:
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


def approval(
    identity: str,
    domain_id: str,
    role: str,
    *,
    verified: bool = True,
    digest: str = DIGEST,
    approved: str = "2026-06-01",
    expires: str = "2027-06-01",
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


def threshold(
    *,
    k: int = 2,
    n: int = 3,
    declared: str = "2026-01-01",
    required: list[str] | None = None,
    amendments: list[dict[str, Any]] | None = None,
    digest: str = DIGEST,
) -> dict[str, Any]:
    return {
        "id": "control-only:threshold",
        "action": "release",
        "k": k,
        "n": n,
        "requiredRoles": required or ["release_authority", "adjudicator"],
        "distinctDomains": True,
        "declaredAt": declared,
        "declaredBy": "control-only:declarer",
        "artefactDigest": digest,
        "asOf": AT,
        "scope": ["*"],
        "amendments": amendments or [],
    }


ALPHA = domain("control-only:alpha")
BETA = domain("control-only:beta")
GAMMA = domain("control-only:gamma")
ALIAS = domain(
    "control-only:alpha-alias",
    path=ALPHA["establishedBy"]["path"],
    digest=ALPHA["establishedBy"]["sha256"],
)
CANDIDATE = domain("control-only:candidate", kind="candidate", independent=False)
SELF = {
    "domainId": "control-only:self",
    "kind": "external",
    "establishedBy": {},
    "independentOfCandidate": True,
}

BASE = domains(ALPHA, BETA, GAMMA)
ALIAS_DOMAINS = domains(ALPHA, ALIAS, BETA)
CANDIDATE_DOMAINS = domains(CANDIDATE, BETA, GAMMA)
SELF_DOMAINS = domains(SELF, BETA, GAMMA)
UNREACHABLE_DOMAINS = domains(CANDIDATE, SELF)

RELEASE = approval("control-only-release", "control-only:alpha", "release_authority")
ADJUDICATOR = approval("control-only-adjudicator", "control-only:beta", "adjudicator")


class RefusalCodes(unittest.TestCase):
    """One control per refusal code, built from control-only fixtures."""

    def evaluate(self, declaration, approvals, domain_document) -> dict[str, Any]:
        return th.evaluate(
            declaration, approvals, domain_document, roles(), at=AT,
            artefact_digest=(declaration or {}).get("artefactDigest"),
        )

    def test_threshold_unrecorded(self) -> None:
        result = self.evaluate(None, [], BASE)
        self.assertEqual(result["outcome"], th.OUTCOME_NOT_RUN)
        self.assertIn(th.TH_REFUSED_THRESHOLD_UNRECORDED, result["codes"])

    def test_threshold_unrecorded_when_distinct_domains_is_false(self) -> None:
        declaration = threshold()
        declaration["distinctDomains"] = False
        result = self.evaluate(declaration, [], BASE)
        self.assertEqual(result["outcome"], th.OUTCOME_NOT_RUN)
        self.assertIn(th.TH_REFUSED_THRESHOLD_UNRECORDED, result["codes"])

    def test_threshold_lowered_declared_after_earliest_approval(self) -> None:
        result = self.evaluate(threshold(declared="2026-08-01"), [RELEASE], BASE)
        self.assertEqual(result["outcome"], th.OUTCOME_UNMET)
        self.assertIn(th.TH_REFUSED_THRESHOLD_LOWERED, result["codes"])

    def test_threshold_lowered_amended_after_approvals(self) -> None:
        declaration = threshold(amendments=[{"at": "2026-06-01", "k": 1}])
        result = self.evaluate(declaration, [RELEASE], BASE)
        self.assertEqual(result["outcome"], th.OUTCOME_UNMET)
        self.assertIn(th.TH_REFUSED_THRESHOLD_LOWERED, result["codes"])

    def test_threshold_unreachable(self) -> None:
        result = self.evaluate(threshold(k=2), [], UNREACHABLE_DOMAINS)
        self.assertEqual(result["outcome"], th.OUTCOME_UNREACHABLE)
        self.assertIn(th.TH_REFUSED_THRESHOLD_UNREACHABLE, result["codes"])

    def test_self_asserted_domain(self) -> None:
        result = self.evaluate(
            threshold(k=2),
            [approval("control-only-release", "control-only:self", "release_authority"),
             ADJUDICATOR],
            SELF_DOMAINS,
        )
        self.assertIn(th.TH_REFUSED_SELF_ASSERTED_DOMAIN, result["codes"])
        self.assertEqual(result["distinctDomains"], 1)

    def test_domain_unrecorded(self) -> None:
        result = self.evaluate(
            threshold(k=2),
            [approval("control-only-release", "control-only:missing",
                      "release_authority"), ADJUDICATOR],
            BASE,
        )
        self.assertIn(th.TH_REFUSED_DOMAIN_UNRECORDED, result["codes"])
        self.assertEqual(result["distinctDomains"], 1)

    def test_candidate_domain(self) -> None:
        result = self.evaluate(
            threshold(k=2),
            [approval("control-only-release", "control-only:candidate",
                      "release_authority"), ADJUDICATOR],
            CANDIDATE_DOMAINS,
        )
        self.assertIn(th.TH_REFUSED_CANDIDATE_DOMAIN, result["codes"])
        self.assertEqual(result["distinctDomains"], 1)

    def test_aliased(self) -> None:
        result = self.evaluate(
            threshold(k=2),
            [approval("control-only-release", "control-only:alpha",
                      "release_authority"),
             approval("control-only-adjudicator", "control-only:alpha-alias",
                      "adjudicator")],
            ALIAS_DOMAINS,
        )
        self.assertIn(th.TH_REFUSED_ALIASED, result["codes"])
        self.assertEqual(result["distinctDomains"], 1)

    def test_domain_duplicate(self) -> None:
        result = self.evaluate(
            threshold(k=2),
            [approval("control-only-release", "control-only:beta",
                      "release_authority"),
             approval("control-only-adjudicator", "control-only:beta", "adjudicator")],
            BASE,
        )
        self.assertIn(th.TH_REFUSED_DOMAIN_DUPLICATE, result["codes"])
        self.assertEqual(result["distinctDomains"], 1)

    def test_unverified(self) -> None:
        result = self.evaluate(
            threshold(k=2),
            [approval("control-only-release", "control-only:alpha",
                      "release_authority", verified=False), ADJUDICATOR],
            BASE,
        )
        self.assertIn(th.TH_REFUSED_UNVERIFIED, result["codes"])
        self.assertEqual(result["distinctDomains"], 1)

    def test_wrong_role(self) -> None:
        result = self.evaluate(
            threshold(k=2),
            [approval("control-only-producer", "control-only:alpha",
                      "release_authority"), ADJUDICATOR],
            BASE,
        )
        self.assertIn(th.TH_REFUSED_WRONG_ROLE, result["codes"])
        self.assertEqual(result["distinctDomains"], 1)

    def test_stale_artefact_digest(self) -> None:
        result = self.evaluate(
            threshold(k=2),
            [approval("control-only-release", "control-only:alpha",
                      "release_authority", digest="e" * 64), ADJUDICATOR],
            BASE,
        )
        self.assertIn(th.TH_REFUSED_STALE_APPROVAL, result["codes"])
        self.assertEqual(result["distinctDomains"], 1)

    def test_stale_expiry(self) -> None:
        result = self.evaluate(
            threshold(k=2),
            [approval("control-only-release", "control-only:alpha",
                      "release_authority", expires="2026-05-01"), ADJUDICATOR],
            BASE,
        )
        self.assertIn(th.TH_REFUSED_STALE_APPROVAL, result["codes"])
        self.assertEqual(result["distinctDomains"], 1)

    def test_insufficient_domains(self) -> None:
        result = self.evaluate(threshold(k=2), [RELEASE], BASE)
        self.assertEqual(result["outcome"], th.OUTCOME_UNMET)
        self.assertIn(th.TH_REFUSED_INSUFFICIENT_DOMAINS, result["codes"])
        self.assertEqual(result["distinctDomains"], 1)

    def test_duplicate_identity(self) -> None:
        result = self.evaluate(
            threshold(k=2),
            [approval("control-only-release", "control-only:alpha",
                      "release_authority"),
             approval("control-only-release", "control-only:beta", "adjudicator")],
            BASE,
        )
        self.assertIn(th.TH_REFUSED_DUPLICATE_IDENTITY, result["codes"])
        self.assertEqual(result["distinctDomains"], 1)


class FiveSubstitutions(unittest.TestCase):
    """Each substitution is refused individually and does not add a domain."""

    def check(self, approvals, domain_document, code, expected_outcome) -> None:
        result = th.evaluate(
            threshold(k=2), approvals, domain_document, roles(), at=AT,
            artefact_digest=DIGEST,
        )
        self.assertIn(code, result["codes"])
        self.assertEqual(result["outcome"], expected_outcome)
        self.assertEqual(result["distinctDomains"], 1)

    def test_self_asserted_domain_is_one_approval_not_two(self) -> None:
        self.check(
            [approval("control-only-release", "control-only:self",
                      "release_authority"), ADJUDICATOR],
            SELF_DOMAINS, th.TH_REFUSED_SELF_ASSERTED_DOMAIN, th.OUTCOME_UNMET,
        )

    def test_alias_is_one_domain_not_two(self) -> None:
        self.check(
            [approval("control-only-release", "control-only:alpha",
                      "release_authority"),
             approval("control-only-adjudicator", "control-only:alpha-alias",
                      "adjudicator")],
            ALIAS_DOMAINS, th.TH_REFUSED_ALIASED, th.OUTCOME_UNMET,
        )

    def test_duplicate_domain_is_one_domain_not_two(self) -> None:
        self.check(
            [approval("control-only-release", "control-only:beta",
                      "release_authority"),
             approval("control-only-adjudicator", "control-only:beta",
                      "adjudicator")],
            BASE, th.TH_REFUSED_DOMAIN_DUPLICATE, th.OUTCOME_UNMET,
        )

    def test_candidate_domain_is_not_an_independent_approval(self) -> None:
        self.check(
            [approval("control-only-release", "control-only:candidate",
                      "release_authority"), ADJUDICATOR],
            CANDIDATE_DOMAINS, th.TH_REFUSED_CANDIDATE_DOMAIN, th.OUTCOME_UNMET,
        )

    def test_wrong_role_is_not_an_approval(self) -> None:
        self.check(
            [approval("control-only-producer", "control-only:alpha",
                      "release_authority"), ADJUDICATOR],
            BASE, th.TH_REFUSED_WRONG_ROLE, th.OUTCOME_UNMET,
        )


class NoLowering(unittest.TestCase):
    def test_declaration_after_the_earliest_approval_is_refused(self) -> None:
        result = th.evaluate(
            threshold(declared="2026-06-02"), [RELEASE], BASE, roles(), at=AT,
            artefact_digest=DIGEST,
        )
        self.assertEqual(result["outcome"], th.OUTCOME_UNMET)
        self.assertIn(th.TH_REFUSED_THRESHOLD_LOWERED, result["codes"])

    def test_declaration_before_the_earliest_approval_is_accepted(self) -> None:
        result = th.evaluate(
            threshold(declared="2026-06-01"), [RELEASE], BASE, roles(), at=AT,
            artefact_digest=DIGEST,
        )
        self.assertNotIn(th.TH_REFUSED_THRESHOLD_LOWERED, result["codes"])

    def test_amendment_at_the_earliest_approval_is_refused(self) -> None:
        result = th.evaluate(
            threshold(amendments=[{"at": "2026-06-01", "k": 1}]),
            [RELEASE], BASE, roles(), at=AT, artefact_digest=DIGEST,
        )
        self.assertIn(th.TH_REFUSED_THRESHOLD_LOWERED, result["codes"])

    def test_amendment_before_the_earliest_approval_is_accepted(self) -> None:
        result = th.evaluate(
            threshold(amendments=[{"at": "2025-12-01", "k": 1}]),
            [RELEASE], BASE, roles(), at=AT, artefact_digest=DIGEST,
        )
        self.assertNotIn(th.TH_REFUSED_THRESHOLD_LOWERED, result["codes"])


class Reachability(unittest.TestCase):
    def test_k_larger_than_available_domains_is_unreachable(self) -> None:
        result = th.evaluate(
            threshold(k=3), [], domains(ALPHA, BETA), roles(), at=AT,
            artefact_digest=DIGEST,
        )
        self.assertEqual(result["outcome"], th.OUTCOME_UNREACHABLE)
        self.assertEqual(result["availableDomains"], 2)

    def test_alias_pair_is_one_available_domain(self) -> None:
        self.assertEqual(th.available_domain_count(ALIAS_DOMAINS), 2)
        result = th.evaluate(
            threshold(k=3), [], ALIAS_DOMAINS, roles(), at=AT,
            artefact_digest=DIGEST,
        )
        self.assertEqual(result["outcome"], th.OUTCOME_UNREACHABLE)

    def test_same_party_and_candidate_domains_are_not_available(self) -> None:
        self.assertEqual(th.available_domain_count(UNREACHABLE_DOMAINS), 0)


class CountAndAliases(unittest.TestCase):
    def test_distinct_domains_returns_groups_not_only_a_number(self) -> None:
        result = th.distinct_domains(
            [approval("control-only-release", "control-only:alpha",
                      "release_authority"),
             approval("control-only-adjudicator", "control-only:alpha-alias",
                      "adjudicator")],
            ALIAS_DOMAINS,
        )
        self.assertEqual(result["count"], 1)
        self.assertEqual(len(result["groups"]), 1)
        self.assertEqual(result["aliases"], result["groups"])
        self.assertEqual(sorted(result["groups"][0]["domainIds"]),
                         ["control-only:alpha", "control-only:alpha-alias"])

    def test_duplicate_labels_are_reported(self) -> None:
        result = th.distinct_domains(
            [approval("control-only-release", "control-only:beta",
                      "release_authority"),
             approval("control-only-adjudicator", "control-only:beta",
                      "adjudicator")],
            BASE,
        )
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["duplicateLabels"], ["control-only:beta"])

    def test_duplicate_identities_are_reported(self) -> None:
        result = th.distinct_domains(
            [approval("control-only-release", "control-only:alpha",
                      "release_authority"),
             approval("control-only-release", "control-only:beta", "adjudicator")],
            BASE,
        )
        self.assertEqual(result["duplicateIdentities"], ["control-only-release"])


class RealRecords(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.domains = load_json(EVIDENCE / "DOMAINS.json")
        cls.thresholds = load_json(EVIDENCE / "THRESHOLDS.json")
        cls.approvals = load_json(EVIDENCE / "APPROVALS.json")
        cls.evaluation = load_json(EVIDENCE / "EVALUATION.json")
        cls.controls = load_json(EVIDENCE / "CONTROLS.json")

    def test_no_external_domain_is_recorded(self) -> None:
        self.assertEqual(self.domains["externalDomains"], [])
        self.assertEqual(self.domains["domains"][0]["independentOfCandidate"], False)
        self.assertEqual(self.domains["domains"][0]["kind"], "same-party")

    def test_no_real_approval_is_recorded(self) -> None:
        self.assertEqual(self.approvals["approvals"], [])
        self.assertEqual(self.evaluation["aggregate"]["realApprovals"], 0)

    def test_the_four_thresholds_are_declared(self) -> None:
        ids = sorted(item["id"] for item in self.thresholds["thresholds"])
        self.assertEqual(ids, [
            "claim-promotion", "consumer-graduation",
            "instrument-qualification", "release",
        ])
        self.assertEqual(self.thresholds["domainsAvailable"], 0)

    def test_zero_thresholds_are_met(self) -> None:
        aggregate = self.evaluation["aggregate"]
        self.assertEqual(aggregate["met"], 0)
        self.assertEqual(aggregate["unreachable"], 4)
        self.assertEqual(aggregate["unmet"], 0)
        self.assertEqual(aggregate["notRun"], 0)
        self.assertEqual(aggregate["distinctDomains"], 0)

    def test_every_real_threshold_is_unreachable(self) -> None:
        for threshold_id, result in self.evaluation["evaluations"].items():
            self.assertEqual(result["outcome"], th.OUTCOME_UNREACHABLE, threshold_id)
            self.assertEqual(result["codes"], [th.TH_REFUSED_THRESHOLD_UNREACHABLE],
                             threshold_id)
            self.assertEqual(result["distinctDomains"], 0, threshold_id)

    def test_controls_exercise_every_code(self) -> None:
        covered = {control["expected"]["code"] for control in self.controls["controls"]}
        self.assertEqual(covered, set(th.CODE_ORDER))
        for control in self.controls["controls"]:
            self.assertTrue(control["controlOnly"])
            self.assertIn(control["expected"]["code"], control["observed"]["codes"])

    def test_positive_and_alias_controls(self) -> None:
        positive = self.controls["positive"]["observed"]
        self.assertEqual(positive["outcome"], th.OUTCOME_MET)
        self.assertEqual(positive["distinctDomains"], 2)
        self.assertEqual(positive["codes"], [])
        alias = next(item for item in self.controls["controls"]
                     if item["id"] == "alias-one-domain")
        self.assertEqual(alias["observed"]["distinctDomains"], 1)
        self.assertIn(th.TH_REFUSED_ALIASED, alias["observed"]["codes"])


class PositiveControl(unittest.TestCase):
    def test_two_distinct_synthetic_domains_reach_met(self) -> None:
        result = th.evaluate(
            threshold(k=2), [RELEASE, ADJUDICATOR], BASE, roles(), at=AT,
            artefact_digest=DIGEST,
        )
        self.assertEqual(result["outcome"], th.OUTCOME_MET)
        self.assertEqual(result["distinctDomains"], 2)
        self.assertEqual(result["codes"], [])
        self.assertEqual(len(result["groups"]), 2)

    def test_the_positive_control_is_not_a_real_approval(self) -> None:
        result = th.evaluate(
            threshold(k=2), [RELEASE, ADJUDICATOR], BASE, roles(), at=AT,
            artefact_digest=DIGEST,
        )
        self.assertTrue(all(
            str(item.get("domainId", "")).startswith("control-only")
            for item in result["approvals"]
        ))


class Determinism(unittest.TestCase):
    def test_builder_is_byte_identical_twice_and_matches_committed(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for out in (first, second):
                run = subprocess.run(
                    [sys.executable, str(BUILDER), "--out", out,
                     "--source-commit", FULL_COMMIT],
                    cwd=str(REPO), text=True, capture_output=True, timeout=120,
                )
                self.assertEqual(run.returncode, 0, run.stderr)
            for name in ("DOMAINS.json", "THRESHOLDS.json", "APPROVALS.json",
                         "EVALUATION.json", "CONTROLS.json"):
                left = (Path(first) / name).read_bytes()
                right = (Path(second) / name).read_bytes()
                self.assertEqual(left, right, name)
                self.assertEqual(left, (EVIDENCE / name).read_bytes(), name)

    def test_build_is_deterministic_in_process(self) -> None:
        builder = load_builder()
        first = builder.build(FULL_COMMIT)
        second = builder.build(FULL_COMMIT)
        names = ("DOMAINS.json", "THRESHOLDS.json", "APPROVALS.json",
                 "EVALUATION.json", "CONTROLS.json")
        for name, document, other in zip(names, first, second):
            rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
            rendered_again = json.dumps(other, indent=2, sort_keys=True) + "\n"
            self.assertEqual(rendered, rendered_again, name)
            self.assertEqual(rendered.encode(), (EVIDENCE / name).read_bytes(), name)


class CommandLine(unittest.TestCase):
    def run_tool(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(TOOLS / "thresholds.py"), *args],
            cwd=str(REPO), text=True, capture_output=True, timeout=120,
        )

    def test_domains_exits_zero_and_reports_zero_external(self) -> None:
        run = self.run_tool("domains")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("external=0", run.stdout)
        self.assertIn("code=TH_OK", run.stdout)

    def test_evaluate_exits_one_and_prints_the_code(self) -> None:
        run = self.run_tool("evaluate", "release")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("outcome=UNREACHABLE", run.stdout)
        self.assertIn("TH_REFUSED_THRESHOLD_UNREACHABLE", run.stdout)

    def test_evaluate_missing_threshold_exits_one(self) -> None:
        run = self.run_tool("evaluate", "not-a-threshold")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("TH_REFUSED_THRESHOLD_UNRECORDED", run.stdout)
        self.assertIn("outcome=NOT_RUN", run.stdout)

    def test_evaluate_json_is_the_evaluation(self) -> None:
        run = self.run_tool("evaluate", "release", "--json")
        self.assertEqual(run.returncode, 1, run.stderr)
        payload = json.loads(run.stdout)
        self.assertEqual(payload["outcome"], th.OUTCOME_UNREACHABLE)
        self.assertEqual(payload["codes"], [th.TH_REFUSED_THRESHOLD_UNREACHABLE])

    def test_count_prints_the_alias_groups(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "thresholds.json").write_text(
                json.dumps({"thresholds": [threshold()]}), encoding="utf-8")
            (root / "domains.json").write_text(
                json.dumps(ALIAS_DOMAINS), encoding="utf-8")
            (root / "roles.json").write_text(
                json.dumps({"assignments": roles()}), encoding="utf-8")
            (root / "approvals.json").write_text(json.dumps({"approvals": [
                approval("control-only-release", "control-only:alpha",
                         "release_authority"),
                approval("control-only-adjudicator", "control-only:alpha-alias",
                         "adjudicator"),
            ]}), encoding="utf-8")
            run = self.run_tool(
                "count", "control-only:threshold", str(root / "approvals.json"),
                "--thresholds", str(root / "thresholds.json"),
                "--domains", str(root / "domains.json"),
                "--roles", str(root / "roles.json"),
                "--at", AT,
            )
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("count=1", run.stdout)
        self.assertIn("TH_REFUSED_ALIASED", run.stdout)
        self.assertIn("control-only:alpha-alias", run.stdout)

    def test_usage_error_is_exit_two(self) -> None:
        run = self.run_tool("domains", "--not-an-option")
        self.assertEqual(run.returncode, 2)


class DocumentSynchronisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8")

    def test_every_refusal_code_is_documented(self) -> None:
        for code in th.CODE_ORDER:
            self.assertIn(code, self.text, code)

    def test_every_enforced_by_names_a_code_or_test(self) -> None:
        markers = ("TH_REFUSED_", "test_", "`thresholds.py`", "`build_evidence.py`")
        for line in self.text.splitlines():
            if "Enforced by" in line:
                self.assertTrue(
                    any(marker in line for marker in markers),
                    f"enforcement line names no code or test: {line!r}",
                )

    def test_the_document_states_the_real_result(self) -> None:
        self.assertIn("0 external trust domains", self.text)
        self.assertIn("0 thresholds can be met", self.text)
        for threshold_id in ("release", "claim-promotion", "consumer-graduation",
                             "instrument-qualification"):
            self.assertIn(threshold_id, self.text)

    def test_the_document_names_the_release_gate_status(self) -> None:
        self.assertIn("RG_THRESHOLD_UNMET", self.text)
        self.assertIn("Release-gate integration", self.text)

    def test_the_document_has_a_not_run_section(self) -> None:
        self.assertIn("## `NOT_RUN`", self.text)
        self.assertIn("NOT_RUN", self.text)


class JsonRecords(unittest.TestCase):
    def test_every_record_parses_and_is_bound(self) -> None:
        schemas = {
            "DOMAINS.json": th.DOMAINS_SCHEMA,
            "THRESHOLDS.json": th.THRESHOLDS_SCHEMA,
            "APPROVALS.json": th.APPROVALS_SCHEMA,
            "EVALUATION.json": th.EVALUATION_SCHEMA,
            "CONTROLS.json": th.CONTROLS_SCHEMA,
        }
        for name, schema in schemas.items():
            document = load_json(EVIDENCE / name)
            self.assertEqual(document["schema"], schema, name)
            self.assertEqual(document["sourceIdentity"]["baseCommit"], FULL_COMMIT, name)
            self.assertTrue(document["sourceIdentity"]["tool"]["sha256"], name)
            self.assertTrue(document["sourceIdentity"]["delegatedRoleTool"]["sha256"], name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
