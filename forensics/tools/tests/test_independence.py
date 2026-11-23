#!/usr/bin/env python3
"""Controls for the independence checker (ETP-T8).

One control per refusal rule in ``docs/INDEPENDENCE.md``, a positive control
that a genuinely distinct-party record passes, a determinism control, a
reproduction control for the committed assignment record, and a dissent control
that proves a retained dissent survives aggregation and lowers the verdict.

Run inside the court:

    python3 forensics/tools/tests/test_independence.py
"""

from __future__ import annotations

import copy
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
sys.path.insert(0, str(TOOLS))

import independence as ind  # noqa: E402

ROLES = ind.load_json_strict(ind.ROLES_PATH)
COMMITTED = ind.load_json_strict(ind.ASSIGNMENTS_PATH)

DELIVERABLES = (
    REPO_ROOT / "docs" / "INDEPENDENCE.md",
    REPO_ROOT / "forensics" / "tools" / "independence.py",
    REPO_ROOT / "evidence" / "etp-t8" / "ROLES.json",
    REPO_ROOT / "evidence" / "etp-t8" / "ASSIGNMENTS.json",
    REPO_ROOT / "evidence" / "etp-t8" / "RECEIPT.md",
)


def codes(findings) -> set[str]:
    return {item.code for item in findings}


def party(ident: str, organisation: str, operator: str, key: str) -> dict:
    return {
        "declared": True,
        "identity": ident,
        "account": f"account-{ident}",
        "organisation": organisation,
        "infrastructure": f"https://{operator}.example/{ident}",
        "infrastructure_operator": operator,
        "signing_key": key,
        "trust_domain": "external",
    }


def distinct_parties() -> dict:
    return {
        "P-A": party("agent-a", "org-a", "operator-a", "key-a"),
        "P-B": party("agent-b", "org-b", "operator-b", "key-b"),
        "P-C": party("agent-c", "org-c", "operator-c", "key-c"),
    }


def filled(role_party: dict) -> dict:
    output = {}
    for role, party_id in role_party.items():
        output[role] = {
            "status": "FILLED",
            "party": party_id,
            "identity": None,
            "declared": True,
        }
    for role in ind.ROLE_IDS:
        if role not in output:
            output[role] = {
                "status": "ABSENT",
                "party": None,
                "identity": None,
                "declared": False,
            }
    return output


def independent_document() -> dict:
    """A record where every required role is a genuinely distinct party."""

    assignment = {
        "id": "A-SYNTHETIC",
        "artefact": "evidence/synthetic.json",
        "class": "SAFE_COMPATIBLE_RELEASE",
        "asserted_verdict": "SAFE_COMPATIBLE",
        "claimed_independence": True,
        "independence_kind": "REVIEW",
        "independence_required": ["adjudicator", "independent_reproducer", "release_authority"],
        "filled": filled(
            {
                "author": "P-A",
                "proof_producer": "P-A",
                "instrument_author": "P-A",
                "evidence_producer": "P-A",
                "adjudicator": "P-B",
                "reviewer": "P-B",
                "independent_reproducer": "P-B",
                "release_authority": "P-C",
                "revocation_authority": "P-C",
            }
        ),
        "reviewers": [
            {
                "id": "RV-1",
                "role": "independent adjudicator",
                "identity": "reviewer-b",
                "account": "account-agent-b",
                "artefact": "reviews/b.md",
                "party": "P-B",
                "signing_key": "key-b",
            }
        ],
        "threshold": {
            "required_distinct_parties": 2,
            "satisfied_by": ["role:author", "role:adjudicator"],
        },
        "reproduction": {
            "claimed_independent": True,
            "rebuilt_from_frozen_package": True,
            "used_project_working_environment": False,
            "used_project_produced_artefact": False,
            "procedure": "rebuild from the frozen package archive",
            "trust_domain": "external",
        },
    }
    document = {
        "schema": ind.SCHEMA_ASSIGNMENTS,
        "kind": "independence-role-assignments",
        "generated_utc": "2026-11-23T00:00:00Z",
        "source_identity": {"commit": "0" * 40, "branch": "test", "worktree_clean_tracked_files": True},
        "roles_document": "evidence/etp-t8/ROLES.json",
        "parties": distinct_parties(),
        "assignments": [assignment],
        "dissents": [],
    }
    document["aggregate"] = ind.aggregate(document)
    return document


def add_dissent(document: dict, position: str = "NOT_ESTABLISHED") -> dict:
    dissent = {
        "id": "D-SYNTHETIC",
        "assignment": "A-SYNTHETIC",
        "artefact": "reviews/dissent.json",
        "party": "P-B",
        "role": "adjudicator",
        "dissented_from": "P-C",
        "position": position,
        "recorded_utc": "2026-11-23T00:00:00Z",
        "retained": True,
        "statement": "The adjudicator refuses the release verdict.",
        "removal_requests": [],
    }
    document["dissents"] = [dissent]
    document["aggregate"] = ind.aggregate(document)
    return document


class NamedRefusalMixin(unittest.TestCase):
    def assert_named(self, findings, code: str, field_fragment: str = "") -> ind.Refusal:
        matches = [item for item in findings if item.code == code]
        self.assertTrue(matches, f"{code} not among {sorted(codes(findings))}")
        if field_fragment:
            chosen = [item for item in matches if field_fragment in item.field]
            self.assertTrue(
                chosen,
                f"{code} field {field_fragment!r} not among {[item.field for item in matches]}",
            )
            matches = chosen
        chosen = matches[0]
        self.assertTrue(chosen.assignment and chosen.assignment != "-", chosen)
        return chosen


class PositiveControl(unittest.TestCase):
    def test_roles_document_is_admissible(self) -> None:
        self.assertEqual(ind.validate_roles(copy.deepcopy(ROLES)), [])

    def test_committed_record_is_structurally_admissible(self) -> None:
        self.assertEqual(ind.validate_structure(copy.deepcopy(COMMITTED), ROLES), [])

    def test_distinct_parties_pass_every_rule(self) -> None:
        document = independent_document()
        self.assertEqual(ind.validate(document, ROLES), [])

    def test_committed_independence_assertions_are_refused(self) -> None:
        findings = ind.validate(copy.deepcopy(COMMITTED), ROLES)
        self.assertEqual(
            codes(findings),
            {
                "IND_ADJUDICATOR_IS_AUTHOR",
                "IND_REPRODUCER_CONTAMINATED",
                "IND_REQUIRED_ROLE_ABSENT",
                "IND_REVIEW_UNSUPPORTED",
                "IND_ROLE_NOT_DISTINCT",
                "IND_THRESHOLD_ALIASED",
            },
        )
        self.assertTrue(all(item.assignment for item in findings))


class RuleOneReviewUnsupported(NamedRefusalMixin, unittest.TestCase):
    def test_reviewer_without_identity_is_refused(self) -> None:
        document = independent_document()
        document["assignments"][0]["reviewers"][0]["identity"] = None
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_REVIEW_UNSUPPORTED", "identity")

    def test_asserted_independence_without_reviewers_is_refused(self) -> None:
        document = independent_document()
        document["assignments"][0]["reviewers"] = []
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_REVIEW_UNSUPPORTED", "reviewers")

    def test_committed_b85c_adjudication_is_named(self) -> None:
        findings = ind.validate(copy.deepcopy(COMMITTED), ROLES)
        match = [item for item in findings if item.assignment == "A-ADJ-B85C"]
        self.assert_named(match, "IND_REVIEW_UNSUPPORTED", "reviewers[0].identity")


class RuleTwoAdjudicatorIsAuthor(NamedRefusalMixin, unittest.TestCase):
    def test_adjudicator_by_the_author_is_refused(self) -> None:
        document = independent_document()
        document["assignments"][0]["filled"]["adjudicator"]["party"] = "P-A"
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_ADJUDICATOR_IS_AUTHOR", "filled.adjudicator")

    def test_ordinary_claim_does_not_require_distinctness(self) -> None:
        document = independent_document()
        document["assignments"][0]["class"] = "ORDINARY_CLAIM"
        document["assignments"][0]["claimed_independence"] = False
        document["assignments"][0]["filled"]["adjudicator"]["party"] = "P-A"
        document["aggregate"] = ind.aggregate(document)
        self.assertEqual(ind.validate(document, ROLES), [])


class RuleThreeReviewersAliased(NamedRefusalMixin, unittest.TestCase):
    def test_same_identity_is_refused(self) -> None:
        document = independent_document()
        document["assignments"][0]["reviewers"].append(
            {
                "id": "RV-2",
                "role": "second reviewer",
                "identity": "reviewer-b",
                "account": "account-other",
                "artefact": "reviews/c.md",
                "party": "P-C",
                "signing_key": "key-c",
            }
        )
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_REVIEWERS_ALIASED", "identity")

    def test_same_signing_key_is_refused(self) -> None:
        document = independent_document()
        document["assignments"][0]["reviewers"].append(
            {
                "id": "RV-2",
                "role": "second reviewer",
                "identity": "reviewer-c",
                "account": "account-c",
                "artefact": "reviews/c.md",
                "party": "P-C",
                "signing_key": "key-b",
            }
        )
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_REVIEWERS_ALIASED", "signing_key")


class RuleFourThresholdAliased(NamedRefusalMixin, unittest.TestCase):
    def test_one_account_under_two_names_is_refused(self) -> None:
        document = independent_document()
        document["parties"]["P-A2"] = {
            "declared": True,
            "identity": "agent-a-alias",
            "account": "account-agent-a",
            "organisation": "org-a",
            "infrastructure": "https://operator-a.example/alias",
            "infrastructure_operator": "operator-a",
            "signing_key": "key-a2",
            "trust_domain": "external",
        }
        document["assignments"][0]["threshold"] = {
            "required_distinct_parties": 2,
            "satisfied_by": ["P-A", "P-A2"],
        }
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_THRESHOLD_ALIASED", "threshold.satisfied_by")

    def test_two_urls_under_one_operator_are_refused(self) -> None:
        document = independent_document()
        document["parties"]["P-A3"] = {
            "declared": True,
            "identity": "agent-a3",
            "account": "account-a3",
            "organisation": "org-a3",
            "infrastructure": "https://second-url.example/a3",
            "infrastructure_operator": "operator-a",
            "signing_key": "key-a3",
            "trust_domain": "external",
        }
        document["assignments"][0]["threshold"] = {
            "required_distinct_parties": 2,
            "satisfied_by": ["P-A", "P-A3"],
        }
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_THRESHOLD_ALIASED", "threshold.satisfied_by")

    def test_two_genuinely_distinct_parties_pass(self) -> None:
        document = independent_document()
        self.assertEqual(ind.validate(document, ROLES), [])


class RuleFiveReproducerContaminated(NamedRefusalMixin, unittest.TestCase):
    def test_project_working_environment_is_refused(self) -> None:
        document = independent_document()
        document["assignments"][0]["reproduction"]["used_project_working_environment"] = True
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_REPRODUCER_CONTAMINATED", "used_project_working_environment")

    def test_project_produced_artefact_is_refused(self) -> None:
        document = independent_document()
        document["assignments"][0]["reproduction"]["used_project_produced_artefact"] = True
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_REPRODUCER_CONTAMINATED", "used_project_produced_artefact")

    def test_not_rebuilt_from_frozen_package_is_refused(self) -> None:
        document = independent_document()
        document["assignments"][0]["reproduction"]["rebuilt_from_frozen_package"] = False
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_REPRODUCER_CONTAMINATED", "rebuilt_from_frozen_package")

    def test_committed_reproduction_is_named(self) -> None:
        findings = ind.validate(copy.deepcopy(COMMITTED), ROLES)
        match = [item for item in findings if item.assignment == "A-ADJ-B85C"]
        self.assert_named(match, "IND_REPRODUCER_CONTAMINATED", "used_project_working_environment")


class DissentPreservation(NamedRefusalMixin, unittest.TestCase):
    def test_dissent_survives_aggregation_and_lowers_the_verdict(self) -> None:
        document = add_dissent(independent_document())
        self.assertEqual(ind.validate(document, ROLES), [])
        computed = ind.aggregate(document)
        self.assertEqual(computed["per_assignment"]["A-SYNTHETIC"]["verdict"], "NOT_ESTABLISHED")
        self.assertEqual(computed["cohorts"]["SAFE_COMPATIBLE_RELEASE"]["verdict"], "NOT_ESTABLISHED")
        self.assertIn("D-SYNTHETIC", computed["included_dissents"])

    def test_dropping_a_dissent_from_the_aggregate_is_refused(self) -> None:
        document = add_dissent(independent_document())
        document["aggregate"]["included_dissents"] = []
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_DISSENT_DROPPED", "included_dissents")

    def test_aggregate_better_than_the_dissent_is_refused(self) -> None:
        document = add_dissent(independent_document())
        document["aggregate"]["per_assignment"]["A-SYNTHETIC"]["verdict"] = "SAFE_COMPATIBLE"
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_DISSENT_OVERRIDDEN", "aggregate.per_assignment")
        self.assertIn("IND_AGGREGATE_MISMATCH", codes(findings))

    def test_removal_by_the_dissented_from_party_is_refused(self) -> None:
        document = add_dissent(independent_document())
        document["dissents"][0]["removal_requests"] = [
            {"requested_by": "P-C", "accepted": True, "reason": "release decision"}
        ]
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_DISSENT_REMOVED_BY_TARGET", "removal_requests[0]")

    def test_withdrawal_by_the_dissenting_party_is_admissible(self) -> None:
        document = add_dissent(independent_document())
        document["dissents"][0]["removal_requests"] = [
            {"requested_by": "P-B", "accepted": True, "reason": "reviewer withdrew"}
        ]
        self.assertEqual(ind.validate(document, ROLES), [])

    def test_committed_b85c_dissent_lowers_the_release_verdict(self) -> None:
        computed = ind.aggregate(copy.deepcopy(COMMITTED))
        self.assertEqual(
            computed["per_assignment"]["A-REL-OPENSSH-B85C"]["verdict"],
            "NOT_ESTABLISHED",
        )
        self.assertEqual(
            computed["cohorts"]["SAFE_COMPATIBLE_RELEASE"]["verdict"], "NOT_ESTABLISHED"
        )
        self.assertIn("D-OPENSSH-B85C", computed["included_dissents"])


class StructuralControls(NamedRefusalMixin, unittest.TestCase):
    def test_unknown_claim_class_is_refused(self) -> None:
        document = independent_document()
        document["assignments"][0]["class"] = "MADE_UP"
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_CLAIM_CLASS_UNKNOWN", "class")

    def test_unknown_party_is_refused(self) -> None:
        document = independent_document()
        document["assignments"][0]["filled"]["author"]["party"] = "P-MISSING"
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_PARTY_UNKNOWN", "filled.author.party")

    def test_recorded_sameness_must_match_the_computation(self) -> None:
        document = independent_document()
        document["assignments"][0]["sameness"] = {
            "author|adjudicator": {
                "same_agent": "SAME",
                "same_organisation": "SAME",
                "same_infrastructure": "SAME",
                "same_key": "SAME",
            }
        }
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_SAMENESS_MISMATCH", "sameness.author|adjudicator")

    def test_recorded_same_party_must_match_the_computation(self) -> None:
        document = independent_document()
        document["assignments"][0]["same_party"] = "SAME"
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_SAMENESS_MISMATCH", "same_party")

    def test_unknown_role_in_the_roles_document_is_refused(self) -> None:
        roles = copy.deepcopy(ROLES)
        roles["roles"] = [role for role in roles["roles"] if role["id"] != "revocation_authority"]
        self.assertIn("IND_ROLES_SCHEMA", codes(ind.validate_roles(roles)))

    def test_external_independence_must_be_stated(self) -> None:
        roles = copy.deepcopy(ROLES)
        roles["external_independence_present"] = True
        self.assertIn("IND_ROLES_SCHEMA", codes(ind.validate_roles(roles)))

    def test_duplicate_json_key_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"a": 1, "a": 2}', encoding="utf-8")
            with self.assertRaises(ind.DocumentError) as raised:
                ind.load_json_strict(path)
            self.assertEqual(raised.exception.code, "IND_JSON_DUPLICATE_KEY")

    def test_non_finite_number_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nan.json"
            path.write_text('{"a": NaN}', encoding="utf-8")
            with self.assertRaises(ind.DocumentError) as raised:
                ind.load_json_strict(path)
            self.assertEqual(raised.exception.code, "IND_JSON_NON_FINITE")


class TrustDomainControls(NamedRefusalMixin, unittest.TestCase):
    def test_missing_required_reproducer_is_refused(self) -> None:
        document = independent_document()
        document["assignments"][0]["filled"]["independent_reproducer"] = {
            "status": "ABSENT",
            "party": None,
            "identity": None,
            "declared": False,
        }
        document["assignments"][0]["same_party"] = ind.assignment_same_party(document, document["assignments"][0])
        findings = ind.validate(document, ROLES)
        self.assert_named(findings, "IND_REQUIRED_ROLE_ABSENT", "filled.independent_reproducer")

    def test_release_authority_not_distinct_from_adjudicator_is_refused(self) -> None:
        document = independent_document()
        document["assignments"][0]["filled"]["release_authority"]["party"] = "P-B"
        document["assignments"][0]["same_party"] = ind.assignment_same_party(
            document, document["assignments"][0]
        )
        findings = ind.validate(document, ROLES)
        self.assert_named(
            findings, "IND_ROLE_NOT_DISTINCT", "filled.release_authority|filled.adjudicator"
        )

    def test_reproducer_sharing_an_organisation_with_the_author_is_refused(self) -> None:
        document = independent_document()
        document["parties"]["P-A2"] = {
            "declared": True,
            "identity": "agent-a2",
            "account": "account-a2",
            "organisation": "org-a",
            "infrastructure": "https://operator-a2.example/a2",
            "infrastructure_operator": "operator-a2",
            "signing_key": "key-a2",
            "trust_domain": "external",
        }
        document["assignments"][0]["filled"]["independent_reproducer"]["party"] = "P-A2"
        document["assignments"][0]["same_party"] = ind.assignment_same_party(
            document, document["assignments"][0]
        )
        findings = ind.validate(document, ROLES)
        self.assert_named(
            findings, "IND_ROLE_NOT_DISTINCT", "filled.independent_reproducer|filled.author"
        )


class PopulationAndIdentity(unittest.TestCase):
    def test_no_external_party_is_recorded(self) -> None:
        summary = ind.summarize(copy.deepcopy(COMMITTED))
        self.assertEqual(summary["external_parties"], 0)
        self.assertEqual(summary["declared_parties"], 0)

    def test_every_assignment_has_a_same_party_adjudicator(self) -> None:
        summary = ind.summarize(copy.deepcopy(COMMITTED))
        self.assertEqual(summary["assignments"], 50)
        self.assertEqual(summary["same_party_adjudicator"], 50)
        self.assertEqual(summary["adjudicator_distinctness_not_established"], 0)

    def test_committed_summary_matches_the_document(self) -> None:
        self.assertEqual(ind.summarize(copy.deepcopy(COMMITTED)), COMMITTED["summary"])

    def test_seed_reproduces_the_committed_record_byte_for_byte(self) -> None:
        seeded = ind.seed(REPO_ROOT, COMMITTED["generated_utc"])
        self.assertEqual(ind.dump_json(seeded), ind.dump_json(COMMITTED))
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            first.write_text(ind.dump_json(ind.seed(REPO_ROOT, COMMITTED["generated_utc"])), encoding="utf-8")
            second.write_text(ind.dump_json(ind.seed(REPO_ROOT, COMMITTED["generated_utc"])), encoding="utf-8")
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_check_is_deterministic(self) -> None:
        first = ind.validate(copy.deepcopy(COMMITTED), ROLES)
        second = ind.validate(copy.deepcopy(COMMITTED), ROLES)
        self.assertEqual(
            [(item.code, item.assignment, item.field) for item in first],
            [(item.code, item.assignment, item.field) for item in second],
        )

    def test_no_first_person_in_the_new_artefacts(self) -> None:
        pattern = re.compile(
            r"(?<![A-Za-z])"
            r"(?:i|w[e]|o[u]r|u[s]|m[y]|m[e]|m[y]self)"
            r"(?![A-Za-z])",
            re.IGNORECASE,
        )
        for path in DELIVERABLES:
            self.assertTrue(path.exists(), f"missing deliverable {path}")
            text = path.read_text(encoding="utf-8")
            match = pattern.search(text)
            self.assertIsNone(
                match,
                f"first person in {path}" + (f": {match.group(0)!r}" if match else ""),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
