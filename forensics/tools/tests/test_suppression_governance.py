#!/usr/bin/env python3
"""Controls for suppression governance.

Each control exercises one rule of `docs/SUPPRESSION-GOVERNANCE.md`: a suppressed
finding is still a finding; a suppression must name its target, its members, a
justification, a reviewer, a time, an expiry and a policy basis; a scope never
exceeds its target; an invalidation trigger records a reason and deletes nothing;
and the disposition totals reconcile with the finding population.

A control mutates a real record or a synthetic suppression in memory. It is not a
source change and not a defect report: a control that fires proves the refusal
works, not that the substituted form occurs anywhere in the tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import dataclasses
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import suppression_governance as sg  # noqa: E402

A6 = REPO_ROOT / "evidence" / "a6"
SUPPRESSIONS = A6 / "SUPPRESSIONS.json"
INVALIDATION = A6 / "INVALIDATION.json"
CONTROLS = A6 / "CONTROLS.json"
PRODUCER = A6 / "build_evidence.py"
DOCUMENT = REPO_ROOT / "docs" / "SUPPRESSION-GOVERNANCE.md"
RECEIPT = A6 / "RECEIPT.md"
TOOL = TOOLS / "suppression_governance.py"

REQUIRED_CODES = {
    "SG_REFUSED_SUPPRESSION_AS_ABSENCE",
    "SG_REFUSED_NO_MEMBER_IDENTITIES",
    "SG_REFUSED_NO_JUSTIFICATION",
    "SG_REFUSED_NO_REVIEWER",
    "SG_REFUSED_UNRECORDED_REVIEWER",
    "SG_REFUSED_NO_EXPIRY",
    "SG_REFUSED_EXPIRED",
    "SG_REFUSED_UNBOUNDED_SCOPE",
    "SG_REFUSED_LOGICAL_AS_EXACT",
    "SG_REFUSED_CROSS_ARTEFACT_INHERITANCE",
    "SG_REFUSED_STALE_CANDIDATE",
    "SG_REFUSED_TARGET_NOT_IN_POPULATION",
    "SG_REFUSED_INVALIDATED",
    "SG_REFUSED_COUNT_UNBALANCED",
}


class RegistryTests(unittest.TestCase):
    def test_the_refusal_registry_is_the_documented_set(self):
        self.assertEqual(set(sg.REFUSALS), REQUIRED_CODES)
        self.assertEqual(len(sg.REFUSALS), 14)

    def test_every_refusal_code_states_what_it_prevents(self):
        for code, (condition, prevents) in sg.REFUSALS.items():
            with self.subTest(code=code):
                self.assertTrue(condition)
                self.assertTrue(prevents)

    def test_the_five_dispositions_are_distinct_and_keep_findings(self):
        self.assertEqual(
            set(sg.DISPOSITIONS),
            {"ACTIVE", "EXPIRED", "INVALIDATED", "NON_ACTIONABLE", "PENDING_REVIEW"},
        )
        for disposition, (licenses, does_not) in sg.DISPOSITION_MEANINGS.items():
            with self.subTest(disposition=disposition):
                self.assertTrue(licenses)
                self.assertIn("finding", does_not + licenses)

    def test_the_seven_invalidation_triggers_are_registered(self):
        self.assertEqual(
            set(sg.TRIGGERS),
            {
                "candidate-identity-change",
                "source-tree-digest-change",
                "tool-identity-change",
                "expiry",
                "target-absent-from-population",
                "new-occurrence-at-logical-identity",
                "policy-basis-change",
            },
        )
        for trigger, (changes, disposition, prevents) in sg.TRIGGER_MEANINGS.items():
            with self.subTest(trigger=trigger):
                self.assertTrue(changes)
                self.assertIn(disposition, sg.DISPOSITIONS)
                self.assertTrue(prevents)


class ConstructionTests(unittest.TestCase):
    def test_a_suppression_without_an_id_is_refused(self):
        with self.assertRaises(ValueError):
            sg.Suppression(id="", record="r", locator="/l", record_sha256="0" * 64)

    def test_an_unknown_scope_is_refused(self):
        with self.assertRaises(ValueError):
            sg.Suppression(
                id="s", record="r", locator="/l", record_sha256="0" * 64,
                target_scope=sg.T_EXACT, scope="tree",
            )

    def test_an_unknown_disposition_is_refused(self):
        with self.assertRaises(ValueError):
            sg.Suppression(
                id="s", record="r", locator="/l", record_sha256="0" * 64,
                disposition="SUPPRESSED",
            )

    def test_a_record_that_is_not_a_suppression_states_why(self):
        with self.assertRaises(ValueError):
            sg.Suppression(
                id="s", record="r", locator="/l", record_sha256="0" * 64,
                classification=sg.C_NOT_A_SUPPRESSION,
            )

    def test_an_expiry_that_is_not_a_date_is_refused(self):
        with self.assertRaises(ValueError):
            sg.Suppression(
                id="s", record="r", locator="/l", record_sha256="0" * 64,
                expires_at="next year",
            )

    def test_the_reader_refuses_a_missing_member_list(self):
        record = sg.build_register(REPO_ROOT)[0].as_dict()
        record.pop("memberIds")
        with self.assertRaises(sg.Refusal) as raised:
            sg.Suppression.from_dict(record)
        self.assertEqual(raised.exception.code, sg.R_NO_MEMBERS)

    def test_the_reader_refuses_a_record_with_no_target(self):
        record = sg.build_register(REPO_ROOT)[0].as_dict()
        record.pop("target")
        with self.assertRaises(sg.Refusal) as raised:
            sg.Suppression.from_dict(record)
        self.assertEqual(raised.exception.code, sg.R_TARGET_ABSENT)


class RealRegisterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = sg.build_register(REPO_ROOT)
        cls.current = sg.candidate_identity(REPO_ROOT)
        cls.reviewers = sg.reviewer_register(REPO_ROOT)
        cls.population = sg.sarif_population(
            REPO_ROOT / "evidence" / "a1" / "SARIF.json",
            expected=sg._second_statement(REPO_ROOT, "a1-sarif-results"),
            display="evidence/a1/SARIF.json",
        )
        cls.admissions = [
            sg.admit(record, population=cls.population, reviewers=cls.reviewers,
                     as_of=cls.current.as_of, current=cls.current)
            for record in cls.records
        ]

    def test_the_register_round_trips(self):
        for record in self.records:
            with self.subTest(record=record.id):
                restored = sg.Suppression.from_dict(record.as_dict())
                self.assertEqual(restored.as_dict(), record.as_dict())

    def test_every_real_suppression_states_at_least_one_refusal(self):
        suppressions = [
            (record, admission)
            for record, admission in zip(self.records, self.admissions)
            if record.classification == sg.C_SUPPRESSION
        ]
        self.assertTrue(suppressions)
        for record, admission in suppressions:
            with self.subTest(record=record.id):
                self.assertTrue(admission.codes)
                self.assertEqual(admission.disposition, sg.D_NON_ACTIONABLE)

    def test_no_real_suppression_is_actionable(self):
        self.assertEqual(
            sum(1 for admission in self.admissions if admission.actionable), 0
        )

    def test_every_member_count_is_read_from_its_record(self):
        for record, admission in zip(self.records, self.admissions):
            with self.subTest(record=record.id):
                if record.member_count is not None:
                    self.assertEqual(admission.member_count, record.member_count)

    def test_the_aggregate_suppression_is_not_read_as_a_census(self):
        record = next(r for r in self.records if r.id == "t4-suppressions")
        self.assertFalse(record.members_recorded)
        self.assertEqual(record.member_ids, ())
        admission = sg.admit(record, population=self.population,
                             reviewers=self.reviewers, as_of=self.current.as_of,
                             current=self.current)
        self.assertIn(sg.R_NO_MEMBERS, admission.codes)

    def test_the_risk_acceptance_does_not_establish_a_reviewer_identity(self):
        record = next(r for r in self.records if r.id.startswith("openssh"))
        self.assertEqual(record.classification, sg.C_SUPPRESSION)
        admission = sg.admit(record, population=self.population,
                             reviewers=self.reviewers, as_of=self.current.as_of,
                             current=self.current)
        self.assertIn(sg.R_UNRECORDED_REVIEWER, admission.codes)
        self.assertNotIn(sg.R_NO_REVIEWER, admission.codes)
        self.assertTrue(record.reviewer_recorded_in.endswith("/decided_by"))
        self.assertNotIn(record.reviewer, self.reviewers)

    def test_a_superseded_disposition_is_not_a_suppression(self):
        record = next(r for r in self.records if r.id == "a1-superseded-disposition")
        self.assertEqual(record.classification, sg.C_NOT_A_SUPPRESSION)
        self.assertTrue(record.members_recorded)
        self.assertEqual(len(record.member_ids), 1)
        admission = sg.admit(record, population=self.population,
                             reviewers=self.reviewers, as_of=self.current.as_of,
                             current=self.current)
        self.assertEqual(admission.codes, ())
        self.assertEqual(admission.disposition, sg.D_NON_ACTIONABLE)

    def test_the_closure_exclusions_are_not_a_suppression(self):
        record = next(r for r in self.records if r.id == "t10-closure-exclusions")
        self.assertEqual(record.classification, sg.C_NOT_A_SUPPRESSION)
        self.assertIn("removes no finding", record.reason)

    def test_the_reconciliation_balances_and_removes_nothing(self):
        reconciliation = sg.reconcile(
            self.population, self.records, reviewers=self.reviewers,
            as_of=self.current.as_of, current=self.current,
        )
        self.assertTrue(reconciliation.balanced)
        self.assertEqual(reconciliation.enumerated, len(self.population.exact))
        self.assertEqual(
            len(reconciliation.suppressed) + len(reconciliation.unsuppressed),
            reconciliation.enumerated,
        )
        self.assertEqual(reconciliation.suppressed, ())
        self.assertEqual(len(reconciliation.unsuppressed), reconciliation.enumerated)


class SemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.population = sg.sarif_population(
            REPO_ROOT / "evidence" / "a1" / "SARIF.json",
            expected=sg._second_statement(REPO_ROOT, "a1-sarif-results"),
            display="evidence/a1/SARIF.json",
        )
        cls.members = sorted(cls.population.exact)
        cls.member = cls.members[0]
        cls.binding = cls.population.bindings[cls.member]
        cls.logical = sorted(cls.population.logical)[0]
        cls.rule = sorted(cls.population.rule)[0]
        cls.reviewers = {"synthetic control reviewer": ["in-memory control register"]}
        cls.as_of = "2026-11-24"
        cls.record = sg._synthetic_active(
            member=cls.member, rule=cls.rule, logical=cls.logical,
            binding=cls.binding, reviewer="synthetic control reviewer",
        )
        cls.current = sg.CurrentIdentity(candidate=cls.record.candidate, as_of=cls.as_of)

    def admit(self, record, **kwargs):
        kwargs.setdefault("population", self.population)
        kwargs.setdefault("reviewers", self.reviewers)
        kwargs.setdefault("as_of", self.as_of)
        kwargs.setdefault("current", self.current)
        return sg.admit(record, **kwargs)

    def test_a_well_formed_suppression_is_active(self):
        admission = self.admit(self.record)
        self.assertEqual(admission.codes, ())
        self.assertEqual(admission.disposition, sg.D_ACTIVE)
        self.assertTrue(admission.actionable)

    def test_a_suppressed_finding_is_still_counted_in_the_population(self):
        reconciliation = sg.reconcile(
            self.population, [self.record], reviewers=self.reviewers,
            as_of=self.as_of, current=self.current,
        )
        self.assertIn(self.member, self.population.exact)
        self.assertIn(self.member, reconciliation.suppressed)
        self.assertNotIn(self.member, reconciliation.unsuppressed)
        self.assertEqual(
            len(reconciliation.suppressed) + len(reconciliation.unsuppressed),
            reconciliation.enumerated,
        )
        self.assertEqual(len(reconciliation.suppressed), 1)

    def test_a_suppressed_finding_dropped_from_the_population_is_refused(self):
        reduced = sg.FindingPopulation(
            id="population-without-the-suppressed-finding",
            record=self.population.record,
            record_sha256=self.population.record_sha256,
            exact=tuple(m for m in self.population.exact if m != self.member),
            logical=self.population.logical,
            rule=self.population.rule,
            bindings=self.population.bindings,
        )
        with self.assertRaises(sg.Refusal) as raised:
            sg.reconcile(reduced, [self.record], reviewers=self.reviewers,
                         as_of=self.as_of, current=self.current)
        self.assertEqual(raised.exception.code, sg.R_AS_ABSENCE)

    def test_logical_scope_cannot_authorise_a_second_exact_occurrence(self):
        logical = dataclasses.replace(
            self.record, target_scope=sg.T_LOGICAL, target_identity=self.logical,
            scope=sg.SCOPE_EXACT, logical_identity=self.logical,
        )
        admission = self.admit(logical)
        self.assertIn(sg.R_LOGICAL_AS_EXACT, admission.codes)
        self.assertEqual(admission.disposition, sg.D_NON_ACTIONABLE)
        self.record.__class__  # keep the base record untouched
        result = sg.invalidate(
            logical, sg.TR_NEW_OCCURRENCE,
            current=sg.CurrentIdentity(
                new_occurrence_logical=self.logical,
                new_occurrence_exact="ff" * 32,
                as_of=self.as_of,
            ),
            population=self.population, as_of=self.as_of,
        )
        self.assertTrue(result.fired)
        self.assertEqual(result.disposition, sg.D_INVALIDATED)
        self.assertIn("ff" * 8, result.reason)

    def test_expiry_changes_the_disposition_to_expired_not_invalidated(self):
        expired = dataclasses.replace(self.record, expires_at="2026-01-01")
        admission = self.admit(expired)
        self.assertIn(sg.R_EXPIRED, admission.codes)
        self.assertEqual(admission.disposition, sg.D_EXPIRED)
        result = sg.invalidate(expired, sg.TR_EXPIRY, current=self.current,
                               population=self.population, as_of=self.as_of)
        self.assertTrue(result.fired)
        self.assertEqual(result.disposition, sg.D_EXPIRED)

    def test_invalidation_records_a_reason_and_deletes_nothing(self):
        after = sg.apply_invalidation(
            self.record,
            sg.invalidate(self.record, sg.TR_CANDIDATE,
                          current=sg.CurrentIdentity(candidate="candidate-b"),
                          population=self.population, as_of=self.as_of),
        )
        self.assertEqual(after.id, self.record.id)
        self.assertEqual(after.member_ids, self.record.member_ids)
        self.assertEqual(after.disposition, sg.D_INVALIDATED)
        self.assertEqual(len(after.invalidation), 1)
        self.assertIn("candidate-b", after.invalidation[0]["reason"])
        self.assertEqual(
            len(self.population.exact), len(self.population.exact)
        )

    def test_an_unrecorded_reviewer_is_refused(self):
        record = dataclasses.replace(
            self.record, reviewer="control-token-not-in-any-record",
            reviewer_recorded_in="not recorded",
        )
        self.assertIn(sg.R_UNRECORDED_REVIEWER, self.admit(record).codes)

    def test_a_scope_broader_than_its_target_is_refused(self):
        record = dataclasses.replace(self.record, scope=sg.SCOPE_RULE)
        self.assertIn(sg.R_UNBOUNDED_SCOPE, self.admit(record).codes)

    def test_a_cross_artefact_member_is_refused(self):
        other = next(
            m for m in self.members[1:]
            if self.population.bindings[m] != self.binding
        )
        record = dataclasses.replace(
            self.record, member_ids=(other,), member_count=1,
            target_identity=other, artefact=self.binding,
        )
        self.assertIn(sg.R_CROSS_ARTEFACT, self.admit(record).codes)

    def test_an_absent_target_is_refused(self):
        record = dataclasses.replace(
            self.record, target_identity="00" * 32, member_ids=("00" * 32,),
            member_count=1,
        )
        self.assertIn(sg.R_TARGET_ABSENT, self.admit(record).codes)

    def test_a_stale_candidate_is_refused(self):
        self.assertIn(
            sg.R_STALE_CANDIDATE,
            self.admit(self.record,
                       current=sg.CurrentIdentity(candidate="candidate-b")).codes,
        )

    def test_an_invalidated_record_is_refused(self):
        record = dataclasses.replace(self.record, disposition=sg.D_INVALIDATED)
        self.assertIn(sg.R_INVALIDATED, self.admit(record).codes)

    def test_a_missing_expiry_is_refused(self):
        record = dataclasses.replace(self.record, expires_at=None, unbounded=True)
        self.assertIn(sg.R_NO_EXPIRY, self.admit(record).codes)

    def test_a_missing_justification_is_refused(self):
        record = dataclasses.replace(self.record, justification="")
        self.assertIn(sg.R_NO_JUSTIFICATION, self.admit(record).codes)

    def test_a_missing_reviewer_is_refused(self):
        record = dataclasses.replace(self.record, reviewer=None,
                                     reviewer_recorded_in=None)
        self.assertIn(sg.R_NO_REVIEWER, self.admit(record).codes)

    def test_an_unbalanced_reconciliation_is_refused(self):
        record = dataclasses.replace(self.record, member_count=2)
        with self.assertRaises(sg.Refusal) as raised:
            sg.reconcile(self.population, [record], reviewers=self.reviewers,
                         as_of=self.as_of, current=self.current)
        self.assertEqual(raised.exception.code, sg.R_COUNT_UNBALANCED)

    def test_a_population_that_does_not_match_its_second_statement_is_refused(self):
        with self.assertRaises(sg.Refusal) as raised:
            sg.FindingPopulation(
                id="p", record="r", record_sha256="0" * 64,
                exact=tuple(self.members[:2]), logical=(), rule=(), expected=3,
            )
        self.assertEqual(raised.exception.code, sg.R_COUNT_UNBALANCED)


class InvalidationTriggerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        population = sg.sarif_population(
            REPO_ROOT / "evidence" / "a1" / "SARIF.json",
            expected=sg._second_statement(REPO_ROOT, "a1-sarif-results"),
            display="evidence/a1/SARIF.json",
        )
        member = sorted(population.exact)[0]
        cls.population = population
        cls.member = member
        cls.record = sg._synthetic_active(
            member=member, rule=sorted(population.rule)[0],
            logical=sorted(population.logical)[0],
            binding=population.bindings[member],
            reviewer="synthetic control reviewer",
        )

    def trigger(self, trigger, **kwargs):
        return sg.invalidate(self.record, trigger, **kwargs)

    def test_candidate_identity_change(self):
        result = self.trigger(
            sg.TR_CANDIDATE, current=sg.CurrentIdentity(candidate="candidate-b")
        )
        self.assertTrue(result.fired)
        self.assertEqual(result.disposition, sg.D_INVALIDATED)
        self.assertIn("candidate-a", result.reason)
        self.assertIn("candidate-b", result.reason)

    def test_source_tree_digest_change(self):
        result = self.trigger(
            sg.TR_SOURCE_TREE, current=sg.CurrentIdentity(source_tree="dd" * 32)
        )
        self.assertTrue(result.fired)
        self.assertIn("dd" * 8, result.reason)

    def test_tool_identity_change(self):
        result = self.trigger(
            sg.TR_TOOL, current=sg.CurrentIdentity(
                tool="forensics/tools/suppression_governance.py@ee"
            ),
        )
        self.assertTrue(result.fired)
        self.assertIn("@ee", result.reason)

    def test_expiry(self):
        result = self.trigger(sg.TR_EXPIRY, as_of="2027-06-01",
                              current=sg.CurrentIdentity(as_of="2027-06-01"))
        self.assertTrue(result.fired)
        self.assertEqual(result.disposition, sg.D_EXPIRED)
        self.assertIn("2027-01-01", result.reason)

    def test_target_absent_from_population(self):
        reduced = sg.FindingPopulation(
            id="without-the-target",
            record=self.population.record,
            record_sha256=self.population.record_sha256,
            exact=tuple(m for m in self.population.exact if m != self.member),
            logical=self.population.logical,
            rule=self.population.rule,
            bindings=self.population.bindings,
        )
        result = self.trigger(sg.TR_TARGET_ABSENT, population=reduced)
        self.assertTrue(result.fired)
        self.assertIn(self.member, result.reason)

    def test_new_occurrence_at_logical_identity(self):
        result = self.trigger(
            sg.TR_NEW_OCCURRENCE,
            current=sg.CurrentIdentity(
                new_occurrence_logical=self.record.logical_identity,
                new_occurrence_exact="ff" * 32,
            ),
        )
        self.assertTrue(result.fired)
        self.assertIn("ff" * 8, result.reason)

    def test_policy_basis_change(self):
        result = self.trigger(
            sg.TR_POLICY, current=sg.CurrentIdentity(policy_basis="control-policy@ff")
        )
        self.assertTrue(result.fired)
        self.assertIn("control-policy@aa", result.reason)
        self.assertIn("control-policy@ff", result.reason)

    def test_an_unrecorded_identity_is_not_run_rather_than_fired(self):
        without = dataclasses.replace(
            self.record, source_tree=None, tool=None, candidate=None,
            expires_at=None, logical_identity=None, policy_token=None,
        )
        for trigger in (sg.TR_SOURCE_TREE, sg.TR_TOOL, sg.TR_EXPIRY,
                        sg.TR_NEW_OCCURRENCE, sg.TR_POLICY):
            with self.subTest(trigger=trigger):
                result = sg.invalidate(without, trigger, population=self.population)
                self.assertEqual(result.status, sg.STATUS_NOT_RUN)


class ProducerTests(unittest.TestCase):
    def test_the_producer_is_deterministic(self):
        recorded = json.loads(INVALIDATION.read_text(encoding="utf-8"))["currentIdentity"]
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for target in (first, second):
                result = subprocess.run(
                    [sys.executable, str(PRODUCER), "--out", target,
                     "--candidate", recorded["candidate"],
                     "--as-of", recorded["asOf"]],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("SUPPRESSIONS.json", "INVALIDATION.json", "CONTROLS.json"):
                with self.subTest(name=name):
                    a = (Path(first) / name).read_bytes()
                    b = (Path(second) / name).read_bytes()
                    self.assertEqual(a, b)
                    self.assertEqual(a, (A6 / name).read_bytes())

    def test_the_producer_runs_at_the_current_candidate(self):
        with tempfile.TemporaryDirectory() as target:
            result = subprocess.run(
                [sys.executable, str(PRODUCER), "--out", target],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            document = json.loads(
                (Path(target) / "INVALIDATION.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                document["currentIdentity"]["candidate"],
                sg.candidate_identity(REPO_ROOT).candidate,
            )

    def test_the_recorded_documents_validate(self):
        for path in (SUPPRESSIONS, INVALIDATION, CONTROLS):
            with self.subTest(path=path.name):
                document = json.loads(path.read_text(encoding="utf-8"))
                self.assertIn("schema", document)
                self.assertEqual(document["model"], sg.MODEL_ID)

    def test_the_recorded_register_matches_a_fresh_read(self):
        document = json.loads(SUPPRESSIONS.read_text(encoding="utf-8"))
        fresh = [record.as_dict() for record in sg.build_register(REPO_ROOT)]
        self.assertEqual(document["records"], fresh)

    def test_the_controls_cover_every_code(self):
        document = json.loads(CONTROLS.read_text(encoding="utf-8"))
        self.assertEqual(set(document["totals"]["byCode"]), REQUIRED_CODES)
        self.assertTrue(all(count >= 1 for count in document["totals"]["byCode"].values()))
        for control in document["controls"]:
            with self.subTest(control=control["id"]):
                self.assertEqual(control["observedCode"], control["expectedCode"])

    def test_the_invalidation_controls_cover_every_trigger(self):
        document = json.loads(INVALIDATION.read_text(encoding="utf-8"))
        self.assertEqual(
            {control["trigger"] for control in document["controls"]}, set(sg.TRIGGERS)
        )
        for control in document["controls"]:
            with self.subTest(control=control["id"]):
                self.assertEqual(control["status"], sg.STATUS_FIRED)
                self.assertTrue(control["changedIdentity"])
                self.assertIn(control["changedIdentity"], control["reason"])

    def test_the_recorded_register_reports_its_dispositions(self):
        document = json.loads(SUPPRESSIONS.read_text(encoding="utf-8"))
        dispositions = {item["id"]: item["disposition"] for item in document["admissions"]}
        self.assertEqual(set(dispositions), {record.id for record in sg.build_register(REPO_ROOT)})
        self.assertEqual(
            document["totals"]["actionable"], 0
        )
        self.assertEqual(
            sum(document["totals"]["byDisposition"].values()),
            len(document["records"]),
        )


class CommandLineTests(unittest.TestCase):
    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            capture_output=True, text=True, check=False,
        )

    def test_register_exits_one_and_prints_every_code(self):
        result = self.run_cli("register")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("actionable=0", result.stdout)
        document = json.loads(SUPPRESSIONS.read_text(encoding="utf-8"))
        fired = {
            code for admission in document["admissions"] for code in admission["codes"]
        }
        for code in fired:
            with self.subTest(code=code):
                self.assertIn(code, result.stdout)
        self.assertEqual(len(result.stdout.strip().splitlines()), 12)

    def test_admit_a_suppression_exits_one_with_its_code(self):
        result = self.run_cli("admit", "t4-suppressions")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("disposition=NON_ACTIONABLE", result.stdout)
        self.assertIn(sg.R_NO_MEMBERS, result.stdout)

    def test_admit_a_non_suppression_exits_zero_with_no_code(self):
        result = self.run_cli("admit", "a1-superseded-disposition")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("codes=none", result.stdout)

    def test_admit_an_unknown_id_is_a_usage_error(self):
        result = self.run_cli("admit", "no-such-suppression")
        self.assertEqual(result.returncode, 2)
        self.assertIn(sg.R_TARGET_ABSENT, result.stderr)

    def test_invalidate_a_fired_trigger_exits_zero_and_prints_the_code(self):
        result = self.run_cli(
            "invalidate", "t4-suppressions", "--trigger", "candidate-identity-change"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("status=FIRED", result.stdout)
        self.assertIn(f"codes={sg.R_INVALIDATED}", result.stdout)

    def test_invalidate_a_trigger_that_cannot_fire_exits_one(self):
        result = self.run_cli(
            "invalidate", "t4-suppressions", "--trigger", "expiry"
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("status=NOT_RUN", result.stdout)
        self.assertIn(sg.R_NO_EXPIRY, result.stdout)

    def test_reconcile_exits_one_and_balances(self):
        result = self.run_cli("reconcile")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("balance=ok", result.stdout)
        self.assertIn("suppressed=0", result.stdout)
        self.assertIn("codes=", result.stdout)


class DocumentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOCUMENT.read_text(encoding="utf-8")

    def test_the_document_exists_and_names_its_implementation(self):
        for name in (
            "forensics/tools/suppression_governance.py",
            "forensics/tools/tests/test_suppression_governance.py",
            "evidence/a6/build_evidence.py",
            "evidence/a6/SUPPRESSIONS.json",
            "evidence/a6/INVALIDATION.json",
            "evidence/a6/CONTROLS.json",
        ):
            with self.subTest(name=name):
                self.assertIn(name, self.text)

    def test_every_refusal_code_appears_in_the_document(self):
        for code in sg.REFUSALS:
            with self.subTest(code=code):
                self.assertIn(code, self.text)

    def test_every_disposition_appears_in_the_document(self):
        for disposition in sg.DISPOSITIONS:
            with self.subTest(disposition=disposition):
                self.assertIn(disposition, self.text)

    def test_every_trigger_appears_in_the_document(self):
        for trigger in sg.TRIGGERS:
            with self.subTest(trigger=trigger):
                self.assertIn(trigger, self.text)

    def test_the_document_records_the_real_register_and_its_verdicts(self):
        document = json.loads(SUPPRESSIONS.read_text(encoding="utf-8"))
        dispositions = {item["id"]: item["disposition"] for item in document["admissions"]}
        for record_id, disposition in dispositions.items():
            with self.subTest(record=record_id):
                pattern = re.compile(
                    r"^\|\s*`" + re.escape(record_id) + r"`\s*\|.*\|\s*"
                    + re.escape(disposition) + r"\s*\|",
                    re.MULTILINE,
                )
                self.assertRegex(self.text, pattern)

    def test_the_document_states_the_recorded_totals(self):
        document = json.loads(SUPPRESSIONS.read_text(encoding="utf-8"))
        totals = document["totals"]
        self.assertIn(f"| records | {totals['records']} |", self.text)
        self.assertIn(f"| suppressions | {totals['suppressions']} |", self.text)
        self.assertIn(f"| actionable | {totals['actionable']} |", self.text)
        for disposition, count in totals["byDisposition"].items():
            with self.subTest(disposition=disposition):
                self.assertIn(f"| `{disposition}` | {count} |", self.text)

    def test_the_document_states_the_non_claims(self):
        for phrase in (
            "does not make a finding false",
            "does not make a finding not exist",
            "never an absence",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.text)

    def test_the_document_has_no_first_person(self):
        first_person = re.compile(
            r"\b(I|We|Our|My|Mine|Ours|Me|Us|we|our|my|mine|ours|me|us)\b"
        )
        self.assertEqual(first_person.findall(self.text), [])

    def test_the_receipt_has_no_first_person(self):
        if not RECEIPT.exists():
            self.skipTest("receipt is written after this file")
        first_person = re.compile(
            r"\b(I|We|Our|My|Mine|Ours|Me|Us|we|our|my|mine|ours|me|us)\b"
        )
        self.assertEqual(first_person.findall(RECEIPT.read_text(encoding="utf-8")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
