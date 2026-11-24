#!/usr/bin/env python3
"""Controls for completeness admission.

Each control exercises one rule of `docs/COMPLETENESS-ADMISSION.md`: the six base
states and the two additional states are distinct; an absent population is not an
empty one; an exit status is not a population; a sample is not a census; a
truncation must carry its bound and its unrecoverable-omitted flag; an expected
population must pre-exist the examined count; and every refusal code fires for the
substitution it names.

A control mutates a real declaration in memory. It is not a source change and not a
defect report: a control that fires proves the refusal works, not that the
substituted form occurs anywhere in the tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import completeness as ca  # noqa: E402

A5 = REPO_ROOT / "evidence" / "a5"
POPULATIONS = A5 / "POPULATIONS.json"
ADMISSION = A5 / "ADMISSION.json"
CONTROLS = A5 / "CONTROLS.json"
PRODUCER = A5 / "build_evidence.py"
DOCUMENT = REPO_ROOT / "docs" / "COMPLETENESS-ADMISSION.md"

BASE_STATES = {
    ca.S_COMPLETE,
    ca.S_SAMPLED,
    ca.S_TRUNCATED_BOUNDED,
    ca.S_ABSENT,
    ca.S_EMPTY,
    ca.S_UNKNOWN,
}
EXTRA_STATES = {ca.S_AGGREGATE_ONLY, ca.S_DEFERRED}


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sources(record: str = "evidence/example.json") -> dict:
    return {
        "expected": {"record": record, "locator": "expected"},
        "examined": {"record": record, "locator": "examined"},
        "omitted": {"record": record, "locator": "omitted"},
    }


def make(**overrides) -> ca.Population:
    fields = {
        "id": "synthetic",
        "subject": "a synthetic population",
        "kind": "census",
        "record": "evidence/example.json",
        "locator": "/population",
        "method": "constructed by the control",
        "expected": 10,
        "examined": 10,
        "omitted": 0,
        "omitted_members_recorded": True,
        "members_identified": True,
        "present": True,
        "bound_declared": False,
        "selection_declared": False,
        "distinct_members": 10,
        "sources": _sources(),
        "declared": ca.S_COMPLETE,
        "declared_basis": "a control declaration",
        "presence_basis": "present for the control",
        "members_basis": "ten distinct members",
    }
    fields.update(overrides)
    return ca.Population(**fields)


class RegistryTests(unittest.TestCase):
    def test_the_six_base_states_are_distinct(self):
        self.assertEqual(len(BASE_STATES), 6)
        self.assertTrue(BASE_STATES <= set(ca.STATES))

    def test_every_state_has_a_meaning(self):
        for state in ca.STATES:
            with self.subTest(state=state):
                licenses, does_not = ca.STATE_MEANINGS[state]
                self.assertTrue(licenses)
                self.assertTrue(does_not)

    def test_every_refusal_is_documented_in_the_module(self):
        for code, (condition, prevents) in ca.REFUSALS.items():
            with self.subTest(code=code):
                self.assertTrue(code.startswith("CA_REFUSED_"))
                self.assertTrue(condition)
                self.assertTrue(prevents)

    def test_unknown_extent_is_not_zero(self):
        self.assertIsInstance(ca.EXTENT_UNKNOWN, str)
        self.assertNotEqual(ca.EXTENT_UNKNOWN, 0)
        self.assertFalse(ca.EXTENT_UNKNOWN == 0)

    def test_the_required_refusal_codes_exist(self):
        required = {
            "CA_REFUSED_ABSENT_AS_EMPTY",
            "CA_REFUSED_UNRECORDED_POPULATION",
            "CA_REFUSED_EXIT_AS_COMPLETENESS",
            "CA_REFUSED_OMITTED_UNRECORDED",
            "CA_REFUSED_TRUNCATION_AS_COMPLETE",
            "CA_REFUSED_SAMPLE_AS_CENSUS",
            "CA_REFUSED_UNKNOWN_AS_COMPLETE",
            "CA_REFUSED_POPULATION_DRIFT",
            "CA_REFUSED_COUNT_INCONSISTENT",
            "CA_REFUSED_DUPLICATE_MEMBER",
        }
        self.assertTrue(required <= set(ca.REFUSALS))


class ConstructionTests(unittest.TestCase):
    def test_examined_plus_omitted_must_equal_expected(self):
        with self.assertRaises(ca.Refusal) as caught:
            make(omitted=1)
        self.assertEqual(caught.exception.code, ca.R_COUNT_INCONSISTENT)

    def test_examined_may_not_exceed_expected(self):
        with self.assertRaises(ca.Refusal) as caught:
            make(examined=11, distinct_members=11)
        self.assertEqual(caught.exception.code, ca.R_COUNT_INCONSISTENT)

    def test_a_duplicate_member_is_refused(self):
        with self.assertRaises(ca.Refusal) as caught:
            make(distinct_members=9)
        self.assertEqual(caught.exception.code, ca.R_DUPLICATE_MEMBER)

    def test_a_count_sourced_from_an_exit_status_is_refused(self):
        sources = _sources()
        sources["expected"] = {"record": "the harness", "locator": "exit status"}
        with self.assertRaises(ca.Refusal) as caught:
            make(sources=sources)
        self.assertEqual(caught.exception.code, ca.R_EXIT_AS_COMPLETENESS)

    def test_an_undeclared_state_is_refused(self):
        with self.assertRaises(ca.Refusal) as caught:
            make(declared="")
        self.assertEqual(caught.exception.code, ca.R_STATE_UNDECLARED)

    def test_an_unknown_kind_is_refused(self):
        with self.assertRaises(ca.Refusal) as caught:
            make(kind="guess")
        self.assertEqual(caught.exception.code, ca.R_STATE_UNDECLARED)

    def test_an_integer_expected_must_name_a_record(self):
        sources = _sources()
        sources["expected"] = {"record": "", "locator": "expected"}
        with self.assertRaises(ca.Refusal) as caught:
            make(sources=sources)
        self.assertEqual(caught.exception.code, ca.R_UNRECORDED_POPULATION)

    def test_a_missing_source_is_refused(self):
        sources = _sources()
        del sources["examined"]
        with self.assertRaises(ca.Refusal) as caught:
            make(sources=sources)
        self.assertEqual(caught.exception.code, ca.R_UNRECORDED_POPULATION)


class ReadPopulationTests(unittest.TestCase):
    def block(self, **overrides) -> dict:
        value = {
            "expected": 4,
            "examined": 4,
            "omitted": 0,
            "omittedMembersRecorded": True,
            "membersIdentified": True,
            "present": True,
            "boundDeclared": False,
            "selectionDeclared": False,
        }
        value.update(overrides)
        return value

    def test_a_complete_block_is_read_unchanged(self):
        self.assertEqual(ca.read_population(self.block()), self.block())

    def test_unknown_is_accepted_for_the_extents(self):
        block = self.block(expected=ca.EXTENT_UNKNOWN, omitted=ca.EXTENT_UNKNOWN)
        self.assertEqual(ca.read_population(block), block)

    def test_a_missing_expected_is_refused_not_defaulted_to_zero(self):
        block = self.block()
        del block["expected"]
        with self.assertRaises(ca.Refusal) as caught:
            ca.read_population(block)
        self.assertEqual(caught.exception.code, ca.R_UNRECORDED_POPULATION)

    def test_a_missing_presence_is_refused_not_defaulted_to_present(self):
        block = self.block()
        del block["present"]
        with self.assertRaises(ca.Refusal) as caught:
            ca.read_population(block)
        self.assertEqual(caught.exception.code, ca.R_UNRECORDED_POPULATION)

    def test_a_missing_omitted_flag_is_refused(self):
        block = self.block()
        del block["omittedMembersRecorded"]
        with self.assertRaises(ca.Refusal) as caught:
            ca.read_population(block)
        self.assertEqual(caught.exception.code, ca.R_OMITTED_UNRECORDED)

    def test_a_non_boolean_flag_is_refused(self):
        with self.assertRaises(ca.Refusal) as caught:
            ca.read_population(self.block(membersIdentified="yes"))
        self.assertEqual(caught.exception.code, ca.R_STATE_UNDECLARED)

    def test_a_missing_locator_is_refused(self):
        with self.assertRaises(ca.Refusal) as caught:
            ca.read_population({"population": self.block()}, "/absent")
        self.assertEqual(caught.exception.code, ca.R_UNRECORDED_POPULATION)


class StateTests(unittest.TestCase):
    def test_a_census_is_complete(self):
        population = make()
        self.assertEqual(ca.supported_state(population), ca.S_COMPLETE)
        self.assertIsNone(ca.admit(population).refusal)

    def test_a_sample_is_sampled(self):
        population = make(
            kind="sample",
            expected=10,
            examined=4,
            omitted=6,
            distinct_members=4,
            selection_declared=True,
            omitted_members_recorded=False,
            declared=ca.S_SAMPLED,
        )
        self.assertEqual(ca.supported_state(population), ca.S_SAMPLED)
        self.assertIsNone(ca.admit(population).refusal)

    def test_a_truncation_is_bounded(self):
        population = make(
            kind="truncation",
            expected=10,
            examined=4,
            omitted=6,
            distinct_members=4,
            bound_declared=True,
            omitted_members_recorded=False,
            declared=ca.S_TRUNCATED_BOUNDED,
        )
        self.assertEqual(ca.supported_state(population), ca.S_TRUNCATED_BOUNDED)
        self.assertIsNone(ca.admit(population).refusal)

    def test_an_aggregate_without_members_is_not_complete(self):
        population = make(
            expected=10,
            examined=0,
            omitted=10,
            omitted_members_recorded=False,
            members_identified=False,
            distinct_members=None,
        )
        self.assertEqual(ca.supported_state(population), ca.S_AGGREGATE_ONLY)
        self.assertEqual(ca.admit(population).refusal, ca.R_OMITTED_UNRECORDED)

    def test_a_deferred_population_is_not_absent(self):
        population = make(
            kind="not-run",
            expected=7,
            examined=0,
            omitted=7,
            omitted_members_recorded=True,
            members_identified=True,
            distinct_members=None,
            declared=ca.S_DEFERRED,
        )
        self.assertEqual(ca.supported_state(population), ca.S_DEFERRED)
        self.assertIsNone(ca.admit(population).refusal)

    def test_an_unstated_population_is_unknown(self):
        population = make(
            kind="scan",
            expected=ca.EXTENT_UNKNOWN,
            examined=73,
            omitted=ca.EXTENT_UNKNOWN,
            distinct_members=73,
            declared=ca.S_UNKNOWN,
            sources={
                "expected": {"record": "", "locator": "no denominator"},
                "examined": {"record": "evidence/example.json", "locator": "count"},
                "omitted": {"record": "", "locator": "unknown"},
            },
        )
        self.assertEqual(ca.supported_state(population), ca.S_UNKNOWN)
        self.assertIsNone(ca.admit(population).refusal)

    def test_a_complete_declaration_over_an_empty_population_is_admitted_as_empty(self):
        population = make(
            expected=0,
            examined=0,
            omitted=0,
            distinct_members=0,
            members_identified=False,
            declared=ca.S_COMPLETE,
        )
        admission = ca.admit(population)
        self.assertIsNone(admission.refusal)
        self.assertEqual(admission.state, ca.S_EMPTY)


class TransitionTests(unittest.TestCase):
    """Every state pair the rule forbids is refused with its named code."""

    def test_complete_over_a_sample(self):
        population = make(
            expected=10, examined=4, omitted=6, distinct_members=4,
            selection_declared=True, omitted_members_recorded=False,
        )
        self.assertEqual(ca.admit(population).refusal, ca.R_SAMPLE_AS_CENSUS)

    def test_complete_over_a_truncation(self):
        population = make(
            expected=10, examined=4, omitted=6, distinct_members=4,
            bound_declared=True, omitted_members_recorded=False,
        )
        self.assertEqual(ca.admit(population).refusal, ca.R_TRUNCATION_AS_COMPLETE)

    def test_complete_over_an_absent_population(self):
        population = make(present=False)
        self.assertEqual(ca.admit(population).refusal, ca.R_ABSENT_AS_OBSERVED)

    def test_complete_over_an_aggregate(self):
        population = make(
            expected=10, examined=0, omitted=10,
            omitted_members_recorded=False, members_identified=False,
            distinct_members=None,
        )
        self.assertEqual(ca.admit(population).refusal, ca.R_OMITTED_UNRECORDED)

    def test_complete_over_an_unidentified_count(self):
        population = make(members_identified=False)
        self.assertEqual(ca.admit(population).refusal, ca.R_MEMBER_UNIDENTIFIED)

    def test_complete_over_an_unknown_population(self):
        population = make(
            expected=ca.EXTENT_UNKNOWN, examined=5, omitted=ca.EXTENT_UNKNOWN,
            distinct_members=5,
            sources={
                "expected": {"record": "evidence/example.json", "locator": "unknown"},
                "examined": {"record": "evidence/example.json", "locator": "count"},
                "omitted": {"record": "evidence/example.json", "locator": "unknown"},
            },
        )
        self.assertEqual(ca.admit(population).refusal, ca.R_UNKNOWN_AS_COMPLETE)

    def test_complete_with_no_expected_record(self):
        population = make(
            expected=ca.EXTENT_UNKNOWN, examined=5, omitted=ca.EXTENT_UNKNOWN,
            distinct_members=5,
            sources={
                "expected": {"record": "", "locator": "no denominator"},
                "examined": {"record": "evidence/example.json", "locator": "count"},
                "omitted": {"record": "", "locator": "unknown"},
            },
        )
        self.assertEqual(ca.admit(population).refusal, ca.R_UNRECORDED_POPULATION)

    def test_a_sample_with_no_population(self):
        population = make(
            kind="sample",
            expected=ca.EXTENT_UNKNOWN, examined=5, omitted=ca.EXTENT_UNKNOWN,
            distinct_members=5, selection_declared=True, declared=ca.S_SAMPLED,
            sources={
                "expected": {"record": "", "locator": "no denominator"},
                "examined": {"record": "evidence/example.json", "locator": "count"},
                "omitted": {"record": "", "locator": "unknown"},
            },
        )
        self.assertEqual(ca.admit(population).refusal, ca.R_SAMPLE_WITHOUT_POPULATION)

    def test_absent_declared_over_a_present_population(self):
        population = make(declared=ca.S_ABSENT)
        self.assertEqual(ca.admit(population).refusal, ca.R_STATE_CONTRADICTED)

    def test_empty_declared_over_a_present_population(self):
        population = make(declared=ca.S_EMPTY)
        self.assertEqual(ca.admit(population).refusal, ca.R_STATE_CONTRADICTED)


class AbsentAndEmptyTests(unittest.TestCase):
    """ABSENT and EMPTY are not interchangeable in either direction."""

    def test_absent_read_as_empty(self):
        population = make(present=False, declared=ca.S_EMPTY)
        self.assertEqual(ca.admit(population).refusal, ca.R_ABSENT_AS_EMPTY)

    def test_empty_read_as_absent(self):
        population = make(
            expected=0, examined=0, omitted=0, distinct_members=0,
            members_identified=False, declared=ca.S_ABSENT,
        )
        self.assertEqual(ca.admit(population).refusal, ca.R_EMPTY_AS_ABSENT)

    def test_absent_is_admitted_as_absent_and_not_as_empty(self):
        population = make(present=False, declared=ca.S_ABSENT)
        admission = ca.admit(population)
        self.assertIsNone(admission.refusal)
        self.assertEqual(admission.state, ca.S_ABSENT)

    def test_empty_is_admitted_as_empty_and_not_as_absent(self):
        population = make(
            expected=0, examined=0, omitted=0, distinct_members=0,
            members_identified=False, declared=ca.S_EMPTY,
        )
        admission = ca.admit(population)
        self.assertIsNone(admission.refusal)
        self.assertEqual(admission.state, ca.S_EMPTY)

    def test_an_exit_status_cannot_stand_in_for_a_population(self):
        with self.assertRaises(ca.Refusal) as caught:
            ca.from_exit_status(0, "the negative-control harness")
        self.assertEqual(caught.exception.code, ca.R_EXIT_AS_COMPLETENESS)


class RecordedInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.populations = ca.build_populations(REPO_ROOT)

    def test_the_registry_reads_every_registered_population(self):
        self.assertEqual(len(self.populations), len(ca.SPECS))
        self.assertEqual({p.id for p in self.populations}, set(ca.SPECS_BY_ID))

    def test_the_real_inventory_matches_the_committed_record(self):
        document = json.loads(POPULATIONS.read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], ca.POPULATIONS_SCHEMA)
        self.assertEqual(document["model"], ca.MODEL_ID)
        self.assertEqual(
            canonical(document["populations"]),
            canonical([p.as_dict() for p in self.populations]),
        )

    def test_the_real_admission_matches_the_committed_record(self):
        document = json.loads(ADMISSION.read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], ca.ADMISSION_SCHEMA)
        self.assertEqual(
            canonical(document["populations"]),
            canonical([ca.admit(p).as_dict() for p in self.populations]),
        )

    def test_every_real_declaration_verifies_against_its_record(self):
        for population in self.populations:
            with self.subTest(population=population.id):
                self.assertEqual(
                    ca.verify_declaration(population, REPO_ROOT), "checked"
                )

    def test_the_recorded_states_by_id(self):
        states = {p.id: ca.admit(p).state for p in self.populations}
        self.assertEqual(
            sorted(i for i, s in states.items() if s == ca.S_COMPLETE),
            [
                "a1-sarif-results",
                "etp-claims",
                "t10-closure-exclusions",
                "t4-ignored-tests",
                "t4-unsafe-sites",
            ],
        )
        self.assertEqual(
            sorted(i for i, s in states.items() if s == ca.S_TRUNCATED_BOUNDED),
            [
                "curl-edge-sample",
                "curl-residual-sites",
                "p1000-campaign-families",
                "ssh-edge-sample",
            ],
        )
        self.assertEqual(
            sorted(i for i, s in states.items() if s == ca.S_ABSENT),
            ["curl-edge-records", "ssh-edge-records"],
        )
        self.assertEqual(
            sorted(i for i, s in states.items() if s == ca.S_UNKNOWN),
            ["etp6-package-inputs", "o11-interop-scripts"],
        )
        self.assertEqual(
            sorted(i for i, s in states.items() if s == ca.S_AGGREGATE_ONLY),
            ["t11-satisfied-runs", "t4-suppressions"],
        )
        self.assertEqual(
            sorted(i for i, s in states.items() if s == ca.S_DEFERRED),
            ["timing-not-run"],
        )
        self.assertEqual([i for i, s in states.items() if s == ca.S_EMPTY], [])

    def test_the_real_refusals_by_id_and_code(self):
        refusals = {
            p.id: ca.admit(p).refusal
            for p in self.populations
            if ca.admit(p).refusal is not None
        }
        self.assertEqual(
            refusals,
            {
                "t4-suppressions": ca.R_OMITTED_UNRECORDED,
                "curl-edge-records": ca.R_ABSENT_AS_OBSERVED,
                "ssh-edge-records": ca.R_ABSENT_AS_OBSERVED,
                "t11-satisfied-runs": ca.R_MEMBER_UNIDENTIFIED,
                "etp6-package-inputs": ca.R_UNRECORDED_POPULATION,
            },
        )

    def test_the_two_edge_sidecars_are_absent_from_the_tracked_tree(self):
        edges = {p.id: p for p in self.populations}
        for name in ("curl-edge-records", "ssh-edge-records"):
            with self.subTest(population=name):
                population = edges[name]
                self.assertFalse(population.present)
                self.assertEqual(population.examined, 0)
                self.assertEqual(population.omitted, population.expected)
                self.assertIn("git ls-files", population.presence_basis)

    def test_no_recorded_population_is_sampled_or_empty(self):
        states = {ca.admit(p).state for p in self.populations}
        self.assertNotIn(ca.S_SAMPLED, states)
        self.assertNotIn(ca.S_EMPTY, states)


class ControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.populations = ca.build_populations(REPO_ROOT)
        cls.controls = ca.build_controls(cls.populations, REPO_ROOT)

    def test_every_refusal_code_has_a_control(self):
        covered = {control["expectedCode"] for control in self.controls}
        self.assertEqual(covered, set(ca.REFUSALS))

    def test_every_control_fires_its_named_code(self):
        for control in self.controls:
            with self.subTest(control=control["id"]):
                self.assertEqual(control["observedCode"], control["expectedCode"])

    def test_the_controls_match_the_committed_record(self):
        document = json.loads(CONTROLS.read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], ca.CONTROLS_SCHEMA)
        self.assertEqual(canonical(document["controls"]), canonical(self.controls))
        self.assertEqual(
            document["totals"]["controls"], len(self.controls)
        )

    def test_the_controls_are_deterministic(self):
        again = ca.build_controls(self.populations, REPO_ROOT)
        self.assertEqual(canonical(again), canonical(self.controls))


class ProducerTests(unittest.TestCase):
    def load_producer(self):
        spec = importlib.util.spec_from_file_location("a5_build_evidence", PRODUCER)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def test_the_producer_reproduces_the_committed_files_byte_for_byte(self):
        producer = self.load_producer()
        documents = producer.build(REPO_ROOT)
        for name, text in documents.items():
            with self.subTest(document=name):
                self.assertEqual((A5 / name).read_text(encoding="utf-8"), text)

    def test_two_producer_runs_are_byte_identical(self):
        producer = self.load_producer()
        first = producer.build(REPO_ROOT)
        second = producer.build(REPO_ROOT)
        self.assertEqual(first, second)

    def test_the_producer_refuses_when_a_count_cannot_be_derived(self):
        producer = self.load_producer()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evidence").mkdir()
            with self.assertRaises(ca.Refusal) as caught:
                producer.build(root)
            self.assertTrue(caught.exception.code.startswith("CA_REFUSED_"))


class CommandLineTests(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ca.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_inventory_reports_the_states_and_exits_one_on_a_refusal(self):
        code, out, _ = self.run_cli(["inventory"])
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertEqual(len(report["populations"]), len(ca.SPECS))
        self.assertEqual(report["totals"]["refused"], 5)

    def test_admit_an_admitted_population_exits_zero(self):
        code, out, _ = self.run_cli(["admit", "curl-residual-sites"])
        self.assertEqual(code, 0)
        self.assertIn("state=TRUNCATED_BOUNDED", out)
        self.assertIn("refusal=admitted", out)

    def test_admit_a_refused_population_exits_one_and_prints_the_code(self):
        code, out, _ = self.run_cli(["admit", "t4-suppressions"])
        self.assertEqual(code, 1)
        self.assertIn(ca.R_OMITTED_UNRECORDED, out)

    def test_an_unknown_population_id_exits_two(self):
        code, out, err = self.run_cli(["admit", "no-such-population"])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn(ca.R_UNRECORDED_POPULATION, err)

    def test_an_unreadable_declaration_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("not json", encoding="utf-8")
            code, out, err = self.run_cli(["admit", str(path)])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn(ca.R_UNRECORDED_POPULATION, err)

    def test_check_every_recorded_population_exits_one(self):
        code, out, _ = self.run_cli(["check", str(POPULATIONS)])
        self.assertEqual(code, 1)
        self.assertIn("populations=16", out)

    def test_check_a_single_admitted_declaration_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "one.json"
            path.write_text(
                json.dumps(make().as_dict()), encoding="utf-8"
            )
            code, out, _ = self.run_cli(["check", str(path)])
        self.assertEqual(code, 0)
        self.assertIn("admitted=1 refused=0", out)
        self.assertIn("native=NOT_RUN", out)

    def test_a_declaration_that_drifted_from_its_record_exits_one(self):
        document = json.loads(POPULATIONS.read_text(encoding="utf-8"))
        target = next(
            item for item in document["populations"]
            if item["id"] == "curl-residual-sites"
        )
        target["expected"] += 1
        target["omitted"] += 1
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "drifted.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            code, out, _ = self.run_cli(["check", str(path)])
        self.assertEqual(code, 1)
        self.assertIn(ca.R_POPULATION_DRIFT, out)
        self.assertIn("populations=16 admitted=10 refused=6", out)


class DocumentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOCUMENT.read_text(encoding="utf-8")
        cls.populations = ca.build_populations(REPO_ROOT)

    def test_the_document_exists_and_names_its_implementation(self):
        for name in (
            "forensics/tools/completeness.py",
            "forensics/tools/tests/test_completeness.py",
            "evidence/a5/build_evidence.py",
            "evidence/a5/POPULATIONS.json",
            "evidence/a5/ADMISSION.json",
            "evidence/a5/CONTROLS.json",
        ):
            with self.subTest(name=name):
                self.assertIn(name, self.text)

    def test_every_refusal_code_appears_in_the_document(self):
        for code in ca.REFUSALS:
            with self.subTest(code=code):
                self.assertIn(code, self.text)

    def test_every_state_appears_in_the_document(self):
        for state in ca.STATES:
            with self.subTest(state=state):
                self.assertIn(state, self.text)

    def test_the_document_records_every_population_and_its_state(self):
        for population in self.populations:
            with self.subTest(population=population.id):
                state = ca.admit(population).state
                pattern = re.compile(
                    r"^\|\s*`" + re.escape(population.id) + r"`\s*\|.*\|\s*"
                    + re.escape(state) + r"\s*\|",
                    re.MULTILINE,
                )
                self.assertRegex(self.text, pattern)

    def test_the_document_states_the_recorded_totals(self):
        totals = ca.admission_document(self.populations)["totals"]
        self.assertIn(f"| populations | {totals['populations']} |", self.text)
        self.assertIn(f"| admitted | {totals['admitted']} |", self.text)
        self.assertIn(f"| refused | {totals['refused']} |", self.text)
        for state, count in totals["byState"].items():
            with self.subTest(state=state):
                self.assertIn(f"| `{state}` | {count} |", self.text)

    def test_the_document_has_no_first_person(self):
        first_person = re.compile(
            r"\b(I|We|Our|My|Mine|Ours|Me|Us|we|our|my|mine|ours|me|us)\b"
        )
        self.assertEqual(first_person.findall(self.text), [])

    def test_the_receipt_has_no_first_person(self):
        receipt = A5 / "RECEIPT.md"
        if not receipt.exists():
            self.skipTest("receipt is written after this file")
        first_person = re.compile(
            r"\b(I|We|Our|My|Mine|Ours|Me|Us|we|our|my|mine|ours|me|us)\b"
        )
        self.assertEqual(first_person.findall(receipt.read_text(encoding="utf-8")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
