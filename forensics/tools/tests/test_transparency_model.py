#!/usr/bin/env python3
"""Controls for forensics/tools/transparency_model.py and the B7 records.

The model must not import the implementation, the clauses must be verbatim
§B.23 bullets, the enumeration must reach its declared bound, every invariant
must be violated individually by a fixture and caught, the canary must fire, the
differential's NOT_RUN rows must be labelled, the records must reproduce byte
for byte, the CLI must use its three exit codes, and the document must name every
code, invariant and bound.

Run directly (`python3 forensics/tools/tests/test_transparency_model.py`) or
with `python3 -m unittest discover -s forensics/tools/tests`.
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import transparency_model as bm  # noqa: E402

TOOL = TOOLS / "transparency_model.py"
DOCUMENT = REPO / "docs/TRANSPARENCY-FORMAL-ASSURANCE.md"
EVIDENCE = REPO / "evidence/b7"
PRODUCER = EVIDENCE / "build_evidence.py"

BOUND = 5
ALPHABET = 14
SEQUENCES = 579195
STATES = 1871
TRANSITIONS = 7770
COMPARED = 219

IMPLEMENTATION_MODULES = ("tlog", "monitor", "corrections", "thresholds", "publication")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def replay(
    sequence: list[str], fault: str | None = None
) -> tuple[bm.State, list[dict[str, str]]]:
    state = bm.INITIAL_STATE
    for operation in sequence:
        state, _accepted, _code = bm.step(state, operation, fault)
    return state, bm.check(state)


class Structure(unittest.TestCase):
    """The model is independent, the clauses are sourced, the state is declared."""

    def test_the_model_does_not_import_an_implementation(self) -> None:
        for function in (
            bm.root_of,
            bm.step,
            bm.check,
            bm.run_model,
            bm.inclusion_holds,
            bm.inclusion_rejects_a_lie,
        ):
            function = getattr(function, "__wrapped__", function)
            for name in IMPLEMENTATION_MODULES:
                self.assertNotIn(
                    name,
                    function.__globals__,
                    f"{function.__name__} resolves {name} through its globals",
                )

    def test_the_model_source_has_no_top_level_import(self) -> None:
        tree = ast.parse(TOOL.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name, IMPLEMENTATION_MODULES)
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn(node.module or "", IMPLEMENTATION_MODULES)

    def test_model_record_is_consistent_and_hashed(self) -> None:
        record = bm.model_record()
        self.assertEqual(record["schema"], bm.SCHEMA_MODEL)
        self.assertEqual(record["digest"], bm.record_digest(record))
        self.assertEqual(record["bound"], BOUND)
        self.assertEqual(record["alphabetSize"], ALPHABET)
        self.assertEqual(list(record["alphabet"]), list(bm.OPERATIONS))
        for field in bm.STATE_FIELDS:
            self.assertIn(field, record["stateFields"])
        self.assertEqual([row["id"] for row in record["invariants"]], list(bm.INVARIANT_IDS))

    def test_every_invariant_names_operations_and_an_assumption(self) -> None:
        for invariant in bm.INVARIANTS:
            self.assertTrue(invariant["operations"], invariant["id"])
            self.assertTrue(invariant["assumption"], invariant["id"])
            for operation in invariant["operations"]:
                self.assertIn(operation, bm.OPERATIONS)
            self.assertIn(invariant["brokenBy"], bm.CANARIES)

    def test_every_clause_is_a_verbatim_b23_bullet(self) -> None:
        authority = bm.authority_clauses()
        self.assertEqual(len(authority), 12)
        for invariant in bm.INVARIANTS:
            self.assertIn(invariant["clause"], authority, invariant["id"])
        record = bm.model_record()
        self.assertEqual({row["clause"] for row in record["clauses"]}, set(authority))
        modelled = sum(1 for row in record["clauses"] if row["modelled"])
        self.assertEqual(modelled, 7)
        self.assertEqual(sum(1 for row in record["clauses"] if not row["modelled"]), 5)

    def test_a_fabricated_clause_is_refused(self) -> None:
        with self.assertRaises(bm.Refusal) as raised:
            bm.assert_sourced("a checkpoint is always accepted;", bm.authority_clauses())
        self.assertEqual(raised.exception.code, "BM_REFUSED_INVARIANT_UNSOURCED")

    def test_the_model_root_matches_rfc_6962(self) -> None:
        import tlog

        for committed in ((), ("claim-0",), ("claim-0", "other-1"),
                          ("claim-0", "claim-1", "other-2")):
            expected = tlog.root_from_entries(
                [item.encode("utf-8") for item in committed]
            ).hex()
            self.assertEqual(bm.root_of(committed), expected, committed)

    def test_the_inclusion_verifier_accepts_the_truth_and_rejects_a_lie(self) -> None:
        for committed in (("claim-0",), ("claim-0", "other-1"),
                          ("claim-0", "other-1", "claim-2")):
            root = bm.root_of(committed)
            for index in range(len(committed)):
                self.assertTrue(bm.inclusion_holds(committed, index, root))
                self.assertTrue(bm.inclusion_rejects_a_lie(committed, index, root))


class Enumeration(unittest.TestCase):
    """The enumeration reaches its declared bound and finds no violation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.record = bm.enumerate_model(BOUND)

    def test_the_enumeration_completes_within_its_bound(self) -> None:
        self.assertEqual(self.record["bound"], BOUND)
        self.assertEqual(self.record["sequences"], SEQUENCES)
        self.assertEqual(self.record["sequenceSpace"], bm.sequence_space(BOUND))
        self.assertEqual(self.record["maxDepthReached"], BOUND)
        self.assertEqual(self.record["statesReached"], STATES)
        self.assertEqual(
            self.record["transitionsExplored"],
            self.record["statesExpanded"] * ALPHABET,
        )
        self.assertEqual(self.record["violationCount"], 0)
        self.assertEqual(self.record["code"], bm.CODE_OK)

    def test_every_invariant_is_checked(self) -> None:
        self.assertEqual(len(self.record["invariants"]), 8)
        for row in self.record["invariants"]:
            self.assertEqual(row["checked"], STATES, row["id"])
            self.assertEqual(row["violations"], 0, row["id"])

    def test_the_enumeration_refuses_a_truncated_run(self) -> None:
        with self.assertRaises(bm.Refusal) as raised:
            bm.enumerate_model(BOUND, limit=BOUND - 1)
        self.assertEqual(raised.exception.code, "BM_REFUSED_ENUMERATION_TRUNCATED")

    def test_a_truncated_record_is_refused(self) -> None:
        record = dict(self.record)
        record["maxDepthReached"] = BOUND - 1
        with self.assertRaises(bm.Refusal) as raised:
            bm.validate_enumeration(record, bm.model_record(), bm.run_canaries(BOUND))
        self.assertEqual(raised.exception.code, "BM_REFUSED_ENUMERATION_TRUNCATED")

    def test_a_bound_above_the_maximum_is_usage(self) -> None:
        with self.assertRaises(bm.Refusal) as raised:
            bm.enumerate_model(bm.MAX_BOUND + 1)
        self.assertEqual(raised.exception.code, "BM_REFUSED_USAGE")


class Canary(unittest.TestCase):
    """Every invariant can fail, and the fixture's witness replays to the failure."""

    def test_the_canary_is_detected(self) -> None:
        canaries = bm.run_canaries(BOUND)
        self.assertTrue(canaries["allDetected"])
        self.assertEqual(len(canaries["canaries"]), 8)
        for row in canaries["canaries"]:
            self.assertTrue(row["detected"], row["id"])
            self.assertGreater(row["targetViolations"], 0, row["id"])
            self.assertTrue(row["firstWitness"]["sequence"], row["id"])
            self.assertEqual(
                row["firstWitness"]["invariant"], row["targetInvariant"], row["id"]
            )

    def test_each_invariant_is_individually_violated_and_caught(self) -> None:
        for fault, meta in bm.CANARIES.items():
            with self.subTest(fault=fault):
                record = bm.enumerate_model(BOUND, fault=fault)
                counts = bm.violations_by_invariant(record["violations"])
                self.assertGreater(counts[meta["invariant"]], 0)
                witness = record["violations"][0]
                self.assertEqual(witness["invariant"], meta["invariant"])
                state, violations = replay(witness["sequence"], fault)
                self.assertTrue(
                    any(item["invariant"] == meta["invariant"] for item in violations),
                    f"the witness does not replay: {witness['sequence']}",
                )

    def test_a_missed_canary_is_refused(self) -> None:
        canaries = bm.run_canaries(BOUND)
        for row in canaries["canaries"]:
            row["detected"] = False
        canaries["allDetected"] = False
        with self.assertRaises(bm.Refusal) as raised:
            bm.validate_enumeration(bm.enumerate_model(BOUND), bm.model_record(), canaries)
        self.assertEqual(raised.exception.code, "BM_REFUSED_CANARY_NOT_DETECTED")


class Differential(unittest.TestCase):
    """The model and the real modules agree, and NOT_RUN is labelled, not counted."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.record = bm.differential()

    def test_the_differential_agrees(self) -> None:
        self.assertEqual(self.record["sequences"], COMPARED)
        self.assertEqual(self.record["compared"], COMPARED)
        self.assertEqual(self.record["agreed"], COMPARED)
        self.assertEqual(self.record["disagreementCount"], 0)
        self.assertEqual(self.record["notRunCount"], 0)
        self.assertEqual(self.record["code"], bm.CODE_OK)
        bm.assert_differential(self.record)

    def test_every_operation_is_driven(self) -> None:
        driven = {
            operation
            for row in self.record["rows"]
            for operation in row["sequence"]
        }
        self.assertEqual(driven, set(bm.OPERATIONS))

    def test_a_not_run_row_is_labelled(self) -> None:
        forced = bm.differential(
            [["issue_checkpoint", "observe_head"]],
            force_not_run={0: "no admitted log service in this venue"},
        )
        self.assertEqual(forced["notRunCount"], 1)
        self.assertEqual(forced["compared"], 0)
        self.assertEqual(forced["rows"][0]["outcome"], "NOT_RUN")
        self.assertIn("no admitted log service", forced["notRun"][0]["reason"])
        bm.assert_differential(forced)

    def test_a_disagreement_is_a_counterexample(self) -> None:
        model = bm.run_model(["issue_checkpoint", "observe_head"])
        implementation = {
            "accepted": [not value for value in model["accepted"]],
            "codes": [],
            "state": model["state"],
        }
        tampered = {
            "disagreementCount": 1,
            "disagreements": [
                {"id": "S000", "sequence": ["issue_checkpoint", "observe_head"],
                 "model": model, "implementation": implementation}
            ],
            "rows": [
                {"id": "S000", "sequence": ["issue_checkpoint", "observe_head"],
                 "outcome": "DISAGREED", "model": model,
                 "implementation": implementation}
            ],
        }
        with self.assertRaises(bm.Refusal) as raised:
            bm.assert_differential(tampered)
        self.assertEqual(raised.exception.code, "BM_REFUSED_DIFFERENTIAL_DISAGREEMENT")

    def test_the_model_only_driver_matches_the_state_projection(self) -> None:
        model = bm.run_model(["append_claim", "append_other", "issue_checkpoint",
                              "observe_head"])
        self.assertEqual(model["accepted"], [True, True, True, True])
        self.assertEqual(model["state"]["sizes"], [3])
        self.assertEqual(
            model["state"]["roots"], [bm.root_of(("claim-0", "claim-1", "other-2"))]
        )


class Refinement(unittest.TestCase):
    """Every invariant has a status; every gap names a source."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.enumeration = bm.enumerate_model(BOUND)
        cls.differential = bm.differential()
        cls.record = bm.build_refinement(cls.enumeration, cls.differential)

    def test_every_invariant_is_stated_and_matched(self) -> None:
        self.assertEqual(len(self.record["invariants"]), 8)
        for row in self.record["invariants"]:
            self.assertEqual(row["status"], "MODEL_AND_MATCHED", row["id"])
            self.assertEqual(row["model"], "PASS", row["id"])
            self.assertTrue(row["sequences"], row["id"])

    def test_every_gap_names_its_source(self) -> None:
        self.assertEqual(len(self.record["gaps"]), 6)
        for gap in self.record["gaps"]:
            self.assertTrue(gap["source"], gap["id"])
            self.assertTrue(gap["assumption"], gap["id"])
            self.assertTrue(gap["consequence"], gap["id"])

    def test_the_five_unmodelled_clauses_are_recorded(self) -> None:
        self.assertEqual(len(self.record["unmodelled"]), 5)
        for row in self.record["unmodelled"]:
            self.assertEqual(row["status"], "NOT_MODELLED")
            self.assertTrue(row["reason"])
            self.assertIn(row["clause"], bm.authority_clauses())

    def test_a_gap_without_a_source_is_refused(self) -> None:
        record = bm.build_refinement(self.enumeration, self.differential)
        record["gaps"][0]["source"] = ""
        with self.assertRaises(bm.Refusal) as raised:
            bm.validate_refinement(record, self.differential)
        self.assertEqual(raised.exception.code, "BM_REFUSED_REFINEMENT_UNSTATED")

    def test_a_missing_status_is_refused(self) -> None:
        record = bm.build_refinement(self.enumeration, self.differential)
        record["invariants"][0]["status"] = "PROBABLY_FINE"
        with self.assertRaises(bm.Refusal) as raised:
            bm.validate_refinement(record, self.differential)
        self.assertEqual(raised.exception.code, "BM_REFUSED_REFINEMENT_UNSTATED")

    def test_a_matched_status_without_a_run_is_refused(self) -> None:
        forced = bm.differential(
            [["issue_checkpoint", "observe_head"]],
            force_not_run={0: "no admitted log service in this venue"},
        )
        record = bm.build_refinement(self.enumeration, self.differential)
        with self.assertRaises(bm.Refusal) as raised:
            bm.validate_refinement(record, forced)
        self.assertEqual(raised.exception.code, "BM_REFUSED_NOT_RUN_AS_VERIFIED")


class Controls(unittest.TestCase):
    """One control per stable refusal code, and the record covers them all."""

    def test_every_code_has_a_control(self) -> None:
        rows = bm.controls()
        covered = {row["expectedCode"] for row in rows}
        self.assertEqual(covered, set(bm.REFUSAL_CODES) | {bm.CODE_OK})
        for row in rows:
            self.assertTrue(row["controlOnly"], row["id"])
            self.assertEqual(row["observedCode"], row["expectedCode"], row["id"])
        bm.assert_controls(rows)

    def test_refused_invariant_violated(self) -> None:
        broken = bm.enumerate_model(BOUND, fault="rollback-accepted")
        with self.assertRaises(bm.Refusal) as raised:
            bm.validate_enumeration(broken, bm.model_record(), bm.run_canaries(BOUND))
        self.assertEqual(raised.exception.code, "BM_REFUSED_INVARIANT_VIOLATED")

    def test_refused_model_incomplete(self) -> None:
        record = bm.model_record()
        record["alphabet"] = record["alphabet"][:-1]
        with self.assertRaises(bm.Refusal) as raised:
            bm.validate_model(record)
        self.assertEqual(raised.exception.code, "BM_REFUSED_MODEL_INCOMPLETE")

    def test_refused_invariant_unsourced(self) -> None:
        record = bm.model_record()
        record["invariants"][0]["clause"] = "a checkpoint is always accepted;"
        with self.assertRaises(bm.Refusal) as raised:
            bm.validate_model(record)
        self.assertEqual(raised.exception.code, "BM_REFUSED_INVARIANT_UNSOURCED")

    def test_refused_enumeration_truncated(self) -> None:
        record = bm.enumerate_model(BOUND)
        record["sequences"] = record["sequences"] - 1
        with self.assertRaises(bm.Refusal) as raised:
            bm.validate_enumeration(record, bm.model_record(), bm.run_canaries(BOUND))
        self.assertEqual(raised.exception.code, "BM_REFUSED_ENUMERATION_TRUNCATED")

    def test_refused_canary_not_detected(self) -> None:
        canaries = bm.run_canaries(BOUND)
        canaries["canaries"][0]["detected"] = False
        canaries["allDetected"] = False
        with self.assertRaises(bm.Refusal) as raised:
            bm.validate_enumeration(bm.enumerate_model(BOUND), bm.model_record(), canaries)
        self.assertEqual(raised.exception.code, "BM_REFUSED_CANARY_NOT_DETECTED")

    def test_refused_refinement_unstated(self) -> None:
        record = bm.build_refinement(bm.enumerate_model(BOUND), bm.differential())
        record["gaps"][1]["source"] = ""
        with self.assertRaises(bm.Refusal) as raised:
            bm.validate_refinement(record, bm.differential())
        self.assertEqual(raised.exception.code, "BM_REFUSED_REFINEMENT_UNSTATED")

    def test_refused_differential_disagreement(self) -> None:
        model = bm.run_model(["observe_head"])
        record = {
            "disagreementCount": 1,
            "disagreements": [
                {"id": "S000", "sequence": ["observe_head"], "model": model,
                 "implementation": {**model, "accepted": [True]}}
            ],
            "rows": [{"id": "S000", "sequence": ["observe_head"],
                      "outcome": "DISAGREED"}],
        }
        with self.assertRaises(bm.Refusal) as raised:
            bm.assert_differential(record)
        self.assertEqual(raised.exception.code, "BM_REFUSED_DIFFERENTIAL_DISAGREEMENT")

    def test_refused_not_run_as_verified(self) -> None:
        forced = bm.differential(
            [["issue_checkpoint", "observe_head"]],
            force_not_run={0: "no admitted log service in this venue"},
        )
        record = bm.build_refinement(bm.enumerate_model(BOUND), bm.differential())
        with self.assertRaises(bm.Refusal) as raised:
            bm.validate_refinement(record, forced)
        self.assertEqual(raised.exception.code, "BM_REFUSED_NOT_RUN_AS_VERIFIED")

    def test_usage_exits_two_with_a_code(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL)], cwd=REPO, capture_output=True, text=True,
            timeout=600,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("code=BM_REFUSED_USAGE", result.stdout)


class Records(unittest.TestCase):
    """The committed records say what a fresh run says."""

    def test_model_record(self) -> None:
        record = load_json(EVIDENCE / "MODEL.json")
        self.assertEqual(record["digest"], bm.record_digest(record))
        bm.validate_model(record)

    def test_enumeration_record(self) -> None:
        record = load_json(EVIDENCE / "ENUMERATION.json")
        self.assertEqual(record["sequences"], SEQUENCES)
        self.assertEqual(record["statesReached"], STATES)
        self.assertEqual(record["maxDepthReached"], BOUND)
        self.assertEqual(record["violationCount"], 0)
        self.assertTrue(record["canary"]["allDetected"])
        bm.validate_enumeration(record, bm.model_record(), record["canary"])

    def test_differential_record(self) -> None:
        record = load_json(EVIDENCE / "DIFFERENTIAL.json")
        self.assertEqual(record["compared"], COMPARED)
        self.assertEqual(record["disagreementCount"], 0)
        self.assertEqual(record["notRunCount"], 0)
        bm.assert_differential(record)

    def test_refinement_record(self) -> None:
        record = load_json(EVIDENCE / "REFINEMENT.json")
        self.assertEqual(len(record["invariants"]), 8)
        self.assertEqual(len(record["unmodelled"]), 5)
        self.assertEqual(len(record["gaps"]), 6)
        for gap in record["gaps"]:
            self.assertTrue(gap["source"], gap["id"])
        bm.validate_refinement(record, load_json(EVIDENCE / "DIFFERENTIAL.json"))

    def test_controls_record(self) -> None:
        record = load_json(EVIDENCE / "CONTROLS.json")
        self.assertEqual(record["code"], bm.CODE_OK)
        self.assertTrue(record["coversEveryCode"])
        self.assertEqual(set(record["codesCovered"]), set(bm.REFUSAL_CODES) | {bm.CODE_OK})
        bm.assert_controls(record["controls"])

    def test_the_producer_is_byte_identical_and_reproduces_the_records(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for out in (first, second):
                result = subprocess.run(
                    [sys.executable, str(PRODUCER), "--out", out],
                    cwd=REPO, capture_output=True, text=True, timeout=900,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in (
                "MODEL.json",
                "ENUMERATION.json",
                "DIFFERENTIAL.json",
                "REFINEMENT.json",
                "CONTROLS.json",
            ):
                a = (Path(first) / name).read_bytes()
                b = (Path(second) / name).read_bytes()
                committed = (EVIDENCE / name).read_bytes()
                self.assertEqual(a, b, f"{name} differs between two runs")
                self.assertEqual(a, committed, f"{name} differs from the committed record")

    def test_the_producer_check_exits_zero(self) -> None:
        result = subprocess.run(
            [sys.executable, str(PRODUCER), "--check"],
            cwd=REPO, capture_output=True, text=True, timeout=900,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("code=BM_OK", result.stdout)


class CommandLine(unittest.TestCase):
    """Exit 0 on a result, 1 on a refusal, 2 on usage, and the code is printed."""

    def run_tool(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            cwd=REPO, capture_output=True, text=True, timeout=900,
        )

    def test_model_exits_zero(self) -> None:
        result = self.run_tool("model")
        self.assertEqual(result.returncode, 0)
        self.assertIn("code=BM_OK", result.stdout)
        self.assertIn("invariants=8", result.stdout)

    def test_enumerate_exits_zero(self) -> None:
        result = self.run_tool("enumerate")
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"sequences={SEQUENCES}", result.stdout)
        self.assertIn(f"states={STATES}", result.stdout)
        self.assertIn("violations=0", result.stdout)
        self.assertIn("allDetected=true", result.stdout)

    def test_differential_exits_zero(self) -> None:
        result = self.run_tool("differential")
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"compared={COMPARED}", result.stdout)
        self.assertIn("disagreements=0", result.stdout)

    def test_controls_exits_zero(self) -> None:
        result = self.run_tool("controls")
        self.assertEqual(result.returncode, 0)
        self.assertIn("code=BM_OK", result.stdout)
        self.assertIn("controls=10", result.stdout)

    def test_refinement_exits_zero(self) -> None:
        result = self.run_tool("refinement")
        self.assertEqual(result.returncode, 0)
        self.assertIn("status=MODEL_AND_MATCHED", result.stdout)

    def test_a_refusal_exits_one_with_its_code(self) -> None:
        original = bm.MODEL_PATH
        bm.MODEL_PATH = REPO / "evidence/b7/MODEL-ABSENT.json"
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                code = bm.main(["model"])
        finally:
            bm.MODEL_PATH = original
        self.assertEqual(code, 1)
        self.assertIn("code=BM_REFUSED_MODEL_INCOMPLETE", buffer.getvalue())


class Document(unittest.TestCase):
    """The document names every code, invariant, bound and gap."""

    def setUp(self) -> None:
        self.assertTrue(DOCUMENT.is_file(), f"{DOCUMENT} is absent")
        self.text = DOCUMENT.read_text(encoding="utf-8")

    def test_every_refusal_code_is_named(self) -> None:
        for code in bm.REFUSAL_CODES:
            self.assertIn(code, self.text, f"the document does not name {code}")

    def test_every_invariant_is_named_with_its_clause(self) -> None:
        for invariant in bm.INVARIANTS:
            self.assertIn(invariant["id"], self.text)
            self.assertIn(invariant["clause"], self.text.replace("\n", " "),
                          invariant["id"])

    def test_every_bound_and_count_is_stated(self) -> None:
        for fragment in (
            "579,195",
            "1,871",
            "7,770",
            "219",
            "fourteen",
            f"bound {BOUND}",
        ):
            self.assertIn(fragment, self.text, f"the document does not state {fragment}")

    def test_every_gap_is_named(self) -> None:
        for gap in bm.REFINEMENT_GAPS:
            self.assertIn(gap["id"], self.text)
            self.assertIn(gap["gap"], self.text)

    def test_the_limits_are_stated(self) -> None:
        for fragment in ("Article 5", "Article 7", "NOT_RUN", "NOT_MODELLED"):
            self.assertIn(fragment, self.text)

    def test_the_tests_are_named(self) -> None:
        self.assertIn("forensics/tools/tests/test_transparency_model.py", self.text)

    def test_every_enforced_by_names_a_test_in_this_module(self) -> None:
        for code in bm.REFUSAL_CODES:
            rows = [
                line
                for line in self.text.splitlines()
                if f"`{code}`" in line
            ]
            self.assertTrue(rows, f"the document has no row for {code}")
            names = [
                token
                for line in rows
                for token in line.replace("|", " ").split()
                if token.startswith("`test_")
            ]
            self.assertTrue(names, f"the row for {code} names no test")
            function = names[0].strip("`")
            self.assertTrue(
                any(
                    hasattr(candidate, function)
                    for candidate in (
                        Structure, Enumeration, Canary, Differential, Refinement,
                        Controls, Records, CommandLine, Document,
                    )
                ),
                f"the document names {function}, which this module does not define",
            )


if __name__ == "__main__":
    unittest.main()
