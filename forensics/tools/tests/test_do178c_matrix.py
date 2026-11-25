#!/usr/bin/env python3
"""Controls for forensics/tools/do178c_matrix.py and the FRC-8 matrix.

What is proved here, and what is not
------------------------------------
* The committed matrix validates against the committed document and the
  project's independence record, and the summary reproduces the declared shape:
  14 objectives, 0 satisfied, 5 partial, 7 not satisfied, 2 unverified, 12
  missing items, 50 party assignments of which 50 are same-party and 0 external.
* Every refusal code has a negative control that corrupts one field and observes
  that exact code, so no code is exercised only by a document.
* Three positive controls establish that the rules are not vacuous: a satisfied
  objective with a settled independence requirement is accepted, an independent
  review with a declared distinct trust domain is accepted, and an UNVERIFIED
  objective with a settling method and no evidence is accepted. None of the
  three describes this project's state.
* The producer is byte-identical across two runs and against the committed
  bytes; the document names every objective, context, exclusion, missing item
  and code; the document names no implementation source path.

These are controls on the matrix, not evidence that any objective is satisfied,
that any tool is qualified, or that anything is certified. Run directly or with
``python3 -m unittest forensics.tools.tests.test_do178c_matrix``.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import do178c_matrix as dm  # noqa: E402

MATRIX_PATH = REPO / dm.MATRIX
DOCUMENT = REPO / dm.DOCUMENT
PRODUCER = REPO / "evidence/frc8/build_evidence.py"
INDEPENDENCE_PATH = REPO / dm.INDEPENDENCE


def load(path: Path) -> object:
    return dm.load_json_strict(path)


def committed() -> tuple[dict, str]:
    return load(MATRIX_PATH), DOCUMENT.read_text(encoding="utf-8")


def independence() -> dict:
    return dm.load_independence(REPO)


def codes_of(problems: list[tuple[str, str]]) -> set[str]:
    return {code for code, _detail in problems}


def matrix_copy() -> dict:
    return copy.deepcopy(load(MATRIX_PATH))


def validate(matrix: dict, record: dict | None = None) -> list[tuple[str, str]]:
    return dm.validate_matrix(matrix, REPO, record if record is not None else independence())


# ---------------------------------------------------------------------------
# Corruptions.  Each returns the refusal codes observed, so the individual
# tests and the coverage test share one definition.
# ---------------------------------------------------------------------------


def corrupt_schema() -> set[str]:
    matrix = matrix_copy()
    matrix["schema"] = "not-the-schema"
    return codes_of(validate(matrix))


def corrupt_duplicate_key() -> set[str]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "dup.json"
        path.write_text('{"a": 1, "a": 2}', encoding="utf-8")
        try:
            dm.load_json_strict(path)
        except dm.Refusal as refusal:
            return {refusal.code}
    return set()


def corrupt_context_absent() -> set[str]:
    matrix = matrix_copy()
    matrix["system_context"]["excludes"] = []
    return codes_of(validate(matrix))


def corrupt_status_without_evidence() -> set[str]:
    matrix = matrix_copy()
    row = next(row for row in matrix["objectives"]
               if row["status"] == "NOT_SATISFIED")
    row["evidence"] = []
    return codes_of(validate(matrix))


def corrupt_evidence_absent() -> set[str]:
    matrix = matrix_copy()
    row = matrix["objectives"][0]
    row["status"] = "SATISFIED_WITH_EVIDENCE"
    row["blocked_by"] = []
    row["required_independence"] = {
        "state": "NONE_REQUIRED",
        "basis": "a control objective with no independence requirement",
        "settling_method": None,
    }
    row["evidence"][0]["path"] = "docs/absent-evidence.md"
    return codes_of(validate(matrix))


def corrupt_unverified_without_method() -> set[str]:
    matrix = matrix_copy()
    row = next(row for row in matrix["objectives"]
               if row["status"] == "UNVERIFIED")
    row["settling_method"] = ""
    return codes_of(validate(matrix))


def corrupt_independence_unsupported() -> set[str]:
    matrix = matrix_copy()
    row = matrix["objectives"][0]
    row["status"] = "SATISFIED_WITH_EVIDENCE"
    row["blocked_by"] = []
    row["independence_held"] = {
        "state": "INDEPENDENT",
        "witness": dm.INDEPENDENCE,
        "trust_domain": None,
        "external_parties": 0,
        "distinct_from_author": False,
    }
    return codes_of(validate(matrix))


def corrupt_certification_claim() -> set[str]:
    matrix = matrix_copy()
    matrix["certification_claimed"] = True
    return codes_of(validate(matrix))


def corrupt_missing_item_omitted() -> set[str]:
    matrix = matrix_copy()
    matrix["missing_items"] = [
        item for item in matrix["missing_items"] if item["id"] != "MI-TARGET-TIMING"]
    return codes_of(validate(matrix))


def corrupt_missing_item_without_method() -> set[str]:
    matrix = matrix_copy()
    matrix["missing_items"][0]["why_required"] = ""
    return codes_of(validate(matrix))


def corrupt_non_claim_absent() -> set[str]:
    matrix = matrix_copy()
    matrix["non_claim"]["statement"] = "objective satisfaction is recorded here"
    return codes_of(validate(matrix))


def corrupt_document_drift() -> set[str]:
    matrix, text = committed()
    text = text.replace("DO8-ARCH", "DO8-DRIFTED")
    return codes_of(dm.validate_document(text, matrix))


def corrupt_usage() -> set[str]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        status = dm.main([])
    return {dm.CODE_USAGE} if status == dm.EXIT_USAGE else set()


CONTROLS = {
    "DO_REFUSED_SCHEMA": corrupt_schema,
    "DO_REFUSED_DUPLICATE_KEY": corrupt_duplicate_key,
    "DO_REFUSED_CONTEXT_ABSENT": corrupt_context_absent,
    "DO_REFUSED_STATUS_WITHOUT_EVIDENCE": corrupt_status_without_evidence,
    "DO_REFUSED_EVIDENCE_ABSENT": corrupt_evidence_absent,
    "DO_REFUSED_UNVERIFIED_WITHOUT_METHOD": corrupt_unverified_without_method,
    "DO_REFUSED_INDEPENDENCE_UNSUPPORTED": corrupt_independence_unsupported,
    "DO_REFUSED_CERTIFICATION_CLAIM": corrupt_certification_claim,
    "DO_REFUSED_MISSING_ITEM_OMITTED": corrupt_missing_item_omitted,
    "DO_REFUSED_MISSING_ITEM_WITHOUT_METHOD": corrupt_missing_item_without_method,
    "DO_REFUSED_NON_CLAIM_ABSENT": corrupt_non_claim_absent,
    "DO_REFUSED_DOCUMENT_DRIFT": corrupt_document_drift,
    "DO_REFUSED_USAGE": corrupt_usage,
}


class CommittedMatrix(unittest.TestCase):
    def test_committed_matrix_validates(self) -> None:
        matrix, text = committed()
        self.assertEqual(dm.check(matrix, text, repo=REPO,
                                  independence=independence()), [])

    def test_summary_reproduces_the_declared_shape(self) -> None:
        matrix, _text = committed()
        counts = dm.summary(matrix, independence())
        self.assertEqual(counts["objectives"], 14)
        self.assertEqual(counts["satisfied"], 0)
        self.assertEqual(counts["partial"], 5)
        self.assertEqual(counts["not_satisfied"], 7)
        self.assertEqual(counts["unverified"], 2)
        self.assertEqual(counts["missing_items"], 12)
        self.assertEqual(counts["normative_ids_unverified"], 14)
        self.assertEqual(counts["independence_assignments"], 50)
        self.assertEqual(counts["same_party_adjudicator"], 50)
        self.assertEqual(counts["external_parties"], 0)
        self.assertEqual(counts["refusal_codes"], len(dm.REFUSALS))

    def test_no_objective_is_satisfied(self) -> None:
        matrix, _text = committed()
        self.assertTrue(all(row["status"] != "SATISFIED_WITH_EVIDENCE"
                            for row in matrix["objectives"]))

    def test_every_objective_identifier_is_unverified(self) -> None:
        matrix, _text = committed()
        for row in matrix["objectives"]:
            self.assertEqual(row["normative_objective_ids"], "UNVERIFIED")
            self.assertTrue(row["normative_settling_method"])

    def test_independence_numbers_match_the_record(self) -> None:
        matrix, _text = committed()
        record = independence()
        block = matrix["independence_record"]
        for field in ("assignments", "same_party_adjudicator", "declared_parties",
                      "external_parties"):
            self.assertEqual(block[field], record[field], field)

    def test_every_missing_item_is_referenced(self) -> None:
        matrix, _text = committed()
        referenced = {item for row in matrix["objectives"] for item in row["blocked_by"]}
        for item in matrix["missing_items"]:
            self.assertIn(item["id"], referenced, item["id"])

    def test_context_excludes_all_required_categories(self) -> None:
        matrix, _text = committed()
        ids = {item["id"] for item in matrix["system_context"]["excludes"]}
        self.assertEqual(ids, set(dm.MUST_EXCLUDE))

    def test_non_claim_is_stated(self) -> None:
        matrix, _text = committed()
        self.assertIn("is not certification", matrix["non_claim"]["statement"])
        self.assertFalse(matrix["certification_claimed"])
        self.assertFalse(matrix["dal_claimed"])
        self.assertIsNone(matrix["assurance_level"])

    def test_party_counts_cannot_outrun_the_record(self) -> None:
        matrix = matrix_copy()
        matrix["independence_record"]["external_parties"] = 1
        self.assertIn("DO_REFUSED_INDEPENDENCE_UNSUPPORTED",
                      codes_of(validate(matrix)))


class Document(unittest.TestCase):
    def test_document_names_every_machine_token(self) -> None:
        matrix, text = committed()
        self.assertEqual(dm.validate_document(text, matrix), [])

    def test_document_has_no_implementation_path(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        self.assertNotIn("src/", text)
        self.assertNotIn("crate::", text)

    def test_document_states_the_non_claim(self) -> None:
        self.assertIn("is not certification", DOCUMENT.read_text(encoding="utf-8"))

    def test_every_code_in_the_document_is_a_known_code(self) -> None:
        import re
        text = DOCUMENT.read_text(encoding="utf-8")
        seen = set(re.findall(r"DO_REFUSED_[A-Z0-9_]+", text))
        self.assertTrue(seen)
        self.assertLessEqual(seen, set(dm.REFUSALS))

    def test_every_known_code_is_in_the_document(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        for code in dm.REFUSALS:
            self.assertIn(code, text)


class NegativeControls(unittest.TestCase):
    """One control per refusal code; each corrupts a real record by one field."""

    def _fires(self, code: str) -> None:
        self.assertIn(code, CONTROLS[code](), f"{code} did not fire")

    def test_schema(self) -> None:
        self._fires("DO_REFUSED_SCHEMA")

    def test_duplicate_key(self) -> None:
        self._fires("DO_REFUSED_DUPLICATE_KEY")

    def test_context_absent(self) -> None:
        self._fires("DO_REFUSED_CONTEXT_ABSENT")

    def test_status_without_evidence(self) -> None:
        self._fires("DO_REFUSED_STATUS_WITHOUT_EVIDENCE")

    def test_evidence_absent(self) -> None:
        self._fires("DO_REFUSED_EVIDENCE_ABSENT")

    def test_unverified_without_method(self) -> None:
        self._fires("DO_REFUSED_UNVERIFIED_WITHOUT_METHOD")

    def test_independence_unsupported(self) -> None:
        self._fires("DO_REFUSED_INDEPENDENCE_UNSUPPORTED")

    def test_certification_claim(self) -> None:
        self._fires("DO_REFUSED_CERTIFICATION_CLAIM")

    def test_missing_item_omitted(self) -> None:
        self._fires("DO_REFUSED_MISSING_ITEM_OMITTED")

    def test_missing_item_without_method(self) -> None:
        self._fires("DO_REFUSED_MISSING_ITEM_WITHOUT_METHOD")

    def test_non_claim_absent(self) -> None:
        self._fires("DO_REFUSED_NON_CLAIM_ABSENT")

    def test_document_drift(self) -> None:
        self._fires("DO_REFUSED_DOCUMENT_DRIFT")

    def test_usage(self) -> None:
        self._fires("DO_REFUSED_USAGE")

    def test_every_declared_code_has_a_firing_control(self) -> None:
        self.assertEqual(set(CONTROLS), set(dm.REFUSALS))
        for code, control in CONTROLS.items():
            self.assertIn(code, control(), f"{code} has no firing control")


class NonVacuity(unittest.TestCase):
    """The acceptance rules can accept; these controls do not describe this project."""

    def test_a_satisfied_objective_with_settled_independence_is_accepted(self) -> None:
        matrix = matrix_copy()
        row = next(row for row in matrix["objectives"]
                   if row["id"] == "DO8-CM")
        row["status"] = "SATISFIED_WITH_EVIDENCE"
        row["blocked_by"] = []
        row["required_independence"] = {
            "state": "NONE_REQUIRED",
            "basis": "a control objective with no independence requirement",
            "settling_method": None,
        }
        self.assertEqual(validate(matrix), [])

    def test_independent_review_with_a_distinct_trust_domain_is_accepted(self) -> None:
        matrix = matrix_copy()
        row = next(row for row in matrix["objectives"]
                   if row["id"] == "DO8-QA")
        row["status"] = "SATISFIED_WITH_EVIDENCE"
        row["blocked_by"] = []
        row["independence_held"] = {
            "state": "INDEPENDENT",
            "witness": dm.INDEPENDENCE,
            "trust_domain": "a control laboratory outside the project",
            "external_parties": 1,
            "distinct_from_author": True,
        }
        matrix["independence_record"].update(
            {"assignments": 51, "same_party_adjudicator": 50,
             "declared_parties": 1, "external_parties": 1})
        record = {"assignments": 51, "same_party_adjudicator": 50,
                  "declared_parties": 1, "external_parties": 1}
        self.assertEqual(validate(matrix, record), [])

    def test_an_unverified_objective_without_evidence_is_accepted(self) -> None:
        matrix = matrix_copy()
        row = next(row for row in matrix["objectives"]
                   if row["id"] == "DO8-LLR")
        row["status"] = "UNVERIFIED"
        row["evidence"] = []
        row["settling_method"] = "a control reading that would settle it"
        self.assertEqual(validate(matrix), [])


class Producer(unittest.TestCase):
    def test_producer_is_byte_identical_across_two_runs(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for directory in (first, second):
                result = subprocess.run([sys.executable, str(PRODUCER), "--out", directory],
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            a = (Path(first) / "DO178C-MATRIX.json").read_bytes()
            b = (Path(second) / "DO178C-MATRIX.json").read_bytes()
            self.assertEqual(a, b)
            self.assertEqual(a, MATRIX_PATH.read_bytes())

    def test_producer_check_exits_zero(self) -> None:
        result = subprocess.run([sys.executable, str(PRODUCER), "--check"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("objectives=14", result.stdout)


class CommandLine(unittest.TestCase):
    def test_check_exits_zero_and_prints_do_ok(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOLS / "do178c_matrix.py"), "check"],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("codes=DO_OK", result.stdout)

    def test_inventory_is_deterministic(self) -> None:
        first = subprocess.run(
            [sys.executable, str(TOOLS / "do178c_matrix.py"), "inventory", "--json"],
            capture_output=True, text=True, check=False)
        second = subprocess.run(
            [sys.executable, str(TOOLS / "do178c_matrix.py"), "inventory", "--json"],
            capture_output=True, text=True, check=False)
        self.assertEqual(first.returncode, 0)
        self.assertEqual(first.stdout, second.stdout)

    def test_check_output_is_deterministic(self) -> None:
        first = subprocess.run(
            [sys.executable, str(TOOLS / "do178c_matrix.py"), "check", "--json"],
            capture_output=True, text=True, check=False)
        second = subprocess.run(
            [sys.executable, str(TOOLS / "do178c_matrix.py"), "check", "--json"],
            capture_output=True, text=True, check=False)
        self.assertEqual(first.stdout, second.stdout)


if __name__ == "__main__":
    unittest.main()
