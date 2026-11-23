#!/usr/bin/env python3
"""Controls for the binary-assurance checker itself.

Each refusal rule in `docs/BINARY-ASSURANCE.md` has a control that mutates a
copy of the committed matrix (or TCB) and requires the named refusal.  The
positive control runs the committed documents, the determinism control runs the
same check twice and the live TCB probe twice, and the structural control
asserts that the checker has no status vocabulary for a source-to-binary
correspondence.

Run inside the court:

    python3 forensics/tools/tests/test_binary_assurance.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
TOOL = TOOLS / "binary_assurance.py"
TCB_PATH = REPO_ROOT / "evidence" / "etp-t6" / "TCB.json"
MATRIX_PATH = REPO_ROOT / "evidence" / "etp-t6" / "CLAIM-MATRIX.json"

sys.path.insert(0, str(TOOLS))
import binary_assurance as ba  # noqa: E402


def load():
    return ba.load_json_strict(TCB_PATH), ba.load_json_strict(MATRIX_PATH)


def claim(matrix: dict, ident: str) -> dict:
    for entry in matrix["claims"]:
        if entry["id"] == ident:
            return entry
    raise KeyError(ident)


def build(matrix: dict, ident: str) -> dict:
    for entry in matrix["builds"]:
        if entry["id"] == ident:
            return entry
    raise KeyError(ident)


def codes(refusals) -> set[str]:
    return {item.code for item in refusals}


class NamedRefusalMixin(unittest.TestCase):
    def assert_named(self, refusals, code: str, ident: str) -> ba.Refusal:
        matches = [item for item in refusals if item.code == code]
        self.assertTrue(matches, f"{code} not among {sorted(codes(refusals))}")
        chosen = matches[0]
        self.assertEqual(chosen.claim, ident, chosen)
        self.assertTrue(chosen.field and chosen.field != "-", chosen)
        self.assertTrue(chosen.target and chosen.target != "-", chosen)
        return chosen


class PositiveControl(unittest.TestCase):
    def test_committed_documents_pass(self) -> None:
        tcb, matrix = load()
        self.assertEqual(ba.check_documents(tcb, matrix, REPO_ROOT), [])

    def test_live_tcb_matches_the_committed_record(self) -> None:
        tcb, _ = load()
        live = ba.build_tcb(REPO_ROOT, tcb["recorded_at_utc"])
        self.assertEqual(live["tcb_digest"], tcb["tcb_digest"])

    def test_checker_has_no_correspondence_status(self) -> None:
        for term in ba.FORBIDDEN_TERMS:
            self.assertNotIn(term, ba.ALLOWED_STATUSES)
        self.assertNotIn("BINARY_REFINEMENT_VERIFIED", ba.ALLOWED_STATUSES)
        self.assertNotIn("BINARY_REFINEMENT_VERIFIED", ba.UNBOUND_STATUSES)


class RuleOneNoInheritance(NamedRefusalMixin):
    def test_claim_asserted_for_another_target_is_refused(self) -> None:
        tcb, matrix = load()
        claim(matrix, "BA-CLM-001")["target"] = "aarch64-unknown-linux-gnu"
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_CROSS_TARGET_INHERITANCE", "BA-CLM-001")

    def test_claim_for_a_target_with_no_artefact_is_refused(self) -> None:
        tcb, matrix = load()
        entry = claim(matrix, "BA-CLM-012")
        entry["asserted"] = True
        entry["status"] = "SCOPED_OBSERVATION"
        entry["instrument"] = "consumer-closure"
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_CLAIM_TARGET_UNBOUND", "BA-CLM-012")

    def test_cross_profile_claim_is_refused(self) -> None:
        tcb, matrix = load()
        claim(matrix, "BA-CLM-001")["profile"] = "debug"
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_CROSS_PROFILE_INHERITANCE", "BA-CLM-001")


class RuleTwoArtefactDigest(NamedRefusalMixin):
    def test_wrong_digest_is_refused(self) -> None:
        tcb, matrix = load()
        claim(matrix, "BA-CLM-002")["artefact"]["sha256"] = "0" * 64
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_ARTEFACT_DIGEST_MISMATCH", "BA-CLM-002")

    def test_wrong_build_id_is_refused(self) -> None:
        tcb, matrix = load()
        claim(matrix, "BA-CLM-003")["artefact"]["build_id"] = "deadbeef"
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_ARTEFACT_DIGEST_MISMATCH", "BA-CLM-003")


class RuleThreeTcb(NamedRefusalMixin):
    def test_wrong_build_tcb_is_refused(self) -> None:
        tcb, matrix = load()
        build(matrix, "B-X86-64-RELEASE-ETP2")["tcb_digest"] = "0" * 64
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_TCB_MISMATCH", "BA-CLM-001")

    def test_wrong_claim_tcb_is_refused(self) -> None:
        tcb, matrix = load()
        claim(matrix, "BA-CLM-001")["tcb_digest"] = "0" * 64
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_TCB_MISMATCH", "BA-CLM-001")

    def test_self_digest_mismatch_is_refused(self) -> None:
        tcb, matrix = load()
        tcb["tcb_digest"] = "0" * 64
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assertIn("BA_TCB_SELF_DIGEST", codes(refusals))

    def test_profile_outside_the_recorded_tcb_is_refused(self) -> None:
        tcb, matrix = load()
        build(matrix, "B-X86-64-RELEASE-ETP2")["profile"]["opt_level"] = 0
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_TCB_MISMATCH", "BA-CLM-001")


class RuleFourSourceIdentity(NamedRefusalMixin):
    def test_changed_build_source_without_explanation_is_refused(self) -> None:
        tcb, matrix = load()
        entry = build(matrix, "B-X86-64-RELEASE-ETP2")
        entry["source_identity"]["commit"] = "1" * 40
        entry["source_explanation"] = ""
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_SOURCE_IDENTITY_MISMATCH", "BA-CLM-001")

    def test_changed_build_source_with_explanation_passes(self) -> None:
        tcb, matrix = load()
        entry = build(matrix, "B-X86-64-RELEASE-ETP2")
        entry["source_identity"]["commit"] = "1" * 40
        entry["source_explanation"] = "The artefact was rebuilt from a later tree; the difference is stated."
        for item in matrix["claims"]:
            if item.get("build") == "B-X86-64-RELEASE-ETP2":
                item["source_identity"]["commit"] = "1" * 40
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assertNotIn("BA_SOURCE_IDENTITY_MISMATCH", codes(refusals))
        self.assertNotIn("BA_SOURCE_IDENTITY_UNKNOWN", codes(refusals))

    def test_unknown_source_without_explanation_is_refused(self) -> None:
        tcb, matrix = load()
        entry = build(matrix, "B-X86-64-RELEASE-ETP2")
        entry["source_identity"]["commit"] = "UNKNOWN"
        entry["source_explanation"] = ""
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_SOURCE_IDENTITY_UNKNOWN", "BA-CLM-001")


class RuleFiveForbiddenVocabulary(NamedRefusalMixin):
    def test_forbidden_status_is_refused(self) -> None:
        tcb, matrix = load()
        claim(matrix, "BA-CLM-001")["status"] = "BINARY_REFINEMENT_VERIFIED"
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_FORBIDDEN_CLAIM", "BA-CLM-001")

    def test_forbidden_text_outside_status_is_refused(self) -> None:
        tcb, matrix = load()
        claim(matrix, "BA-CLM-002")["does_not_establish"].append(
            "the artefact is BINARY_REFINEMENT_VERIFIED"
        )
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_FORBIDDEN_CLAIM", "BA-CLM-002")


class UnboundDiscipline(NamedRefusalMixin):
    def test_asserted_unbound_claim_is_refused(self) -> None:
        tcb, matrix = load()
        entry = claim(matrix, "BA-CLM-010")
        entry["asserted"] = True
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_UNBOUND_ASSERTED", "BA-CLM-010")

    def test_unasserted_claim_needs_a_reason(self) -> None:
        tcb, matrix = load()
        claim(matrix, "BA-CLM-011")["unbindable_reason"] = ""
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_CLAIM_INCOMPLETE", "BA-CLM-011")

    def test_evidence_digest_mismatch_is_refused(self) -> None:
        tcb, matrix = load()
        claim(matrix, "BA-CLM-004")["evidence"]["sha256"] = "0" * 64
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assert_named(refusals, "BA_EVIDENCE_DIGEST_MISMATCH", "BA-CLM-004")


class Determinism(unittest.TestCase):
    def test_check_output_is_byte_identical_twice(self) -> None:
        command = [
            sys.executable,
            str(TOOL),
            "check",
            "--tcb",
            str(TCB_PATH),
            "--matrix",
            str(MATRIX_PATH),
        ]
        first = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, timeout=300)
        second = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, timeout=300)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout)

    def test_record_is_byte_identical_twice(self) -> None:
        with tempfile.TemporaryDirectory(prefix="etp-t6-record-") as tmp:
            outputs = []
            for name in ("a.json", "b.json"):
                path = Path(tmp) / name
                result = subprocess.run(
                    [
                        sys.executable,
                        str(TOOL),
                        "record",
                        "--recorded-at",
                        "2026-11-22T00:00:00Z",
                        "--out",
                        str(path),
                    ],
                    cwd=REPO_ROOT,
                    capture_output=True,
                    text=True,
                    timeout=900,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs.append(path.read_bytes())
            self.assertEqual(outputs[0], outputs[1])


class StrictJson(unittest.TestCase):
    def test_malformed_container_is_refused(self) -> None:
        tcb, matrix = load()
        matrix["claims"] = ["not an object"]
        refusals = ba.check_documents(tcb, matrix, REPO_ROOT)
        self.assertIn("BA_DOC_SHAPE", codes(refusals))

    def test_duplicate_key_is_refused(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write('{"a": 1, "a": 2}\n')
            path = Path(handle.name)
        self.addCleanup(path.unlink)
        with self.assertRaises(ba.DocumentError) as caught:
            ba.load_json_strict(path)
        self.assertEqual(caught.exception.code, "BA_JSON_DUPLICATE_KEY")

    def test_non_finite_number_is_refused(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write('{"a": NaN}\n')
            path = Path(handle.name)
        self.addCleanup(path.unlink)
        with self.assertRaises(ba.DocumentError) as caught:
            ba.load_json_strict(path)
        self.assertEqual(caught.exception.code, "BA_JSON_NON_FINITE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
