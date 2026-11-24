#!/usr/bin/env python3
"""Controls for forensics/tools/verification_summary.py and the A21 records.

One control per refusal code; counts recomputed from a deliberately inconsistent
decision; every source-digest failure (a changed primary source, a changed
corroborating source, a changed decision record, a changed policy); an absent
source; the coverage gap in both directions (an obligation removed from the
summary and an obligation the policy does not declare); a decision upgraded from
``DENY`` to ``ADMIT``; a flipped obligation state; a summary with no source
digests; a summary with no source manifest; a consumer that cites the summary as
its evidence; an unsigned envelope; a summary mutated after signing; the real
summary and its reconstruction; determinism; the command line's exit codes and
printed codes; and document synchronisation.

A control mutates a synthetic or mirrored record in a temporary directory. It is
not a source change and not a defect report: a control that fires proves the
refusal works, not that the substituted form occurs anywhere in the tree.

Run directly (`python3 forensics/tools/tests/test_verification_summary.py`) or
with `python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics/tools"
EVIDENCE = REPO / "evidence/a21"
BUILDER = EVIDENCE / "build_evidence.py"
DOCUMENT = REPO / "docs/VERIFICATION-SUMMARIES.md"
sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402
import policy_engine as pe  # noqa: E402
import verification_summary as vs  # noqa: E402

DECISION_PATH = REPO / "evidence/a20/DECISION.json"
POLICY_PATH = REPO / "evidence/a20/POLICY.json"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value))


def mirror_real_records() -> Path:
    """A temporary repository holding the exact bytes the real summary cites."""
    root = Path(tempfile.mkdtemp(prefix="a21-mirror-"))
    summary = load_json(EVIDENCE / "SUMMARY.json")
    decision = load_json(DECISION_PATH)
    policy = load_json(POLICY_PATH)
    for relative in [vs.DECISION_PATH, vs.POLICY_PATH]:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / relative, target)
    for entry in summary["reconstructedFrom"]:
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / entry["path"], target)
    for obligation in policy["obligations"]:
        tool = obligation["source"]["tool"]
        target = root / tool
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / tool, target)
    for entry in decision["obligations"]:
        for corroborating in entry.get("corroboration") or []:
            path = corroborating["source"]["record"]
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / path, target)
    return root


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = vs.controls_document()
        cls.fixtures = cls.document["controls"]
        cls.by_code = {fixture["code"]: fixture for fixture in cls.fixtures if fixture["code"]}

    def test_one_control_per_refusal_code(self) -> None:
        self.assertEqual(sorted(self.by_code), sorted(vs.REFUSAL_CODES))
        self.assertEqual(len(self.by_code), len(vs.REFUSAL_CODES))

    def test_every_control_is_control_only_and_establishes_its_code(self) -> None:
        for fixture in self.fixtures:
            with self.subTest(control=fixture["id"]):
                self.assertEqual(fixture["kind"], "control-only")
                self.assertTrue(fixture["established"], fixture)
                self.assertIn(fixture["code"], fixture["observed"]["codes"])

    def test_the_required_wrong_conclusions_are_covered(self) -> None:
        required = {
            "consumer-cites-summary",
            "obligation-removed",
            "counts-disagree-with-list",
            "source-bytes-changed",
            "decision-upgraded",
            "obligation-added",
            "obligation-without-digest",
            "signed-summary-mutated",
        }
        self.assertEqual(sorted(required - {fixture["id"] for fixture in self.fixtures}), [])


class Recounting(unittest.TestCase):
    def test_counts_are_recounted_from_a_deliberately_inconsistent_decision(self) -> None:
        root, decision, _summary = vs._control_fixture()
        inconsistent = copy_json(decision)
        inconsistent["met"] = ["C01.met", "C02.unmet", "C03.invented"]
        inconsistent["unmet"] = []
        inconsistent["unknown"] = ["C04.invented"]
        inconsistent["notApplicable"] = ["C05.invented"]
        summary = vs.summarise(inconsistent, pe.filesystem_reader(root))
        self.assertEqual(
            summary["counts"],
            {"met": 1, "unmet": 1, "unknown": 0, "notApplicable": 0},
        )
        self.assertEqual(summary["unmet"], ["C02.unmet"])

    def test_the_recount_must_agree_with_the_decision_totals(self) -> None:
        root, decision, _summary = vs._control_fixture()
        inconsistent = copy_json(decision)
        inconsistent["met"] = ["C01.met", "C02.unmet"]
        inconsistent["unmet"] = []
        # The record is rewritten so the summary is a summary of *this* decision;
        # otherwise the digest check, not the totals check, is what fires.
        (root / vs.DECISION_PATH).write_bytes(pe.decision_bytes(inconsistent))
        summary = vs.summarise(inconsistent, pe.filesystem_reader(root))
        with self.assertRaises(vs.Refusal) as caught:
            vs.reconstruct(summary, root)
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_COUNTS_MISMATCH)

    def test_a_decision_with_a_stale_source_digest_is_not_summarised(self) -> None:
        root, decision, _summary = vs._control_fixture()
        stale = copy_json(decision)
        stale["obligations"][0]["recordSha256"] = "0" * 64
        with self.assertRaises(vs.Refusal) as caught:
            vs.summarise(stale, pe.filesystem_reader(root))
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_SOURCE_DIGEST_MISMATCH)


class SourceIdentity(unittest.TestCase):
    def test_a_changed_primary_source_is_refused(self) -> None:
        root = mirror_real_records()
        summary = load_json(EVIDENCE / "SUMMARY.json")
        path = summary["obligations"][1]["sourcePath"]
        (root / path).write_bytes((root / path).read_bytes() + b" ")
        with self.assertRaises(vs.Refusal) as caught:
            vs.reconstruct(summary, root)
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_SOURCE_DIGEST_MISMATCH)

    def test_a_changed_corroborating_source_is_refused(self) -> None:
        root = mirror_real_records()
        summary = load_json(EVIDENCE / "SUMMARY.json")
        path = "evidence/a17/FREEZE-forward.json"
        (root / path).write_bytes((root / path).read_bytes() + b" ")
        with self.assertRaises(vs.Refusal) as caught:
            vs.reconstruct(summary, root)
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_SOURCE_DIGEST_MISMATCH)

    def test_an_absent_source_is_refused(self) -> None:
        root = mirror_real_records()
        summary = load_json(EVIDENCE / "SUMMARY.json")
        (root / summary["obligations"][0]["sourcePath"]).unlink()
        with self.assertRaises(vs.Refusal) as caught:
            vs.reconstruct(summary, root)
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_EVIDENCE_ABSENT)

    def test_a_changed_decision_record_is_refused(self) -> None:
        root = mirror_real_records()
        summary = load_json(EVIDENCE / "SUMMARY.json")
        (root / vs.DECISION_PATH).write_bytes(
            (root / vs.DECISION_PATH).read_bytes() + b" "
        )
        with self.assertRaises(vs.Refusal) as caught:
            vs.reconstruct(summary, root)
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_SOURCE_DIGEST_MISMATCH)

    def test_a_changed_policy_record_is_refused(self) -> None:
        root = mirror_real_records()
        summary = load_json(EVIDENCE / "SUMMARY.json")
        policy = load_json(root / vs.POLICY_PATH)
        policy["obligations"][0]["predicate"]["value"] = "NOT_THE_RECORDED_VALUE"
        del policy["digest"]
        policy["digest"] = pe.policy_digest(policy)
        (root / vs.POLICY_PATH).write_bytes(
            pe.canonical(policy).encode("utf-8")
        )
        with self.assertRaises(vs.Refusal) as caught:
            vs.reconstruct(summary, root)
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_SOURCE_DIGEST_MISMATCH)

    def test_the_summary_digest_is_the_digest_of_the_decision_record(self) -> None:
        summary = load_json(EVIDENCE / "SUMMARY.json")
        self.assertEqual(
            summary["decisionDigest"],
            vs.sha256_bytes(DECISION_PATH.read_bytes()),
        )
        self.assertEqual(summary["decisionDigest"], vs.decision_digest(load_json(DECISION_PATH)))
        for entry in summary["reconstructedFrom"]:
            with self.subTest(path=entry["path"]):
                self.assertEqual(
                    entry["sha256"], vs.sha256_bytes((REPO / entry["path"]).read_bytes())
                )


class CoverageAndClaims(unittest.TestCase):
    def test_an_omitted_policy_obligation_is_a_coverage_gap(self) -> None:
        root, _decision, summary = vs._control_fixture()
        gap = copy_json(summary)
        gap["obligations"] = [
            entry for entry in gap["obligations"] if entry["id"] != "C02.unmet"
        ]
        gap["counts"] = {"met": 1, "unmet": 0, "unknown": 0, "notApplicable": 0}
        gap["unmet"] = []
        with self.assertRaises(vs.Refusal) as caught:
            vs.reconstruct(gap, root)
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_COVERAGE_GAP)

    def test_an_obligation_not_in_the_policy_is_an_overclaim(self) -> None:
        root, _decision, summary = vs._control_fixture()
        extra = copy_json(summary)
        extra["obligations"].append(
            {
                "id": "C03.extra",
                "state": pe.STATE_MET,
                "sourcePath": summary["obligations"][0]["sourcePath"],
                "sourceDigest": summary["obligations"][0]["sourceDigest"],
            }
        )
        extra["counts"] = {"met": 2, "unmet": 1, "unknown": 0, "notApplicable": 0}
        with self.assertRaises(vs.Refusal) as caught:
            vs.reconstruct(extra, root)
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_OVERCLAIM)

    def test_a_denial_published_as_an_admission_is_refused(self) -> None:
        root, _decision, summary = vs._control_fixture()
        upgraded = copy_json(summary)
        upgraded["decision"] = pe.DECISION_ADMIT
        with self.assertRaises(vs.Refusal) as caught:
            vs.reconstruct(upgraded, root)
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_DECISION_UPGRADED)

    def test_a_flipped_obligation_state_is_an_overclaim(self) -> None:
        root, _decision, summary = vs._control_fixture()
        flipped = copy_json(summary)
        for entry in flipped["obligations"]:
            if entry["id"] == "C02.unmet":
                entry["state"] = pe.STATE_MET
        flipped["counts"] = {"met": 2, "unmet": 0, "unknown": 0, "notApplicable": 0}
        flipped["unmet"] = []
        with self.assertRaises(vs.Refusal) as caught:
            vs.reconstruct(flipped, root)
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_OVERCLAIM)

    def test_an_obligation_without_a_digest_is_refused(self) -> None:
        root, _decision, summary = vs._control_fixture()
        no_digest = copy_json(summary)
        no_digest["obligations"][0]["sourceDigest"] = None
        with self.assertRaises(vs.Refusal) as caught:
            vs.reconstruct(no_digest, root)
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_NO_SOURCE_DIGEST)

    def test_an_empty_source_manifest_is_not_reconstructible(self) -> None:
        root, _decision, summary = vs._control_fixture()
        empty = copy_json(summary)
        empty["reconstructedFrom"] = []
        with self.assertRaises(vs.Refusal) as caught:
            vs.reconstruct(empty, root)
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_NON_RECONSTRUCTIBLE)

    def test_a_consumer_may_not_cite_the_summary_as_evidence(self) -> None:
        root, _decision, summary = vs._control_fixture()
        with self.assertRaises(vs.Refusal) as caught:
            vs.consume(
                summary,
                ["evidence/a21/SUMMARY.json"],
                summary_path="evidence/a21/SUMMARY.json",
            )
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_SUMMARY_AS_EVIDENCE)
        sources = sorted(entry["path"] for entry in summary["reconstructedFrom"])
        self.assertEqual(vs.consume(summary, sources), sources)


class Signature(unittest.TestCase):
    def test_the_statement_subject_is_the_decision_record(self) -> None:
        summary = load_json(EVIDENCE / "SUMMARY.json")
        statement = vs.statement_for(summary, repo=REPO)
        self.assertEqual(statement["_type"], vs.STATEMENT_TYPE)
        self.assertEqual(statement["predicateType"], vs.PREDICATE_TYPE)
        self.assertEqual(
            statement["subject"],
            [
                {
                    "name": vs.DECISION_PATH,
                    "digest": {"sha256": summary["decisionDigest"]},
                }
            ],
        )

    def test_the_signature_is_labelled_self_issued_and_claims_no_authentication(self) -> None:
        summary = load_json(EVIDENCE / "SUMMARY.json")
        _statement, envelope = vs.sign_summary(summary, repo=REPO)
        report = vs.verify_summary(vs.encode_summary(summary), dsse.encode_envelope(envelope), REPO)
        self.assertEqual(report["signatureLabel"], vs.SIGNATURE_LABEL)
        self.assertEqual(report["keyid"], dsse.test_only_keyid())
        label = vs.statement_for(summary, repo=REPO)["predicate"]["signature"]
        self.assertEqual(label["label"], "SELF_ISSUED")
        self.assertEqual(label["authentication"], "NOT_CLAIMED")

    def test_an_unsigned_summary_is_refused(self) -> None:
        root, _decision, summary = vs._control_fixture()
        _statement, envelope = vs.sign_summary(summary, repo=root)
        unsigned = copy_json(envelope)
        unsigned["signatures"] = []
        with self.assertRaises(vs.Refusal) as caught:
            vs.verify_summary(
                vs.encode_summary(summary), dsse.encode_envelope(unsigned), root
            )
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_SUMMARY_UNSIGNED)

    def test_a_summary_mutated_after_signing_is_refused(self) -> None:
        root, _decision, summary = vs._control_fixture()
        _statement, envelope = vs.sign_summary(summary, repo=root)
        mutated = copy_json(summary)
        mutated["unmet"] = []
        with self.assertRaises(vs.Refusal) as caught:
            vs.verify_summary(
                vs.encode_summary(mutated), dsse.encode_envelope(envelope), root
            )
        self.assertEqual(caught.exception.code, vs.AS_REFUSED_SUMMARY_MUTATED)


class RealSummary(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary = load_json(EVIDENCE / "SUMMARY.json")
        cls.reconstruction = load_json(EVIDENCE / "RECONSTRUCTION.json")
        cls.decision = load_json(DECISION_PATH)

    def test_the_real_summary_is_a_summary_of_the_real_decision(self) -> None:
        self.assertEqual(self.summary["topLevel"], "summary")
        self.assertIs(self.summary["replacesEvidence"], False)
        self.assertEqual(self.summary["decision"], "DENY")
        self.assertEqual(len(self.summary["obligations"]), 8)
        self.assertEqual(
            self.summary["counts"],
            {"met": 3, "unmet": 5, "unknown": 0, "notApplicable": 0},
        )
        self.assertEqual(
            self.summary["unmet"],
            [
                "A06.suppression-member-identities",
                "A12.independent-attestation",
                "A14.release-authorised",
                "A15.release-threshold-met",
                "A17.forward-freeze-closed",
            ],
        )
        self.assertEqual(self.summary["decisionDigest"], vs.decision_digest(self.decision))

    def test_the_real_summary_is_the_live_summary(self) -> None:
        live = vs.summarise(self.decision, pe.filesystem_reader(REPO))
        self.assertEqual(vs.encode_summary(live), vs.encode_summary(self.summary))

    def test_reconstructing_the_real_summary_equals_its_counts(self) -> None:
        report = vs.reconstruct(self.summary, REPO)
        self.assertTrue(report["equal"])
        self.assertEqual(report["counts"], self.summary["counts"])
        self.assertEqual(report["unmet"], self.summary["unmet"])
        self.assertEqual(report["decision"], self.summary["decision"])
        for entry in report["obligations"]:
            with self.subTest(obligation=entry["id"]):
                self.assertTrue(entry["matches"])
                self.assertEqual(entry["summaryState"], entry["recomputedState"])

    def test_the_committed_reconstruction_is_the_live_reconstruction(self) -> None:
        self.assertEqual(
            vs.reconstruct(self.summary, REPO), self.reconstruction
        )

    def test_the_committed_envelope_verifies(self) -> None:
        report = vs.verify_summary(
            (EVIDENCE / "SUMMARY.json").read_bytes(),
            (EVIDENCE / "SUMMARY.envelope.json").read_bytes(),
            REPO,
        )
        self.assertEqual(report["code"], vs.CODE_OK)
        self.assertEqual(report["decision"], "DENY")
        self.assertEqual(report["counts"], self.summary["counts"])
        self.assertTrue(report["equal"])

    def test_the_reconstruction_records_nine_sources(self) -> None:
        self.assertEqual(len(self.reconstruction["sources"]), 9)
        self.assertEqual(
            [entry["path"] for entry in self.reconstruction["sources"]],
            sorted(entry["path"] for entry in self.summary["reconstructedFrom"]),
        )


class Determinism(unittest.TestCase):
    def test_the_producer_reproduces_the_committed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for directory in (first, second):
                run = subprocess.run(
                    [sys.executable, str(BUILDER), "--out", directory],
                    cwd=str(REPO), capture_output=True, text=True,
                )
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            for name in (
                "SUMMARY.json",
                "SUMMARY.envelope.json",
                "RECONSTRUCTION.json",
                "CONTROLS.json",
            ):
                with self.subTest(name=name):
                    committed = (EVIDENCE / name).read_bytes()
                    self.assertEqual((Path(first) / name).read_bytes(), committed)
                    self.assertEqual((Path(second) / name).read_bytes(), committed)


class CommandLine(unittest.TestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOLS / "verification_summary.py"), *arguments],
            cwd=str(REPO), capture_output=True, text=True,
        )

    def test_summarise_exits_zero_and_prints_the_code(self) -> None:
        result = self.run_cli("summarise")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("code=AS_OK", result.stdout)
        self.assertIn("decision=DENY", result.stdout)
        self.assertIn("met=3 unmet=5", result.stdout)

    def test_reconstruct_exits_zero_and_prints_the_counts(self) -> None:
        result = self.run_cli("reconstruct", "evidence/a21/SUMMARY.json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("code=AS_OK", result.stdout)
        self.assertIn("equal=true", result.stdout)

    def test_verify_exits_zero_and_prints_the_label(self) -> None:
        result = self.run_cli(
            "verify", "evidence/a21/SUMMARY.json", "evidence/a21/SUMMARY.envelope.json"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("code=AS_OK", result.stdout)
        self.assertIn("label=SELF_ISSUED", result.stdout)

    def test_a_refused_reconstruction_exits_one_and_prints_the_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = load_json(EVIDENCE / "SUMMARY.json")
            summary["counts"] = {"met": 8, "unmet": 0, "unknown": 0, "notApplicable": 0}
            path = Path(directory) / "summary.json"
            path.write_bytes(vs.encode_summary(summary))
            result = self.run_cli("reconstruct", str(path))
            self.assertEqual(result.returncode, 1)
            self.assertIn("AS_REFUSED_COUNTS_MISMATCH", result.stdout)

    def test_a_missing_input_is_a_usage_error_with_a_code(self) -> None:
        result = self.run_cli("reconstruct", "evidence/a21/absent.json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("AS_USAGE", result.stdout)

    def test_an_unknown_command_is_a_usage_error_with_a_code(self) -> None:
        result = self.run_cli("frobnicate")
        self.assertEqual(result.returncode, 2)
        self.assertIn("AS_USAGE", result.stdout)


class DocumentSynchronisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8")

    def test_every_refusal_code_is_named_in_the_document(self) -> None:
        for code in vs.REFUSAL_CODES:
            with self.subTest(code=code):
                self.assertIn(code, self.text)

    def test_the_document_names_no_unknown_refusal_code(self) -> None:
        import re

        named = set(re.findall(r"AS_REFUSED_[A-Z_]+", self.text))
        self.assertEqual(sorted(named - set(vs.REFUSAL_CODES)), [])

    def test_the_document_names_the_real_obligations_and_sources(self) -> None:
        summary = load_json(EVIDENCE / "SUMMARY.json")
        for entry in summary["obligations"]:
            with self.subTest(obligation=entry["id"]):
                self.assertIn(entry["id"], self.text)
                self.assertIn(entry["sourcePath"], self.text)

    def test_the_document_states_the_real_counts_and_decision(self) -> None:
        for phrase in ("8 obligations", "3 `MET`", "5 `UNMET`", "`DENY`"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.text)

    def test_the_document_carries_the_marker_and_the_signature_caveat(self) -> None:
        self.assertIn("replacesEvidence", self.text)
        self.assertIn("SELF_ISSUED", self.text)
        self.assertIn("not an admission", self.text)

    def test_the_document_names_the_command_line(self) -> None:
        for command in ("summarise", "reconstruct", "verify"):
            with self.subTest(command=command):
                self.assertIn(f"verification_summary.py {command}", self.text)


if __name__ == "__main__":
    unittest.main()
