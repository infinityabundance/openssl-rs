#!/usr/bin/env python3
"""Controls for the PFP-9 kernel provenance and no-inheritance validator.

The validator must refuse evidence cited at a different identity and must accept
a legitimate artefact-bound entry as `NO_PROOF` (non-vacuity). Every refusal code
has a negative control in the tool's self-test; this module additionally checks
the committed register, the document binding, and the real-register refusals the
document promises (SOS at the wrong digest, the DH preset repair without an
audit, and source-bound constant-time evidence).

Run:

    python3 forensics/tools/tests/test_kernel_verification.py
"""

from __future__ import annotations

import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
TOOL = TOOLS / "kernel_verification.py"
REGISTER = REPO_ROOT / "forensics" / "performance" / "KERNELS.json"
DOC = REPO_ROOT / "docs" / "KERNEL-VERIFICATION.md"

sys.path.insert(0, str(TOOLS))
import kernel_verification as kv  # noqa: E402


def load(path: Path = REGISTER) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def codes(document: dict, doc_text: str | None = None) -> list[str]:
    return sorted({problem.code for problem in kv.check_document(document, doc_text=doc_text)})


class CommittedRegister(unittest.TestCase):
    # On a clean checkout the audited DSOs are absent by design.  The register
    # must fail closed, never pass on a declared digest alone (PFP-86).  A
    # declared unavailable subject is a non-pass too, but a typed one.
    RETRIEVAL_ONLY = {
        kv.KV_SUBJECT_NOT_RETRIEVABLE,
        kv.KV_SUBJECT_UNAVAILABLE_DECLARED,
        kv.KV_SUBJECT_REPRODUCIBLE_NOT_RETRIEVED,
    }

    def test_the_committed_register_is_accepted_or_refused_as_unretrievable(self) -> None:
        codes_found = {problem.code for problem in kv.check_document(load())}
        self.assertTrue(
            codes_found == set() or codes_found <= self.RETRIEVAL_ONLY,
            sorted(codes_found),
        )

    def test_the_cli_accepts_or_names_unretrievable_subjects(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "check"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            self.assertIn("1 register(s) accepted, 0 refused", result.stdout)
        else:
            self.assertTrue(
                kv.KV_SUBJECT_NOT_RETRIEVABLE in result.stdout
                or kv.KV_SUBJECT_UNAVAILABLE_DECLARED in result.stdout,
                result.stdout,
            )
            self.assertNotIn("KV_AUDIT_RECORD_LEGACY_SHAPE", result.stdout)

    def test_every_kernel_names_the_hardware_absent_arms(self) -> None:
        document = load()
        for kernel in document["kernels"]:
            targets = {entry["target"]: entry for entry in kernel["no_evidence_targets"]}
            self.assertIn("aarch64-unknown-linux-gnu", targets, kernel["id"])
            self.assertEqual(
                targets["aarch64-unknown-linux-gnu"]["status"], "NOT_APPLICABLE_HARDWARE"
            )
            avx512 = [name for name in targets if "avx512ifma" in name]
            self.assertTrue(avx512, kernel["id"])
            self.assertEqual(targets[avx512[0]]["status"], "NOT_APPLICABLE_HARDWARE")

    def test_every_kernel_has_an_explicit_proof_status(self) -> None:
        for kernel in load()["kernels"]:
            self.assertEqual(kernel["proof"], "NO_PROOF", kernel["id"])

    def test_every_evidence_record_matches_its_campaign(self) -> None:
        document = load()
        campaigns = document["campaigns"]
        for kernel in document["kernels"]:
            for record in kernel["evidence"]:
                artefact = campaigns[record["campaign"]]["artefact"]
                self.assertEqual(record["target"], artefact["target"], kernel["id"])
                self.assertEqual(record["profile"], artefact["profile"], kernel["id"])
                if artefact["binding"] == "ARTEFACT":
                    self.assertEqual(record["artefact_sha256"], artefact["sha256"])
                else:
                    self.assertIsNone(record["artefact_sha256"])
                    self.assertEqual(record["binding"], "SOURCE")

    def test_the_source_bound_entry_is_accepted_only_without_an_assurance_claim(self) -> None:
        document = load()
        claims = {claim["id"]: claim for claim in document["claims"]}
        preset = claims["PFP-8-PRESET-e3ef3d84-DIFFERENTIAL-ONLY"]
        self.assertEqual(preset["assurance"], [])
        # Only a subject-availability refusal is allowed on a clean checkout.
        self.assertLessEqual(
            {problem.code for problem in kv.check_document(document)},
            {
                kv.KV_SUBJECT_NOT_RETRIEVABLE,
                kv.KV_SUBJECT_UNAVAILABLE_DECLARED,
                kv.KV_SUBJECT_REPRODUCIBLE_NOT_RETRIEVED,
            },
        )
        mutated = copy.deepcopy(document)
        for claim in mutated["claims"]:
            if claim["id"] == "PFP-8-PRESET-e3ef3d84-DIFFERENTIAL-ONLY":
                claim["assurance"] = ["ARTEFACT_AUDITED"]
        self.assertIn(kv.KV_CT_CLAIM_WITHOUT_AUDIT, codes(mutated))

    def test_no_constant_time_boolean_remains(self) -> None:
        document = load()
        for claim in document["claims"]:
            self.assertNotIn("constant_time", claim, claim["id"])
        for kernel in document["kernels"]:
            self.assertNotIn("constant_time", kernel, kernel["id"])

    def test_every_kernel_records_an_assurance_dimension(self) -> None:
        for kernel in load()["kernels"]:
            entries = kernel.get("assurance")
            self.assertIsInstance(entries, list, kernel["id"])
            self.assertTrue(entries, kernel["id"])
            for entry in entries:
                self.assertIn(entry["class"], kv.ASSURANCE_CLASSES, kernel["id"])

    def test_the_migration_claims_no_artefact_class_without_a_retrieval_clause(self) -> None:
        # An artefact class must name how the uncommitted subject is reproduced,
        # and the declared digest must be the one retrieval must yield.
        for kernel in load()["kernels"]:
            for entry in kernel["assurance"]:
                if entry["class"] not in kv.ARTEFACT_CLASSES:
                    continue
                artefact = entry["subject"]["artefact"]
                self.assertRegex(artefact["sha256"], r"^[0-9a-f]{64}$", kernel["id"])
                clause = artefact["retrieval"]
                self.assertTrue(clause["mechanism"], kernel["id"])
                self.assertEqual(clause["expected_sha256"], artefact["sha256"], kernel["id"])

    def test_the_rsa_crt_family_is_not_flattered(self) -> None:
        document = load()
        rsa = next(kernel for kernel in document["kernels"] if kernel["id"] == "rsa-crt")
        self.assertEqual([entry["class"] for entry in rsa["assurance"]], ["UNASSESSED"])
        claim = next(c for c in document["claims"] if c["id"] == "PFP-7-RSA-6d002db2")
        self.assertEqual(claim["assurance"], [])

    def test_every_proof_is_no_proof_or_a_bound_machine_check(self) -> None:
        for kernel in load()["kernels"]:
            self.assertIn(kernel["proof"], kv.PROOF_STATES, kernel["id"])
            if kernel["proof"] == "MACHINE_CHECKED":
                self.assertTrue(
                    any(
                        entry["class"] == "MACHINE_CHECKED"
                        for entry in kernel["assurance"]
                    ),
                    kernel["id"],
                )

    def test_sos_is_not_inherited_across_digests(self) -> None:
        document = load()
        kernels = {kernel["id"]: kernel for kernel in document["kernels"]}
        sos = kernels["bn-mont-sos"]
        self.assertIsNone(sos["evidence"][0]["audit"])
        self.assertIsNotNone(sos["evidence"][1]["audit"])
        self.assertNotEqual(
            sos["evidence"][0]["artefact_sha256"], sos["evidence"][1]["artefact_sha256"]
        )
        mutated = copy.deepcopy(document)
        for claim in mutated["claims"]:
            if claim["id"] == "PFP-5-SOS-842efa27":
                claim["target"] = sos["evidence"][0]["target"]
                claim["profile"] = sos["evidence"][0]["profile"]
                claim["artefact_sha256"] = sos["evidence"][0]["artefact_sha256"]
                claim["assurance"] = ["ARTEFACT_AUDITED"]
                claim["kernels"] = [{"id": "bn-mont-sos", "evidence": 0}]
        self.assertIn(kv.KV_CT_CLAIM_WITHOUT_AUDIT, codes(mutated))

    def test_the_arch_kernel_cannot_support_an_artefact_claim(self) -> None:
        document = load()
        arch = next(kernel for kernel in document["kernels"] if kernel["id"] == "p256-field-arch")
        claim = {
            "id": "arch-ct",
            "assurance": ["ARTEFACT_AUDITED"],
            "target": arch["evidence"][0]["target"],
            "profile": arch["evidence"][0]["profile"],
            "artefact_sha256": arch["evidence"][0]["artefact_sha256"],
            "kernels": [{"id": "p256-field-arch", "evidence": 0}],
        }
        mutated = copy.deepcopy(document)
        mutated["claims"].append(claim)
        found = codes(mutated)
        self.assertIn(kv.KV_SOURCE_BOUND_CT_CLAIM, found)
        self.assertIn(kv.KV_CT_CLAIM_WITHOUT_AUDIT, found)

    def test_the_document_names_every_kernel_and_the_rule(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        for kernel in load()["kernels"]:
            self.assertIn(kernel["id"], text)
        self.assertIn("no-inheritance", text.lower())
        self.assertIn("NOT_APPLICABLE_HARDWARE", text)


class Refusals(unittest.TestCase):
    def test_one_negative_control_per_non_document_code(self) -> None:
        controlled = {
            expected
            for _name, _document, expected in kv._controls()
            if expected is not None
        }
        document_codes = {
            kv.KV_DOC_KERNEL_MISSING,
            kv.KV_DOC_NO_INHERITANCE_MISSING,
            kv.KV_JSON_MALFORMED,
            kv.KV_JSON_DUPLICATE_KEY,
            kv.KV_JSON_NON_FINITE,
        }
        self.assertEqual(set(kv.CODES) - document_codes, controlled)

    def test_the_self_test_passes(self) -> None:
        self.assertEqual(kv.self_test(), 0)

    def test_a_different_evidence_digest_is_refused(self) -> None:
        document = load()
        document["kernels"][0]["evidence"][0]["artefact_sha256"] = "b" * 64
        self.assertIn(kv.KV_EVIDENCE_DIGEST_MISMATCH, codes(document))

    def test_a_different_target_is_refused(self) -> None:
        document = load()
        document["kernels"][0]["evidence"][0]["target"] = "another-target"
        self.assertIn(kv.KV_TARGET_MISMATCH, codes(document))

    def test_a_different_profile_is_refused(self) -> None:
        document = load()
        document["kernels"][0]["evidence"][0]["profile"] = "another-profile"
        self.assertIn(kv.KV_PROFILE_MISMATCH, codes(document))

    def test_an_inherited_audit_digest_is_refused(self) -> None:
        document = load()
        document["kernels"][0]["evidence"][0]["audit"]["digest"] = "b" * 64
        self.assertIn(kv.KV_AUDIT_DIGEST_MISMATCH, codes(document))

    def test_a_claim_across_identities_is_refused(self) -> None:
        document = load()
        document["claims"][0]["target"] = "another-target"
        self.assertIn(kv.KV_CLAIM_IDENTITY_MISMATCH, codes(document))

    def test_a_missing_audit_is_refused_for_an_artefact_assurance_claim(self) -> None:
        document = load()
        document["kernels"][0]["evidence"][0]["binding"] = "ARTEFACT"
        document["kernels"][0]["evidence"][0]["audit"] = None
        for claim in document["claims"]:
            if claim["id"] == "PFP-6-CIOS-6d002db2":
                claim["assurance"] = ["ARTEFACT_AUDITED"]
        self.assertIn(kv.KV_CT_CLAIM_WITHOUT_AUDIT, codes(document))

    def test_a_missing_court_is_refused_for_an_artefact_assurance_claim(self) -> None:
        document = load()
        document["kernels"][0]["evidence"][0]["binding"] = "ARTEFACT"
        document["kernels"][0]["evidence"][0]["differential"] = None
        for claim in document["claims"]:
            if claim["id"] == "PFP-6-CIOS-6d002db2":
                claim["assurance"] = ["ARTEFACT_AUDITED"]
        self.assertIn(kv.KV_CT_CLAIM_WITHOUT_COURT, codes(document))

    def test_a_blank_proof_is_refused(self) -> None:
        document = load()
        document["kernels"][0]["proof"] = ""
        self.assertIn(kv.KV_PROOF_ABSENT, codes(document))

    def test_malformed_duplicate_and_non_finite_loads_are_refused(self) -> None:
        with self.assertRaises(kv.Refusal) as malformed:
            kv.loads_document("{")
        self.assertEqual(malformed.exception.code, kv.KV_JSON_MALFORMED)
        with self.assertRaises(kv.Refusal) as duplicate:
            kv.loads_document('{"a": 1, "a": 2}')
        self.assertEqual(duplicate.exception.code, kv.KV_JSON_DUPLICATE_KEY)
        with self.assertRaises(kv.Refusal) as non_finite:
            kv.loads_document('{"a": NaN}')
        self.assertEqual(non_finite.exception.code, kv.KV_JSON_NON_FINITE)


class AssuranceDefects(unittest.TestCase):
    """One mutation test per acceptance defect the PFP-49 review found."""

    def fixture(self) -> dict:
        return copy.deepcopy(kv._valid_document())

    def test_a_complete_assurance_claim_is_accepted(self) -> None:
        self.assertEqual(kv.check_document(self.fixture()), [])

    def test_mixed_binding_refuses_an_artefact_class(self) -> None:
        document = self.fixture()
        document["kernels"][0]["evidence"][0]["binding"] = "MIXED"
        self.assertIn(kv.KV_ASSURANCE_BINDING_MISMATCH, codes(document))

    def test_an_audit_without_a_structured_pass_is_refused(self) -> None:
        document = self.fixture()
        document["kernels"][0]["evidence"][0]["audit"]["verdict"] = "NOT_RUN"
        self.assertIn(kv.KV_AUDIT_VERDICT_NOT_PASS, codes(document))

    def test_a_taint_class_without_taint_evidence_is_refused(self) -> None:
        document = self.fixture()
        document["kernels"][0]["evidence"][0]["ctgrind"] = None
        self.assertIn(kv.KV_ASSURANCE_TAINT_ABSENT, codes(document))

    def test_a_taint_class_without_a_firing_control_is_refused(self) -> None:
        document = self.fixture()
        document["kernels"][0]["assurance"][1]["negative_control"]["fired"] = False
        self.assertIn(kv.KV_ASSURANCE_NO_FIRING_CONTROL, codes(document))

    def test_a_prose_proof_is_refused(self) -> None:
        document = self.fixture()
        document["kernels"][0]["proof"] = "checked by inspection"
        self.assertIn(kv.KV_PROOF_UNBOUND, codes(document))

    def test_pass_with_stop_or_residual_above_source_reviewed_is_refused(self) -> None:
        for result in ("PASS_WITH_STOP", "PASS_WITH_RESIDUAL"):
            document = self.fixture()
            document["kernels"][0]["assurance"][0]["result"] = result
            self.assertIn(kv.KV_ASSURANCE_OUTCOME_INADMISSIBLE, codes(document))

    def test_the_subject_is_hashed_not_just_declared(self) -> None:
        document = self.fixture()
        artefact = document["kernels"][0]["assurance"][0]["subject"]["artefact"]
        # The declared digest still matches the evidence record, the claim and the
        # audit; only the file at the named path has different bytes.
        artefact["path"] = "docs/KERNEL-VERIFICATION.md"
        self.assertIn(kv.KV_ARTEFACT_SUBJECT_MISMATCH, codes(document))

    def test_an_unretrieved_subject_is_refused_not_passed(self) -> None:
        # PFP-86 mutation control: the audited binary is absent, so the entry must
        # fail closed with SUBJECT_NOT_RETRIEVABLE rather than trust its digest.
        document = self.fixture()
        document["kernels"][0]["assurance"][0]["subject"]["artefact"]["path"] = (
            "docs/not-retrieved.so"
        )
        found = codes(document)
        self.assertIn(kv.KV_SUBJECT_NOT_RETRIEVABLE, found)
        self.assertNotIn(kv.KV_ARTEFACT_SUBJECT_MISMATCH, found)

    def test_a_legacy_boolean_record_is_refused(self) -> None:
        # PFP-84 mutation control: re-introduce the old zero shape.
        document = self.fixture()
        record = document["kernels"][0]["assurance"][0]["secret_dependence"]["document"]
        record["targets"]["mont_mul_ladder_into"]["secret_derived_jcc"] = 0
        self.assertIn(kv.KV_AUDIT_RECORD_LEGACY_SHAPE, codes(document))

    def test_a_verdict_cannot_be_read_from_not_assessed(self) -> None:
        # PFP-84 mutation control: the record says NOT_ASSESSED, the entry reads
        # OBSERVED_ZERO.  The verdict must be refused.
        document = self.fixture()
        record = document["kernels"][0]["assurance"][0]["secret_dependence"]["document"]
        record["targets"]["mont_mul_ladder_into"]["secret_dependence"]["jcc"] = (
            kv.NOT_ASSESSED
        )
        self.assertIn(kv.KV_SECRET_DEPENDENCE_UNMEASURED, codes(document))

    def test_the_aggregate_mechanised_count_must_match_the_states(self) -> None:
        document = self.fixture()
        record = document["kernels"][0]["assurance"][0]["secret_dependence"]["document"]
        record["secret_dependence_aggregate"]["mechanised_targets"] = 0
        self.assertIn(kv.KV_AUDIT_RECORD_AGGREGATE_MISMATCH, codes(document))

    def test_source_review_argument_must_name_the_reviewed_source(self) -> None:
        document = load()
        document["kernels"][0]["assurance"][0]["scope"] = "the kernel looks constant-time"
        self.assertIn(kv.KV_ASSURANCE_INCOMPLETE, codes(document))

    def test_machine_checked_with_a_bound_harness_is_accepted(self) -> None:
        document = self.fixture()
        entry = document["kernels"][0]["assurance"][0]
        entry["class"] = "MACHINE_CHECKED"
        entry["instrument"] = "kani"
        entry["harness"] = {"path": str(kv._FIXTURE_ARTEFACT), "sha256": kv._A}
        document["kernels"][0]["proof"] = "MACHINE_CHECKED"
        document["claims"][0]["assurance"] = ["MACHINE_CHECKED", "SOURCE_TAINT_TESTED"]
        self.assertEqual(kv.check_document(document), [])

    def test_statistically_tested_with_a_declared_experiment_is_accepted(self) -> None:
        document = self.fixture()
        entry = document["kernels"][0]["assurance"][0]
        entry["class"] = "STATISTICALLY_TESTED"
        entry["experiment"] = {
            "samples": 15,
            "statistic": "median paired ratio",
            "threshold": "1.0",
            "environment": "taskset -c 1, court feature set",
        }
        document["claims"][0]["assurance"] = ["STATISTICALLY_TESTED", "SOURCE_TAINT_TESTED"]
        self.assertEqual(kv.check_document(document), [])

    def test_independent_reproduction_with_a_distinct_party_is_accepted(self) -> None:
        document = self.fixture()
        entry = document["kernels"][0]["assurance"][0]
        entry["class"] = "INDEPENDENTLY_REPRODUCED"
        entry["reproduction"] = {
            "party": "independent reviewer",
            "producer": "campaign author",
        }
        document["claims"][0]["assurance"] = [
            "INDEPENDENTLY_REPRODUCED",
            "SOURCE_TAINT_TESTED",
        ]
        self.assertEqual(kv.check_document(document), [])

    def test_a_class_the_kernel_does_not_hold_is_refused(self) -> None:
        document = self.fixture()
        document["claims"][0]["assurance"] = ["MACHINE_CHECKED"]
        self.assertIn(kv.KV_ASSURANCE_CLASS_ABSENT, codes(document))

    def test_source_review_needs_a_written_invariant_argument(self) -> None:
        document = self.fixture()
        entry = document["kernels"][0]["assurance"][0]
        entry["class"] = "SOURCE_REVIEWED"
        entry["assumptions"] = []
        self.assertIn(kv.KV_ASSURANCE_INCOMPLETE, codes(document))

    def test_machine_checked_needs_an_existing_harness_and_digest(self) -> None:
        document = self.fixture()
        entry = document["kernels"][0]["assurance"][0]
        entry["class"] = "MACHINE_CHECKED"
        entry["instrument"] = "kani"
        entry["harness"] = {"path": "evidence/absent-harness.py", "sha256": "b" * 64}
        self.assertIn(kv.KV_ASSURANCE_INCOMPLETE, codes(document))

    def test_statistically_tested_needs_a_declared_experiment(self) -> None:
        document = self.fixture()
        entry = document["kernels"][0]["assurance"][0]
        entry["class"] = "STATISTICALLY_TESTED"
        entry.pop("experiment", None)
        self.assertIn(kv.KV_ASSURANCE_INCOMPLETE, codes(document))

    def test_independent_reproduction_needs_a_distinct_party(self) -> None:
        document = self.fixture()
        entry = document["kernels"][0]["assurance"][0]
        entry["class"] = "INDEPENDENTLY_REPRODUCED"
        entry["reproduction"] = {"party": "same", "producer": "Same"}
        self.assertIn(kv.KV_ASSURANCE_INCOMPLETE, codes(document))


class RetrievalMechanisms(unittest.TestCase):
    """PFP-90: retrieval kinds are typed, and only retrieval validates bytes."""

    def setUp(self) -> None:
        self.cache = tempfile.TemporaryDirectory()
        self.addCleanup(self.cache.cleanup)
        self.source_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.source_dir.cleanup)
        self._old_cache = os.environ.get("OPENSSL_RS_AUDIT_SUBJECT_CACHE")
        os.environ["OPENSSL_RS_AUDIT_SUBJECT_CACHE"] = self.cache.name
        self.addCleanup(self._restore_cache)

    def _restore_cache(self) -> None:
        if self._old_cache is None:
            os.environ.pop("OPENSSL_RS_AUDIT_SUBJECT_CACHE", None)
        else:
            os.environ["OPENSSL_RS_AUDIT_SUBJECT_CACHE"] = self._old_cache

    def fixture(self) -> dict:
        return copy.deepcopy(kv._valid_document())

    def retrieval(self, document: dict) -> dict:
        return document["kernels"][0]["assurance"][0]["subject"]["artefact"][
            "retrieval"
        ]

    def artifact(self, document: dict) -> dict:
        return document["kernels"][0]["assurance"][0]["subject"]["artefact"]

    def test_a_release_asset_is_fetched_and_hashed(self) -> None:
        data = b"the audited subject bytes"
        digest = hashlib.sha256(data).hexdigest()
        source = Path(self.source_dir.name) / "asset.bin"
        source.write_bytes(data)
        document = self.fixture()
        self.artifact(document)["sha256"] = digest
        self.retrieval(document).update(
            kind="release-asset", url=source.as_uri(), expected_sha256=digest
        )
        found = codes(document)
        self.assertNotIn(kv.KV_SUBJECT_NOT_RETRIEVABLE, found)
        self.assertNotIn(kv.KV_ARTEFACT_SUBJECT_MISMATCH, found)

    def test_a_release_asset_with_the_wrong_digest_is_refused(self) -> None:
        data = b"not the audited bytes"
        source = Path(self.source_dir.name) / "asset.bin"
        source.write_bytes(data)
        document = self.fixture()
        declared = "b" * 64
        self.artifact(document)["sha256"] = declared
        self.retrieval(document).update(
            kind="release-asset", url=source.as_uri(), expected_sha256=declared
        )
        found = codes(document)
        self.assertIn(kv.KV_ARTEFACT_SUBJECT_MISMATCH, found)
        self.assertNotIn(kv.KV_SUBJECT_NOT_RETRIEVABLE, found)

    def test_a_failed_release_asset_download_is_refused(self) -> None:
        document = self.fixture()
        missing = Path(self.source_dir.name) / "missing.bin"
        self.retrieval(document).update(
            kind="release-asset",
            url=missing.as_uri(),
            expected_sha256=self.artifact(document)["sha256"],
        )
        self.assertIn(kv.KV_SUBJECT_NOT_RETRIEVABLE, codes(document))

    def test_an_unavailable_declaration_without_why_is_refused(self) -> None:
        document = self.fixture()
        self.retrieval(document).update(
            kind="unavailable", recipe="forensics/tools/kernel_verification.py"
        )
        self.retrieval(document).pop("why", None)
        found = codes(document)
        self.assertIn(kv.KV_ASSURANCE_INCOMPLETE, found)
        self.assertNotIn(kv.KV_SUBJECT_UNAVAILABLE_DECLARED, found)

    def test_an_unavailable_declaration_is_a_declared_non_pass(self) -> None:
        document = self.fixture()
        self.retrieval(document).update(
            kind="unavailable",
            why="the bytes were deleted",
            recipe="forensics/tools/kernel_verification.py",
        )
        found = codes(document)
        self.assertIn(kv.KV_SUBJECT_UNAVAILABLE_DECLARED, found)
        self.assertIn(kv.KV_SUBJECT_UNAVAILABLE_DECLARED, kv.DECLARED_SUBJECT_CODES)

    def test_no_kind_still_emits_the_hard_refusal(self) -> None:
        document = self.fixture()
        self.artifact(document)["path"] = "docs/not-retrieved.so"
        self.assertNotIn("kind", self.retrieval(document))
        found = codes(document)
        self.assertIn(kv.KV_SUBJECT_NOT_RETRIEVABLE, found)
        self.assertNotIn(kv.KV_SUBJECT_UNAVAILABLE_DECLARED, found)

    def test_a_reproduce_recipe_is_verified_but_never_executed(self) -> None:
        recipe = Path(kv.__file__)
        document = self.fixture()
        self.retrieval(document).update(
            kind="reproduce",
            recipe=str(recipe),
            recipe_sha256=hashlib.sha256(recipe.read_bytes()).hexdigest(),
        )
        found = codes(document)
        self.assertIn(kv.KV_SUBJECT_REPRODUCIBLE_NOT_RETRIEVED, found)
        self.assertNotIn(kv.KV_ARTEFACT_SUBJECT_MISMATCH, found)

    def test_a_reproduce_recipe_with_the_wrong_digest_is_refused(self) -> None:
        document = self.fixture()
        self.retrieval(document).update(
            kind="reproduce",
            recipe="forensics/tools/kernel_verification.py",
            recipe_sha256="b" * 64,
        )
        found = codes(document)
        self.assertIn(kv.KV_ARTEFACT_SUBJECT_MISMATCH, found)
        self.assertNotIn(kv.KV_SUBJECT_REPRODUCIBLE_NOT_RETRIEVED, found)


class GateWiring(unittest.TestCase):
    """PFP-49 defect 7: the checker must run where the gate runs."""

    def test_check_root_refuses_a_defective_register(self) -> None:
        document = copy.deepcopy(kv._valid_document())
        document["kernels"][0]["proof"] = "checked by inspection"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "forensics" / "performance").mkdir(parents=True)
            (root / "docs").mkdir()
            (root / "forensics/performance/KERNELS.json").write_text(
                json.dumps(document), encoding="utf-8"
            )
            (root / "docs/KERNEL-VERIFICATION.md").write_text(
                "k-artefact k-source no-inheritance rule", encoding="utf-8"
            )
            found = {problem.code for problem in kv.check_root(root)}
        self.assertIn(kv.KV_PROOF_UNBOUND, found)

    def test_docs_consistency_runs_the_kernel_checker(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "docs_consistency_under_test", TOOLS / "docs_consistency.py"
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.assertIs(module.kernel_verification, kv)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = module.main(["--list"])
        self.assertEqual(code, 0)
        self.assertIn("kernel_register_assurance", buffer.getvalue())

    def test_docs_consistency_propagates_a_kernel_refusal(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "docs_consistency_refusal_under_test", TOOLS / "docs_consistency.py"
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        original = module.kernel_verification.check_root

        def refuse(_root: Path) -> list:
            return [kv.Problem("/kernels/0/proof", kv.KV_PROOF_UNBOUND, "defect")]

        module.kernel_verification.check_root = refuse
        try:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = module.main([])
        finally:
            module.kernel_verification.check_root = original
        self.assertEqual(code, 1)
        self.assertIn(kv.KV_PROOF_UNBOUND, buffer.getvalue())

    def test_the_summary_counts_the_committed_unavailable_declaration(self) -> None:
        summary = kv.artefact_subject_summary(REPO_ROOT)
        self.assertEqual(summary["VALIDATED"], 0)
        self.assertEqual(summary["REPRODUCIBLE_NOT_RETRIEVED"], 0)
        self.assertEqual(summary["UNAVAILABLE_DECLARED"], 5)

    def test_docs_consistency_refuses_a_summary_that_omits_a_declared_non_pass(
        self,
    ) -> None:
        spec = importlib.util.spec_from_file_location(
            "docs_consistency_summary_under_test", TOOLS / "docs_consistency.py"
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        original = module.kernel_verification.artefact_subject_summary
        module.kernel_verification.artefact_subject_summary = lambda _root: {
            "VALIDATED": 0,
            "REPRODUCIBLE_NOT_RETRIEVED": 0,
            "UNAVAILABLE_DECLARED": 0,
        }
        try:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = module.main([])
        finally:
            module.kernel_verification.artefact_subject_summary = original
        self.assertEqual(code, 1)
        self.assertIn("declared non-pass must be reported", buffer.getvalue())

    def test_docs_consistency_prints_the_declared_summary(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "docs_consistency_summary_printed_under_test", TOOLS / "docs_consistency.py"
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            module.main([])
        text = buffer.getvalue()
        self.assertIn("[docs-consistency] artefact-audited subjects:", text)
        self.assertIn("5 UNAVAILABLE_DECLARED", text)
        self.assertIn("DECLARED:", text)


class Determinism(unittest.TestCase):
    def test_problems_are_sorted_and_deduplicated(self) -> None:
        document = load()
        document["kernels"][0]["evidence"][0]["artefact_sha256"] = "b" * 64
        document["kernels"][0]["evidence"][0]["target"] = "another-target"
        first = kv.check_document(document)
        second = kv.check_document(copy.deepcopy(document))
        self.assertEqual(first, second)
        self.assertEqual(first, sorted(set(first)))

    def test_rules_lists_every_code(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "rules"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for code in kv.CODES:
            self.assertIn(code, result.stdout)


if __name__ == "__main__":
    unittest.main()
