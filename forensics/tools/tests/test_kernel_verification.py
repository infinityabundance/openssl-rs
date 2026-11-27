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
import json
import subprocess
import sys
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
    def test_the_committed_register_is_accepted(self) -> None:
        self.assertEqual(kv.check_document(load()), [])

    def test_the_cli_accepts_the_committed_register_and_the_document(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "check"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 register(s) accepted, 0 refused", result.stdout)

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

    def test_the_source_bound_entry_is_accepted_only_without_a_constant_time_claim(self) -> None:
        document = load()
        claims = {claim["id"]: claim for claim in document["claims"]}
        preset = claims["PFP-8-PRESET-e3ef3d84-DIFFERENTIAL-ONLY"]
        self.assertFalse(preset["constant_time"])
        self.assertEqual(kv.check_document(document), [])
        mutated = copy.deepcopy(document)
        for claim in mutated["claims"]:
            if claim["id"] == "PFP-8-PRESET-e3ef3d84-DIFFERENTIAL-ONLY":
                claim["constant_time"] = True
        self.assertIn(kv.KV_CT_CLAIM_WITHOUT_AUDIT, codes(mutated))

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
                claim["kernels"] = [{"id": "bn-mont-sos", "evidence": 0}]
        self.assertIn(kv.KV_CT_CLAIM_WITHOUT_AUDIT, codes(mutated))

    def test_the_arch_kernel_cannot_support_a_constant_time_claim(self) -> None:
        document = load()
        arch = next(kernel for kernel in document["kernels"] if kernel["id"] == "p256-field-arch")
        claim = {
            "id": "arch-ct",
            "constant_time": True,
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

    def test_a_missing_audit_is_refused_for_a_constant_time_claim(self) -> None:
        document = load()
        document["kernels"][0]["evidence"][0]["audit"] = None
        self.assertIn(kv.KV_CT_CLAIM_WITHOUT_AUDIT, codes(document))

    def test_a_missing_court_is_refused_for_a_constant_time_claim(self) -> None:
        document = load()
        document["kernels"][0]["evidence"][0]["differential"] = None
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
