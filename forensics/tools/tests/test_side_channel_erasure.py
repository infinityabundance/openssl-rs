#!/usr/bin/env python3
"""Controls for the ETP-T7 validator and preregistration checker.

Each required refusal rule has a negative control that must be refused by name,
and each has a positive control that must be accepted. The committed register,
audit and preregistration must validate, and the committed prospective and
reconstructed receipts must match their preregistrations. Mutation controls
prove that a changed count, a wrong source token, an uncovered erasure
obligation, a missing preregistration field and a changed measurement geometry
are all refused.

Run inside the court:

    python3 forensics/tools/tests/test_side_channel_erasure.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
VALIDATOR = TOOLS / "side_channel_erasure.py"
CHECKER = TOOLS / "preregistration_check.py"
SECRETS = REPO_ROOT / "evidence" / "etp-t7" / "SECRETS.json"
ERASURE = REPO_ROOT / "evidence" / "etp-t7" / "ERASURE-AUDIT.json"
PREREG = REPO_ROOT / "evidence" / "etp-t7" / "PREREGISTRATION.json"
PROSPECTIVE = REPO_ROOT / "evidence" / "etp-t7" / "DUDECT-ETP-T7.json"
LEGACY = REPO_ROOT / "courts" / "phase18" / "timing" / "RECEIPT-dudect-modes.json"

sys.path.insert(0, str(TOOLS))
import preregistration_check as pc  # noqa: E402
import side_channel_erasure as sce  # noqa: E402


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class RefusalRules(unittest.TestCase):
    """One negative and one positive control per refusal rule."""

    def setUp(self) -> None:
        self.secrets = load(SECRETS)
        self.prereg = load(PREREG)

    def assert_refused(self, claim: dict, code: str) -> None:
        codes = [item[0] for item in sce.check_claim(claim, self.secrets, self.prereg)]
        self.assertIn(code, codes, f"expected {code}, got {codes}")

    def assert_accepted(self, claim: dict) -> None:
        refusals = sce.check_claim(claim, self.secrets, self.prereg)
        self.assertEqual(refusals, [], f"unexpected refusals: {refusals}")

    def test_r1_t_without_preregistered_geometry(self) -> None:
        self.assert_refused(
            {
                "id": "R1",
                "kind": "constant_time",
                "statement": "The operation is constant-time.",
                "evidence": {"kind": "statistical", "t_statistic": 0.4},
                "scope": {"artefact": "release"},
            },
            sce.R1,
        )

    def test_r2_ctgrind_without_identity(self) -> None:
        self.assert_refused(
            {
                "id": "R2",
                "kind": "ctgrind_finding",
                "statement": "Memcheck reported a tainted branch.",
                "evidence": {"kind": "ctgrind", "harness": "ct_bn.c"},
                "scope": {"artefact": "test_binary"},
            },
            sce.R2,
        )

    def _ctgrind_claim(self) -> dict:
        return {
            "id": "R2-IDENTITY",
            "kind": "ctgrind_finding",
            "statement": "Memcheck reported a tainted branch.",
            "evidence": {
                "kind": "ctgrind",
                "harness": "courts/phase18/timing/ct_bn.c",
                "binary_identity": "sha256:" + "ab" * 32,
                "tainted_inputs": ["nonce"],
            },
            "scope": {"artefact": "test_binary"},
        }

    def test_r2_identity_must_equal_the_artefact_under_test(self) -> None:
        refusals = sce.check_claim(
            self._ctgrind_claim(),
            self.secrets,
            self.prereg,
            expected_binary_identity="sha256:" + "cd" * 32,
        )
        self.assertIn(sce.R2_IDENTITY, [item[0] for item in refusals])
        detail = " ".join(item[1] for item in refusals)
        self.assertIn("ab" * 32, detail)
        self.assertIn("cd" * 32, detail)

    def test_r2_identity_matches_the_artefact_under_test(self) -> None:
        claim = self._ctgrind_claim()
        refusals = sce.check_claim(
            claim,
            self.secrets,
            self.prereg,
            expected_binary_identity=claim["evidence"]["binary_identity"],
        )
        self.assertEqual(refusals, [])

    def test_r2_identity_is_not_invented_without_an_expected_value(self) -> None:
        # Presence is still checked; identity needs a caller-supplied value.
        self.assertEqual(
            sce.check_claim(self._ctgrind_claim(), self.secrets, self.prereg), []
        )

    def test_r3_debug_binary_to_release(self) -> None:
        self.assert_refused(
            {
                "id": "R3",
                "kind": "release_claim",
                "statement": "The release artefact is safe.",
                "evidence": {"kind": "source-contract", "reference": "x", "result": "OK"},
                "scope": {
                    "artefact": "debug_test_binary",
                    "target": "release",
                    "generalises_to_release": True,
                },
            },
            sce.R3,
        )

    def test_r4_secret_dependent_control_without_evidence(self) -> None:
        self.assert_refused(
            {
                "id": "R4",
                "kind": "constant_time",
                "statement": "The AES S-box lookup is constant-time.",
                "evidence": {"kind": "source-contract", "reference": "x", "result": "OK"},
                "mechanism_ref": "AES-SBOX",
                "scope": {"artefact": "release"},
            },
            sce.R4,
        )

    def test_r5_exclusions_changed(self) -> None:
        self.assert_refused(
            {
                "id": "R5",
                "kind": "observation",
                "statement": "No leakage evidence at this geometry.",
                "evidence": {
                    "kind": "statistical",
                    "state": 1,
                    "preregistration_id": "ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1",
                    "exclusions": ["EX-1"],
                    "verdict": "ABSENCE_OF_EVIDENCE_AT_GEOMETRY",
                },
                "scope": {"artefact": "release"},
            },
            sce.R5,
        )

    def test_r6_dudect_state_1_as_proof(self) -> None:
        self.assert_refused(
            {
                "id": "R6",
                "kind": "constant_time",
                "statement": "The operation is constant-time.",
                "evidence": {"kind": "dudect", "state": 1, "verdict": "SAFE"},
                "scope": {"artefact": "release"},
            },
            sce.R6,
        )

    def test_positive_controls_accepted(self) -> None:
        self.assert_accepted(
            {
                "id": "P1",
                "kind": "constant_time",
                "statement": "No statistically detectable timing class was observed at this geometry.",
                "evidence": {
                    "kind": "statistical",
                    "t_statistic": 0.4,
                    "preregistration_id": "ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1",
                    "geometry": {"per_batch": 10000, "max_batches": 3},
                    "criterion": {"threshold": 10},
                    "exclusions": ["EX-1", "EX-2", "EX-3", "EX-4", "EX-5"],
                },
                "scope": {"artefact": "release"},
            }
        )
        self.assert_accepted(
            {
                "id": "P2",
                "kind": "ctgrind_finding",
                "statement": "A tainted branch was reported.",
                "evidence": {
                    "kind": "ctgrind",
                    "harness": "courts/phase18/timing/ct_bn.c",
                    "binary_identity": "sha256:abc",
                    "tainted_inputs": ["nonce"],
                },
                "scope": {"artefact": "test_binary"},
            }
        )
        self.assert_accepted(
            {
                "id": "P3",
                "kind": "mechanism_safe",
                "statement": "The ladder has no secret-dependent address.",
                "evidence": {
                    "kind": "ctgrind",
                    "harness": "h",
                    "binary_identity": "b",
                    "tainted_inputs": ["exponent"],
                },
                "mechanism_ref": "LADDER-BIT",
                "scope": {"artefact": "test_binary"},
            }
        )


class RegisterAndAuditControls(unittest.TestCase):
    def setUp(self) -> None:
        self.secrets = load(SECRETS)
        self.erasure = load(ERASURE)
        self.prereg = load(PREREG)

    def test_committed_documents_validate(self) -> None:
        self.assertEqual(sce.validate_secrets(self.secrets, REPO_ROOT), [])
        self.assertEqual(sce.validate_erasure(self.erasure, self.secrets, REPO_ROOT), [])
        self.assertEqual(sce.validate_prereg(self.prereg), [])

    def test_count_mutation_refused(self) -> None:
        document = copy.deepcopy(self.secrets)
        document["counts"]["SECRET_DATA"] += 1
        codes = [code for code, _ in sce.validate_secrets(document, REPO_ROOT)]
        self.assertIn("SE_COUNT_MISMATCH", codes)

    def test_source_token_mutation_refused(self) -> None:
        document = copy.deepcopy(self.secrets)
        document["entries"][0]["source"]["token"] = "not present in the cited window"
        codes = [code for code, _ in sce.validate_secrets(document, REPO_ROOT)]
        self.assertIn("SE_SOURCE_TOKEN", codes)

    def test_uncovered_erasure_obligation_refused(self) -> None:
        document = copy.deepcopy(self.erasure)
        document["findings"] = [item for item in document["findings"] if item["id"] != "ERA-01"]
        codes = [code for code, _ in sce.validate_erasure(document, self.secrets, REPO_ROOT)]
        self.assertIn("ER_UNCOVERED_OBLIGATION", codes)

    def test_repair_claim_refused(self) -> None:
        document = copy.deepcopy(self.erasure)
        document["findings"][0]["repaired"] = True
        codes = [code for code, _ in sce.validate_erasure(document, self.secrets, REPO_ROOT)]
        self.assertIn("ER_BAD_SCHEMA", codes)

    def test_missing_preregistration_field_refused(self) -> None:
        document = copy.deepcopy(self.prereg)
        document["instances"][0].pop("controls")
        codes = [code for code, _ in sce.validate_prereg(document)]
        self.assertIn("PR_MISSING_FIELD", codes)

    def test_bad_geometry_refused(self) -> None:
        document = copy.deepcopy(self.prereg)
        document["instances"][0]["geometry"]["max_batches"] = 0
        codes = [code for code, _ in sce.validate_prereg(document)]
        self.assertIn("PR_BAD_GEOMETRY", codes)


class PreregistrationControls(unittest.TestCase):
    def test_prospective_receipt_matches(self) -> None:
        self.assertEqual(
            pc.check(PREREG, PROSPECTIVE, "ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1"), []
        )

    def test_reconstructed_receipt_matches(self) -> None:
        self.assertEqual(
            pc.check(PREREG, LEGACY, "ETP-T7-DUDECT-LEGACY-RECONSTRUCTED"), []
        )

    def test_changed_geometry_refused(self) -> None:
        document = load(PROSPECTIVE)
        document["modes"]["cmpcmp"]["total_measurements"] = 40000
        document["modes"]["cmpcmp"]["batches_run"] = 4
        with tempfile.TemporaryDirectory(prefix="etp-t7-test-") as tmp:
            path = Path(tmp) / "receipt.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            codes = [code for code, _ in pc.check(PREREG, path, "ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1")]
        self.assertIn("PR_BATCH_BUDGET", codes)

    def test_changed_artefact_refused(self) -> None:
        document = load(PROSPECTIVE)
        document["candidate"]["libcrypto_sha256"] = "f" * 64
        with tempfile.TemporaryDirectory(prefix="etp-t7-test-") as tmp:
            path = Path(tmp) / "receipt.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            codes = [code for code, _ in pc.check(PREREG, path, "ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1")]
        self.assertIn("PR_CANDIDATE_MISMATCH", codes)

    def test_changed_preregistration_digest_refused(self) -> None:
        document = load(PROSPECTIVE)
        document["preregistration_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory(prefix="etp-t7-test-") as tmp:
            path = Path(tmp) / "receipt.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            codes = [code for code, _ in pc.check(PREREG, path, "ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1")]
        self.assertIn("PR_PREREG_DIGEST_MISMATCH", codes)


class CommandLine(unittest.TestCase):
    def run_cmd(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, *args],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=300,
        )

    def test_validate_command(self) -> None:
        result = self.run_cmd(str(VALIDATOR), "validate", "--repo-root", str(REPO_ROOT))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"ok": true', result.stdout)

    def test_validator_self_test(self) -> None:
        result = self.run_cmd(str(VALIDATOR), "--self-test", "--repo-root", str(REPO_ROOT))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SELF-TEST PASS", result.stdout)

    def test_checker_self_test(self) -> None:
        result = self.run_cmd(str(CHECKER), "--self-test", "--repo-root", str(REPO_ROOT))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SELF-TEST PASS", result.stdout)

    def test_identity_mismatch_is_refused_by_the_cli(self) -> None:
        claim = {
            "id": "CLI-1",
            "kind": "ctgrind_finding",
            "statement": "Memcheck reported a tainted branch.",
            "evidence": {
                "kind": "ctgrind",
                "harness": "courts/phase18/timing/ct_bn.c",
                "binary_identity": "sha256:" + "ab" * 32,
                "tainted_inputs": ["nonce"],
            },
            "scope": {"artefact": "test_binary"},
        }
        with tempfile.TemporaryDirectory(prefix="etp-t7-cli-") as tmp:
            path = Path(tmp) / "claims.json"
            path.write_text(json.dumps({"claims": [claim]}), encoding="utf-8")
            result = self.run_cmd(
                str(VALIDATOR),
                "check-claims",
                "--repo-root",
                str(REPO_ROOT),
                "--claims",
                str(path),
                "--binary-identity",
                "sha256:" + "cd" * 32,
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(sce.R2_IDENTITY, result.stderr)

    def test_artefact_option_derives_the_expected_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="etp-t7-cli-") as tmp:
            artefact_path = Path(tmp) / "candidate.bin"
            artefact_path.write_bytes(b"a candidate binary")
            digest = "sha256:" + hashlib.sha256("a candidate binary".encode("utf-8")).hexdigest()
            claim = {
                "id": "CLI-2",
                "kind": "ctgrind_finding",
                "statement": "Memcheck reported a tainted branch.",
                "evidence": {
                    "kind": "ctgrind",
                    "harness": "courts/phase18/timing/ct_bn.c",
                    "binary_identity": digest,
                    "tainted_inputs": ["nonce"],
                },
                "scope": {"artefact": "test_binary"},
            }
            path = Path(tmp) / "claims.json"
            path.write_text(json.dumps({"claims": [claim]}), encoding="utf-8")
            result = self.run_cmd(
                str(VALIDATOR),
                "check-claims",
                "--repo-root",
                str(REPO_ROOT),
                "--claims",
                str(path),
                "--artefact",
                str(artefact_path),
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CLAIMS ok", result.stdout)


class TrackedFileStyle(unittest.TestCase):
    def test_no_first_person_in_new_deliverables(self) -> None:
        paths = [
            REPO_ROOT / "docs/SIDE-CHANNEL-AND-ERASURE.md",
            SECRETS,
            ERASURE,
            PREREG,
            PROSPECTIVE,
            REPO_ROOT / "evidence/etp-t7/RECEIPT.md",
            VALIDATOR,
            CHECKER,
        ]
        import re

        # `-I` is a compiler flag, not a pronoun.
        forbidden = [re.compile(r"(?<![-\w])I(?![\w-])"), re.compile(r"\bwe\b"),
                     re.compile(r"\bWe\b"), re.compile(r"\bmy\b"), re.compile(r"\bMy\b"),
                     re.compile(r"\bours\b")]
        for path in paths:
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            for pattern in forbidden:
                self.assertIsNone(pattern.search(text), f"{path} contains {pattern.pattern}")


if __name__ == "__main__":
    unittest.main()
