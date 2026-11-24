#!/usr/bin/env python3
"""Controls for A12: independent verification, and the trust root outside the candidate.

Each control exercises one rule of `docs/INDEPENDENT-VERIFICATION.md`.  A control
proves that a refusal fires for the substituted form; it does not prove that the
form occurs anywhere in the tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(REPO_ROOT / "evidence" / "a12"))

import build_evidence as be  # noqa: E402
import dsse as d  # noqa: E402
import independent_verify as iv  # noqa: E402

A12 = REPO_ROOT / "evidence" / "a12"
INVENTORY = A12 / "TRUST-ROOTS.json"
VERIFICATION = A12 / "VERIFICATION.json"
CONTROLS = A12 / "CONTROLS.json"
PRODUCER = A12 / "build_evidence.py"
TOOL = TOOLS / "independent_verify.py"
DOCUMENT = REPO_ROOT / "docs" / "INDEPENDENT-VERIFICATION.md"

BASE_COMMIT = "1d571da35"
_UNSET = object()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _real_policy() -> tuple[dict, dict]:
    document = iv.load_inventory(INVENTORY)
    return document, iv.policy_from_inventory(document, INVENTORY)


def _real_verifier(keyid: str, pae: bytes, signature: bytes, material: object) -> bool:
    return d.test_only_verifier()(keyid, pae, signature)


def _fixture_result(
    root_update: dict | None = None,
    policy_update: dict | None = None,
    *,
    verifier: object = _UNSET,
    envelope: bytes | None = None,
    artefact: str | None = None,
    artefact_bytes: bytes | None = b"control artefact\n",
    artefact_present: bool = True,
) -> dict:
    base = Path(tempfile.mkdtemp(prefix="a12-test-"))
    try:
        fixture = be.Fixture(
            base,
            artefact_bytes=artefact_bytes,
            artefact_present=artefact_present,
        )
        root = dict(fixture.root)
        root.update(root_update or {})
        policy = dict(fixture.policy)
        policy.update(policy_update or {})
        policy["trustRoots"] = {
            "schema": iv.INVENTORY_SCHEMA,
            "roots": [root],
        }
        if artefact is not None:
            policy["artefact"] = artefact
        chosen = fixture.check if verifier is _UNSET else verifier
        raw = fixture.envelope if envelope is None else envelope
        return iv.verify(raw, policy, chosen)
    finally:
        shutil.rmtree(base, ignore_errors=True)


class RealEnvelopes(unittest.TestCase):
    def test_the_four_real_envelopes_are_self_issued_and_never_independently_verified(self) -> None:
        _document, policy = _real_policy()
        for name, envelope_path, _statement, artefact_path in be.ENVELOPES:
            with self.subTest(name=name):
                raw = (REPO_ROOT / envelope_path).read_bytes()
                result = iv.verify(
                    raw,
                    {**policy, "artefact": artefact_path},
                    _real_verifier,
                )
                self.assertEqual(result["outcome"], iv.OUTCOME_SELF_ISSUED)
                self.assertFalse(result["independentlyVerified"])
                for code in (
                    iv.IV_REFUSED_SYMMETRIC,
                    iv.IV_REFUSED_CANDIDATE_TRUST_ROOT,
                    iv.IV_REFUSED_SELF_ISSUED,
                ):
                    self.assertIn(code, result["codes"])

    def test_the_aggregate_is_zero_independently_verified(self) -> None:
        document = _load(VERIFICATION)
        self.assertEqual(document["independentlyVerified"], 0)
        self.assertEqual(document["counts"][iv.OUTCOME_SELF_ISSUED], 4)
        self.assertEqual(document["counts"][iv.OUTCOME_UNVERIFIED], 0)
        self.assertEqual(document["counts"][iv.OUTCOME_NOT_RUN], 0)
        for row in document["verifications"]:
            with self.subTest(name=row["name"]):
                self.assertFalse(row["independentlyVerified"])
                self.assertEqual(row["outcome"], iv.OUTCOME_SELF_ISSUED)

    def test_the_inventory_records_no_external_root_explicitly(self) -> None:
        document = _load(INVENTORY)
        self.assertEqual(document["externalRoots"], [])
        self.assertIn("no external root", document["externalRootsNote"].lower())
        self.assertEqual(document["counts"]["externalRoots"], 0)
        self.assertEqual(document["counts"]["symmetricRoots"], 1)
        root = document["roots"][0]
        self.assertTrue(root["symmetric"])
        self.assertEqual(root["trustDomain"], "same-party")


class OutcomeStates(unittest.TestCase):
    def test_outcome_states_are_distinct(self) -> None:
        states = {
            iv.OUTCOME_VERIFIED,
            iv.OUTCOME_SELF_ISSUED,
            iv.OUTCOME_UNVERIFIED,
            iv.OUTCOME_NOT_RUN,
        }
        self.assertEqual(len(states), 4)
        self.assertNotEqual(iv.OUTCOME_SELF_ISSUED, iv.OUTCOME_VERIFIED)
        self.assertNotEqual(iv.OUTCOME_SELF_ISSUED, iv.OUTCOME_NOT_RUN)


class RefusalCodes(unittest.TestCase):
    def test_controls_cover_every_code_and_fire(self) -> None:
        produced = be.controls_document()
        codes = [control["code"] for control in produced["controls"]]
        self.assertEqual(sorted(codes), sorted(iv.REFUSALS))
        self.assertEqual(len(codes), len(set(codes)))
        self.assertEqual(produced["codes"], len(iv.REFUSALS))
        self.assertEqual(produced["controlCount"], len(iv.REFUSALS))
        for control in produced["controls"]:
            with self.subTest(control=control["control"]):
                self.assertIn(control["code"], control["codes"])

    def test_envelope_invalid(self) -> None:
        result = _fixture_result(envelope=b"not-json", verifier=None)
        self.assertIn(iv.IV_REFUSED_ENVELOPE, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_UNVERIFIED)

    def test_unrecorded_root(self) -> None:
        result = _fixture_result(
            policy_update={"keyid": "external:not-recorded"}, verifier=None
        )
        self.assertIn(iv.IV_REFUSED_TRUST_ROOT_UNRECORDED, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_UNVERIFIED)

    def test_digest_mismatch(self) -> None:
        result = _fixture_result(
            root_update={"provenance": {
                "path": str(REPO_ROOT / "evidence" / "a10" / "ENVELOPES.json"),
                "sha256": "0" * 64,
            }},
            policy_update={"candidateRoot": str(REPO_ROOT / "forensics")},
            verifier=None,
        )
        self.assertIn(iv.IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_UNVERIFIED)

    def test_stale_root(self) -> None:
        result = _fixture_result(
            root_update={"recordedAt": "2020-01-01"},
            policy_update={"asOf": "2026-11-24", "maxRootAgeDays": 1},
            verifier=None,
        )
        self.assertIn(iv.IV_REFUSED_TRUST_ROOT_STALE, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_UNVERIFIED)

    def test_signature_invalid(self) -> None:
        result = _fixture_result(
            verifier=lambda keyid, pae, signature, material: False
        )
        self.assertIn(iv.IV_REFUSED_SIGNATURE, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_UNVERIFIED)


class IndependenceRefusals(unittest.TestCase):
    def test_the_envelope_keyid_cannot_select_a_root(self) -> None:
        result = _fixture_result(policy_update={"keyid": None}, verifier=None)
        self.assertIn(iv.IV_REFUSED_KEY_FROM_ENVELOPE, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_UNVERIFIED)
        self.assertEqual(result["keyid"]["selectedBy"], "policy")
        self.assertEqual(result["keyid"]["envelopeKeyids"], [be.STUB_KEYID])

    def test_a_different_policy_keyid_does_not_fall_back_to_the_envelope(self) -> None:
        result = _fixture_result(
            policy_update={"keyid": "external:elsewhere"}, verifier=None
        )
        self.assertIn(iv.IV_REFUSED_TRUST_ROOT_UNRECORDED, result["codes"])
        self.assertNotEqual(result["outcome"], iv.OUTCOME_VERIFIED)

    def test_hmac_is_refused_for_independence(self) -> None:
        result = _fixture_result(
            root_update={
                "symmetric": True,
                "publicMaterial": None,
                "algorithm": "hmac-sha256",
            },
            verifier=None,
        )
        self.assertIn(iv.IV_REFUSED_SYMMETRIC, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_SELF_ISSUED)
        self.assertFalse(result["independentlyVerified"])

    def test_a_candidate_tree_root_is_refused(self) -> None:
        provenance = REPO_ROOT / "evidence" / "a10" / "ENVELOPES.json"
        result = _fixture_result(
            root_update={"provenance": {
                "path": str(provenance),
                "sha256": iv.sha256_bytes(provenance.read_bytes()),
            }},
            policy_update={"candidateRoot": str(REPO_ROOT)},
            verifier=None,
        )
        self.assertIn(iv.IV_REFUSED_CANDIDATE_TRUST_ROOT, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_SELF_ISSUED)

    def test_the_inventory_inside_the_candidate_evidence_is_refused(self) -> None:
        base = Path(tempfile.mkdtemp(prefix="a12-test-"))
        try:
            fixture = be.Fixture(base, artefact_bytes=b"control artefact\n")
            evidence = fixture.candidate / "evidence"
            evidence.mkdir(parents=True, exist_ok=True)
            policy = dict(fixture.policy)
            policy["trustRootsPath"] = str(evidence / "TRUST-ROOTS.json")
            policy["candidateEvidenceRoot"] = str(evidence)
            result = iv.verify(fixture.envelope, policy, None)
        finally:
            shutil.rmtree(base, ignore_errors=True)
        self.assertIn(iv.IV_REFUSED_CANDIDATE_TRUST_ROOT, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_SELF_ISSUED)

    def test_a_same_domain_root_is_refused(self) -> None:
        result = _fixture_result(
            root_update={"trustDomain": "candidate-producer"}, verifier=None
        )
        self.assertIn(iv.IV_REFUSED_SAME_DOMAIN, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_SELF_ISSUED)

    def test_a_self_issued_basis_is_refused(self) -> None:
        result = _fixture_result(
            root_update={"selfIssued": True}, verifier=None
        )
        self.assertIn(iv.IV_REFUSED_SELF_ISSUED, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_SELF_ISSUED)

    def test_multiple_roots_claiming_one_keyid_are_refused(self) -> None:
        base = Path(tempfile.mkdtemp(prefix="a12-test-"))
        try:
            fixture = be.Fixture(base, artefact_bytes=b"control artefact\n")
            policy = dict(fixture.policy)
            policy["trustRoots"] = {
                "schema": iv.INVENTORY_SCHEMA,
                "roots": [fixture.root, dict(fixture.root)],
            }
            result = iv.verify(fixture.envelope, policy, None)
        finally:
            shutil.rmtree(base, ignore_errors=True)
        self.assertIn(iv.IV_REFUSED_MULTIPLE_ROOTS, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_UNVERIFIED)


class PublicVerifierBoundary(unittest.TestCase):
    def test_no_public_verifier_is_not_run_and_never_pass(self) -> None:
        result = _fixture_result(verifier=None)
        self.assertEqual(result["outcome"], iv.OUTCOME_NOT_RUN)
        self.assertIn(iv.IV_REFUSED_NO_PUBLIC_VERIFIER, result["codes"])
        self.assertFalse(result["independentlyVerified"])

    def test_the_stub_verifier_positive_control_is_control_only(self) -> None:
        produced = be.controls_document()["positiveControl"]
        self.assertEqual(produced["label"], "control-only")
        self.assertEqual(produced["outcome"], iv.OUTCOME_VERIFIED)
        self.assertTrue(produced["independentlyVerified"])
        self.assertEqual(produced["codes"], [])
        self.assertIn(
            "a real independent party: the verifier is a test stub",
            produced["doesNotEstablish"],
        )

    def test_a_stub_verifier_reaches_independently_verified_only_for_its_key(self) -> None:
        result = _fixture_result(artefact_bytes=None)
        self.assertEqual(result["outcome"], iv.OUTCOME_VERIFIED)
        self.assertTrue(result["independentlyVerified"])
        self.assertEqual(result["codes"], [])


class SubjectRehashing(unittest.TestCase):
    def test_a_different_artefact_digest_is_refused(self) -> None:
        result = _fixture_result(artefact_bytes=b"different artefact bytes\n")
        self.assertIn(iv.IV_REFUSED_PAYLOAD_NOT_SUBJECT, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_UNVERIFIED)
        self.assertNotEqual(
            result["artefact"]["sha256"], result["artefact"]["declaredSha256"]
        )

    def test_an_absent_artefact_is_refused(self) -> None:
        result = _fixture_result(artefact_present=False)
        self.assertIn(iv.IV_REFUSED_SUBJECT_ABSENT, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_UNVERIFIED)
        self.assertFalse(result["artefact"]["present"])

    def test_a_statement_naming_another_artefact_is_refused(self) -> None:
        result = _fixture_result(artefact="evidence/a5/ADMISSION.json")
        self.assertIn(iv.IV_REFUSED_SUBJECT_MISMATCH, result["codes"])
        self.assertEqual(result["outcome"], iv.OUTCOME_UNVERIFIED)

    def test_subject_rehashing_is_not_skipped(self) -> None:
        result = _fixture_result(artefact_bytes=None)
        self.assertEqual(result["outcome"], iv.OUTCOME_VERIFIED)
        self.assertEqual(
            result["artefact"]["sha256"], result["artefact"]["declaredSha256"]
        )


class CommandLine(unittest.TestCase):
    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )

    def test_roots_exits_zero_and_prints_the_code(self) -> None:
        result = self._run("roots")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(iv.CODE_OK, result.stdout)
        self.assertIn("externalRoots=0", result.stdout)
        self.assertIn("symmetricRoots=1", result.stdout)

    def test_verify_prints_the_outcome_and_exits_one(self) -> None:
        result = self._run(
            "verify",
            str(REPO_ROOT / "evidence" / "a10" / "ENVELOPES" / "a1-sarif.json"),
            "evidence/a1/SARIF.json",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(iv.OUTCOME_SELF_ISSUED, result.stdout)
        self.assertIn(iv.IV_REFUSED_SYMMETRIC, result.stdout)
        self.assertIn("independentlyVerified=false", result.stdout)

    def test_verify_missing_envelope_exits_one_with_envelope_code(self) -> None:
        result = self._run("verify", "evidence/a10/ENVELOPES/absent.json", "x")
        self.assertEqual(result.returncode, 1)
        self.assertIn(iv.IV_REFUSED_ENVELOPE, result.stderr)

    def test_qualify_reports_zero_external_roots(self) -> None:
        result = self._run("qualify")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(iv.CODE_OK, result.stdout)
        self.assertIn("externalRoots=0", result.stdout)
        self.assertIn(iv.OUTCOME_NOT_RUN, result.stdout)

    def test_usage_errors_exit_two_and_print_a_code(self) -> None:
        for arguments in ((), ("not-a-command",)):
            with self.subTest(arguments=arguments):
                result = self._run(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn(iv.CODE_USAGE, result.stderr)


class Determinism(unittest.TestCase):
    def test_the_producer_is_deterministic_and_matches_the_committed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for output in (first, second):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(PRODUCER),
                        "--out",
                        output,
                        "--source-commit",
                        BASE_COMMIT,
                    ],
                    capture_output=True,
                    text=True,
                    cwd=REPO_ROOT,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("TRUST-ROOTS.json", "VERIFICATION.json", "CONTROLS.json"):
                with self.subTest(name=name):
                    committed = (A12 / name).read_bytes()
                    self.assertEqual((Path(first) / name).read_bytes(), committed)
                    self.assertEqual((Path(second) / name).read_bytes(), committed)

    def test_the_source_identity_is_supplied_not_read_live(self) -> None:
        for name in ("TRUST-ROOTS.json", "VERIFICATION.json", "CONTROLS.json"):
            document = _load(A12 / name)
            with self.subTest(name=name):
                if "sourceIdentity" in document:
                    self.assertEqual(
                        document["sourceIdentity"]["baseCommit"], BASE_COMMIT
                    )
        verification = _load(VERIFICATION)
        tool = verification["sourceIdentity"]["tool"]
        self.assertEqual(tool["path"], "forensics/tools/independent_verify.py")
        self.assertEqual(
            tool["sha256"],
            iv.sha256_bytes((REPO_ROOT / tool["path"]).read_bytes()),
        )


class DocumentSynchronisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8") if DOCUMENT.is_file() else ""

    def test_the_document_names_every_refusal_code(self) -> None:
        for code in iv.REFUSALS:
            with self.subTest(code=code):
                self.assertIn(f"`{code}`", self.text)

    def test_the_document_names_every_control(self) -> None:
        for control in _load(CONTROLS)["controls"]:
            with self.subTest(control=control["control"]):
                self.assertIn(control["control"], self.text)
        self.assertIn(_load(CONTROLS)["positiveControl"]["control"], self.text)

    def test_the_document_names_the_implementation_tests_and_evidence(self) -> None:
        for token in (
            iv.TOOL_PATH,
            "forensics/tools/tests/test_independent_verify.py",
            "evidence/a12/TRUST-ROOTS.json",
            "evidence/a12/VERIFICATION.json",
            "evidence/a12/CONTROLS.json",
            "evidence/a12/build_evidence.py",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.text)

    def test_the_document_states_the_outcomes_and_the_real_result(self) -> None:
        for token in (
            iv.OUTCOME_VERIFIED,
            iv.OUTCOME_SELF_ISSUED,
            iv.OUTCOME_UNVERIFIED,
            iv.OUTCOME_NOT_RUN,
            "0 independently verified",
            "4 self-issued",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.text)

    def test_the_document_states_the_boundary(self) -> None:
        for token in ("A14", "A15", "A16", "A17"):
            with self.subTest(token=token):
                self.assertIn(token, self.text)
        lowered = self.text.lower()
        for phrase in ("role", "threshold", "sigstore", "transparency"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, lowered)

    def test_the_document_declares_not_run(self) -> None:
        self.assertIn("`NOT_RUN`", self.text)
        self.assertIn("NOT_RUN", self.text)
        self.assertIn("no external", self.text.lower())


if __name__ == "__main__":
    unittest.main()
