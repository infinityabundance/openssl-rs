#!/usr/bin/env python3
"""Controls for A13: signature reproducibility versus artefact reproducibility.

Each control exercises one rule of `docs/REPRODUCIBILITY-AXES.md`.  A control
proves that a refusal fires for the substituted form; it does not prove that the
form occurs anywhere in the tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

A13 = REPO_ROOT / "evidence" / "a13"
SIGNATURE = A13 / "SIGNATURE.json"
ARTEFACT = A13 / "ARTEFACT.json"
CLASSIFICATION = A13 / "CLASSIFICATION.json"
CONTROLS = A13 / "CONTROLS.json"
PRODUCER = A13 / "build_evidence.py"
TOOL = TOOLS / "reproducibility.py"
DOCUMENT = REPO_ROOT / "docs" / "REPRODUCIBILITY-AXES.md"

def _load_producer():
    """Load the A13 producer under a private name.

    Several items name their producer ``build_evidence``.  Importing it by that
    name would collide with the copy another test file has already cached in
    ``sys.modules``; discovery order would then decide which item's producer this
    module sees.
    """
    spec = importlib.util.spec_from_file_location("a13_build_evidence", PRODUCER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


import dsse as d  # noqa: E402
import reproducibility as r  # noqa: E402

be = _load_producer()

BASE_COMMIT = "6b33f1caa"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _attempt(
    signature: bytes,
    *,
    inputs: dict | None = None,
    nonce: object = None,
    key_kind: str = "derived-key",
    scheme: str = "ed25519",
) -> dict:
    record = {
        "scheme": scheme,
        "signature": base64.b64encode(signature).decode("ascii"),
        "inputs": inputs or {"keyid": "control", "payloadSha256": "00" * 32},
        "keyKind": key_kind,
    }
    if nonce is not None:
        record["nonce"] = nonce
    return record


def _subject(kind: str = "build-product") -> dict:
    return {
        "name": "control-artefact",
        "path": "control/artefact",
        "kind": kind,
        "sha256": "a" * 64,
    }


def _completed_rebuild(
    *,
    first: str = "b" * 64,
    second: str = "b" * 64,
    subject_sha: str = "a" * 64,
    outcome: str = "REPRODUCED",
    method: str = "rebuild",
    inputs: dict | None = None,
) -> dict:
    return {
        "method": method,
        "outcome": outcome,
        "inputs": inputs if inputs is not None else {"control": "two builds"},
        "digests": {"first": first, "second": second},
        "subjectSha256": subject_sha,
    }


class SchemeRegistry(unittest.TestCase):
    def test_the_scheme_registry_declares_the_four_classes(self) -> None:
        self.assertEqual(
            sorted(r.SCHEMES),
            ["ecdsa", "ed25519", "hmac-sha256", "rsa-pkcs1v15"],
        )
        self.assertTrue(r.SCHEMES["hmac-sha256"].deterministic)
        self.assertTrue(r.SCHEMES["hmac-sha256"].symmetric)
        self.assertTrue(r.SCHEMES["rsa-pkcs1v15"].deterministic)
        self.assertFalse(r.SCHEMES["rsa-pkcs1v15"].symmetric)
        self.assertTrue(r.SCHEMES["ed25519"].deterministic)
        self.assertFalse(r.SCHEMES["ed25519"].symmetric)
        self.assertFalse(r.SCHEMES["ecdsa"].deterministic)
        self.assertTrue(r.SCHEMES["ecdsa"].randomised)
        for name in ("hmac-sha256", "rsa-pkcs1v15", "ed25519"):
            self.assertEqual(r.SCHEMES[name].repeat, "byte-equality")
        self.assertEqual(
            r.SCHEMES["ecdsa"].repeat, "non-equality-and-nonce-reuse-check"
        )

    def test_a_deterministic_scheme_is_compared_by_byte_equality(self) -> None:
        stable = r.signature_evidence(
            [_attempt(b"same"), _attempt(b"same")], "rsa-pkcs1v15"
        )
        self.assertEqual(stable["state"], r.SIGNATURE_STABLE)
        self.assertEqual(stable["code"], r.CODE_OK)
        different = r.signature_evidence(
            [_attempt(b"one"), _attempt(b"two")], "rsa-pkcs1v15"
        )
        self.assertEqual(different["state"], r.SIGNATURE_VARIES)
        self.assertEqual(different["code"], r.SR_REFUSED_DETERMINISTIC_VARIED)

    def test_a_deterministic_scheme_that_varies_is_refused(self) -> None:
        result = r.signature_evidence(
            [_attempt(b"one"), _attempt(b"two")], "ed25519"
        )
        self.assertEqual(result["code"], r.SR_REFUSED_DETERMINISTIC_VARIED)
        self.assertIn(r.SR_REFUSED_DETERMINISTIC_VARIED, result["refusals"])

    def test_a_randomised_scheme_varies_and_is_not_a_failure(self) -> None:
        result = r.signature_evidence(
            [
                _attempt(b"one", nonce="n1", scheme="ecdsa"),
                _attempt(b"two", nonce="n2", scheme="ecdsa"),
            ],
            "ecdsa",
        )
        self.assertEqual(result["state"], r.SIGNATURE_VARIES)
        self.assertEqual(result["code"], r.CODE_OK)
        self.assertEqual(result["refusals"], [])
        self.assertFalse(result["nonceReused"])

    def test_a_randomised_scheme_that_repeats_is_refused(self) -> None:
        result = r.signature_evidence(
            [
                _attempt(b"same", nonce="n1", scheme="ecdsa"),
                _attempt(b"same", nonce="n1", scheme="ecdsa"),
            ],
            "ecdsa",
        )
        self.assertEqual(result["state"], r.SIGNATURE_NONCE_REUSED)
        self.assertEqual(result["code"], r.SR_REFUSED_NONCE_REUSE)
        self.assertTrue(result["nonceReused"])

    def test_a_repeated_nonce_with_distinct_signatures_is_refused(self) -> None:
        result = r.signature_evidence(
            [
                _attempt(b"one", nonce="reused", scheme="ecdsa"),
                _attempt(b"two", nonce="reused", scheme="ecdsa"),
            ],
            "ecdsa",
        )
        self.assertEqual(result["state"], r.SIGNATURE_NONCE_REUSED)
        self.assertEqual(result["code"], r.SR_REFUSED_NONCE_REUSE)

    def test_fewer_than_two_attempts_is_unknown(self) -> None:
        result = r.signature_evidence([_attempt(b"one")], "ed25519")
        self.assertEqual(result["state"], r.SIGNATURE_UNKNOWN)
        self.assertEqual(result["code"], r.SR_REFUSED_ATTEMPTS_INSUFFICIENT)

    def test_an_unrecorded_scheme_is_unknown(self) -> None:
        result = r.signature_evidence(
            [_attempt(b"one"), _attempt(b"one")], "rsa-pss"
        )
        self.assertEqual(result["state"], r.SIGNATURE_UNKNOWN)
        self.assertEqual(result["code"], r.SR_REFUSED_SCHEME_UNRECORDED)

    def test_a_raw_seed_as_key_is_refused(self) -> None:
        result = r.signature_evidence(
            [
                _attempt(b"one", key_kind="seed"),
                _attempt(b"one", key_kind="seed"),
            ],
            "ed25519",
        )
        self.assertEqual(result["state"], r.SIGNATURE_UNKNOWN)
        self.assertEqual(result["code"], r.SR_REFUSED_SEED_AS_KEY)

    def test_different_inputs_are_refused(self) -> None:
        result = r.signature_evidence(
            [
                _attempt(b"one", inputs={"payloadSha256": "00" * 32}),
                _attempt(b"one", inputs={"payloadSha256": "11" * 32}),
            ],
            "ed25519",
        )
        self.assertEqual(result["state"], r.SIGNATURE_UNKNOWN)
        self.assertEqual(result["code"], r.SR_REFUSED_INPUTS_UNSTATED)

    def test_an_attempt_without_a_signature_is_malformed(self) -> None:
        result = r.signature_evidence(
            [{"inputs": {"keyid": "control"}}, _attempt(b"one")], "ed25519"
        )
        self.assertEqual(result["state"], r.SIGNATURE_UNKNOWN)
        self.assertEqual(result["code"], r.SR_REFUSED_ATTEMPT_MALFORMED)


class ArtefactAxis(unittest.TestCase):
    def test_an_absent_rebuild_is_not_rebuilt(self) -> None:
        result = r.artefact_evidence(_subject(), None)
        self.assertEqual(result["state"], r.ARTEFACT_NOT_REBUILT)
        self.assertEqual(result["code"], r.SR_REFUSED_REBUILD_NOT_RUN)
        self.assertFalse(result["reproducibilityClaimed"])

    def test_a_recorded_not_run_rebuild_is_not_rebuilt(self) -> None:
        result = r.artefact_evidence(
            _subject(),
            {
                "method": "rebuild",
                "outcome": "NOT_RUN",
                "inputs": {"candidateCommit": "x"},
                "reason": "the court is capped at 6 GiB and the script exited 101",
            },
        )
        self.assertEqual(result["state"], r.ARTEFACT_NOT_REBUILT)
        self.assertEqual(result["code"], r.SR_REFUSED_REBUILD_NOT_RUN)

    def test_a_replay_is_not_a_rebuild(self) -> None:
        result = r.artefact_evidence(
            _subject(), _completed_rebuild(method="replay")
        )
        self.assertEqual(result["state"], r.ARTEFACT_NOT_REBUILT)
        self.assertEqual(result["code"], r.SR_REFUSED_REPLAY_AS_REPRODUCTION)

    def test_an_envelope_digest_is_not_a_build_digest(self) -> None:
        result = r.artefact_evidence(_subject("envelope"), None)
        self.assertEqual(result["state"], r.ARTEFACT_UNKNOWN)
        self.assertEqual(
            result["code"], r.SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST
        )

    def test_a_synthetic_reproducible_rebuild_reaches_reproducible(self) -> None:
        result = r.artefact_evidence(_subject(), _completed_rebuild())
        self.assertEqual(result["state"], r.ARTEFACT_REPRODUCIBLE)
        self.assertEqual(result["code"], r.CODE_OK)
        self.assertTrue(result["reproducibilityClaimed"])

    def test_a_differing_rebuild_reaches_differs(self) -> None:
        result = r.artefact_evidence(
            _subject(),
            _completed_rebuild(first="b" * 64, second="c" * 64, outcome="DIFFERS"),
        )
        self.assertEqual(result["state"], r.ARTEFACT_DIFFERS)
        self.assertEqual(result["code"], r.CODE_OK)
        self.assertFalse(result["reproducibilityClaimed"])

    def test_a_reproduced_build_of_another_subject_differs(self) -> None:
        result = r.artefact_evidence(
            _subject(),
            _completed_rebuild(subject_sha="c" * 64),
        )
        self.assertEqual(result["state"], r.ARTEFACT_DIFFERS)

    def test_missing_inputs_are_unknown(self) -> None:
        result = r.artefact_evidence(
            _subject(),
            {
                "method": "rebuild",
                "outcome": "REPRODUCED",
                "inputs": {},
                "digests": {"first": "b" * 64, "second": "b" * 64},
                "subjectSha256": "a" * 64,
            },
        )
        self.assertEqual(result["state"], r.ARTEFACT_UNKNOWN)
        self.assertEqual(result["code"], r.SR_REFUSED_INPUTS_UNSTATED)

    def test_a_stable_digest_is_not_reproducibility(self) -> None:
        subject = _subject()
        result = r.artefact_evidence(subject, None)
        self.assertEqual(subject["sha256"], "a" * 64)
        self.assertEqual(result["state"], r.ARTEFACT_NOT_REBUILT)
        self.assertFalse(result["reproducibilityClaimed"])


class Classification(unittest.TestCase):
    def setUp(self) -> None:
        self.stable = r.signature_evidence(
            [_attempt(b"same"), _attempt(b"same")], "ed25519"
        )
        self.varying = r.signature_evidence(
            [
                _attempt(b"one", nonce="n1", scheme="ecdsa"),
                _attempt(b"two", nonce="n2", scheme="ecdsa"),
            ],
            "ecdsa",
        )
        self.reproducible = r.artefact_evidence(_subject(), _completed_rebuild())
        self.not_rebuilt = r.artefact_evidence(_subject(), None)

    def test_all_four_combinations_are_named(self) -> None:
        pairs = {
            (r.SIGNATURE_STABLE, r.ARTEFACT_REPRODUCIBLE):
                "STABLE_SIGNATURE__REPRODUCIBLE_ARTEFACT",
            (r.SIGNATURE_STABLE, r.ARTEFACT_NOT_REBUILT):
                "STABLE_SIGNATURE__NOT_REBUILT_ARTEFACT",
            (r.SIGNATURE_VARIES, r.ARTEFACT_REPRODUCIBLE):
                "VARYING_SIGNATURE__REPRODUCIBLE_ARTEFACT",
            (r.SIGNATURE_VARIES, r.ARTEFACT_NOT_REBUILT):
                "VARYING_SIGNATURE__NOT_REBUILT_ARTEFACT",
        }
        self.assertEqual(r.COMBINATION_LABELS, pairs)
        observed = {
            r.classify(self.stable, self.reproducible)["combination"],
            r.classify(self.stable, self.not_rebuilt)["combination"],
            r.classify(self.varying, self.reproducible)["combination"],
            r.classify(self.varying, self.not_rebuilt)["combination"],
        }
        self.assertEqual(observed, set(pairs.values()))

    def test_each_combination_names_its_prohibited_inference(self) -> None:
        stable_reproducible = r.classify(self.stable, self.reproducible)
        stable_not_rebuilt = r.classify(self.stable, self.not_rebuilt)
        varying_reproducible = r.classify(self.varying, self.reproducible)
        varying_not_rebuilt = r.classify(self.varying, self.not_rebuilt)
        self.assertIn(
            r.SR_REFUSED_SIGNATURE_AS_ARTEFACT, stable_reproducible["prohibited"]
        )
        self.assertIn(
            r.SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE,
            stable_reproducible["prohibited"],
        )
        self.assertIn(
            r.SR_REFUSED_REBUILD_NOT_RUN, stable_not_rebuilt["prohibited"]
        )
        self.assertIn(
            r.SR_REFUSED_ARTEFACT_AS_SIGNATURE,
            varying_reproducible["prohibited"],
        )
        self.assertIn(
            r.SR_REFUSED_NONDETERMINISTIC_AS_FAILURE,
            varying_reproducible["prohibited"],
        )
        self.assertIn(
            r.SR_REFUSED_REBUILD_NOT_RUN, varying_not_rebuilt["prohibited"]
        )

    def test_a_reproducible_artefact_does_not_make_a_randomised_signer_deterministic(self) -> None:
        result = r.classify(self.varying, self.reproducible)
        self.assertEqual(result["signature"], r.SIGNATURE_VARIES)
        self.assertEqual(result["artefact"], r.ARTEFACT_REPRODUCIBLE)
        self.assertIn(
            r.SR_REFUSED_ARTEFACT_AS_SIGNATURE, result["prohibited"]
        )
        self.assertIn(
            r.SR_REFUSED_NONDETERMINISTIC_AS_FAILURE, result["prohibited"]
        )

    def test_a_nonce_reused_signature_is_refused_not_classified(self) -> None:
        reuse = r.signature_evidence(
            [
                _attempt(b"same", nonce="n1", scheme="ecdsa"),
                _attempt(b"same", nonce="n1", scheme="ecdsa"),
            ],
            "ecdsa",
        )
        with self.assertRaises(r.Refusal) as caught:
            r.classify(reuse, self.reproducible)
        self.assertEqual(caught.exception.code, r.SR_REFUSED_NONCE_REUSE)

    def test_unknown_states_are_refused(self) -> None:
        unknown_signature = r.signature_evidence([_attempt(b"one")], "ed25519")
        with self.assertRaises(r.Refusal) as caught:
            r.classify(unknown_signature, self.reproducible)
        self.assertEqual(caught.exception.code, r.SR_REFUSED_ATTEMPTS_INSUFFICIENT)
        unknown_artefact = r.artefact_evidence(_subject("envelope"), None)
        with self.assertRaises(r.Refusal) as caught:
            r.classify(self.stable, unknown_artefact)
        self.assertEqual(
            caught.exception.code, r.SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST
        )


class RealEvidence(unittest.TestCase):
    def test_the_real_envelopes_are_signature_stable(self) -> None:
        document = _load(SIGNATURE)
        self.assertEqual(document["counts"]["signatures"], 4)
        self.assertEqual(document["counts"]["stable"], 4)
        self.assertEqual(document["counts"]["varies"], 0)
        self.assertEqual(document["counts"]["nonceReused"], 0)
        for row in document["signatures"]:
            with self.subTest(name=row["name"]):
                self.assertEqual(row["scheme"], "hmac-sha256")
                self.assertEqual(row["state"], r.SIGNATURE_STABLE)
                self.assertEqual(row["code"], r.CODE_OK)
                self.assertEqual(len(row["attempts"]), 2)
                self.assertEqual(
                    {attempt["envelopeSha256"] for attempt in row["attempts"]},
                    {row["a10EnvelopeSha256"]},
                )

    def test_no_real_subject_is_reproducible(self) -> None:
        document = _load(ARTEFACT)
        self.assertEqual(document["counts"]["subjects"], 5)
        self.assertEqual(document["counts"]["notRebuilt"], 5)
        self.assertEqual(document["counts"]["reproducible"], 0)
        self.assertEqual(document["counts"]["differs"], 0)
        self.assertEqual(document["counts"]["unknown"], 0)
        for row in document["subjects"]:
            with self.subTest(name=row["name"]):
                self.assertEqual(row["state"], r.ARTEFACT_NOT_REBUILT)
                self.assertEqual(row["code"], r.SR_REFUSED_REBUILD_NOT_RUN)
                self.assertFalse(row["reproducibilityClaimed"])

    def test_the_dso_records_its_digest_and_not_run_rebuild(self) -> None:
        document = _load(ARTEFACT)
        dso = next(row for row in document["subjects"] if row["name"] == be.DSO_NAME)
        self.assertEqual(dso["subject"]["kind"], "build-product")
        self.assertEqual(
            dso["subject"]["sha256"], dso["subject"]["recordedSha256"]
        )
        self.assertEqual(
            dso["subject"]["sha256"],
            "fd25cc9e6424ea79aaaff05df22b3f6e1d46aa22d5666cfe7589dce95ffd88a9",
        )
        self.assertEqual(dso["rebuild"]["outcome"], "NOT_RUN")
        self.assertEqual(dso["rebuild"]["attemptedInCourt"]["exit"], 101)
        self.assertIn("6 GiB", dso["reason"])
        self.assertIn("101", dso["reason"])
        self.assertEqual(dso["state"], r.ARTEFACT_NOT_REBUILT)

    def test_every_real_pair_is_classified(self) -> None:
        document = _load(CLASSIFICATION)
        self.assertEqual(document["counts"]["pairs"], 4)
        self.assertEqual(document["counts"]["unpaired"], 1)
        for pair in document["pairs"]:
            with self.subTest(name=pair["name"]):
                self.assertEqual(
                    pair["combination"],
                    "STABLE_SIGNATURE__NOT_REBUILT_ARTEFACT",
                )
                self.assertIn(
                    r.SR_REFUSED_SIGNATURE_AS_ARTEFACT, pair["prohibited"]
                )
                self.assertIn(r.SR_REFUSED_REBUILD_NOT_RUN, pair["prohibited"])
        self.assertEqual(document["unpaired"][0]["name"], be.DSO_NAME)
        self.assertEqual(document["unpaired"][0]["combination"], "UNPAIRED")

    def test_the_signature_axis_does_not_claim_anything_about_the_build(self) -> None:
        document = _load(SIGNATURE)
        self.assertTrue(
            any("rebuil" in text.lower() for text in document["doesNotEstablish"])
        )
        self.assertIn("says nothing about the build", document["note"])


class Controls(unittest.TestCase):
    def test_controls_cover_every_code_and_fire(self) -> None:
        document = _load(CONTROLS)
        self.assertEqual(document["codes"], len(r.REFUSALS))
        self.assertEqual(document["controlCount"], len(r.REFUSALS))
        rows = {row["code"]: row for row in document["controls"]}
        self.assertEqual(set(rows), set(r.REFUSALS))
        for code, row in rows.items():
            with self.subTest(code=code):
                self.assertTrue(row["fired"], row)
                self.assertEqual(row["code"], code)

    def test_every_code_has_a_control(self) -> None:
        document = _load(CONTROLS)
        self.assertEqual(
            {row["code"] for row in document["controls"]}, set(r.REFUSALS)
        )

    def test_the_randomised_varying_control_is_accepted(self) -> None:
        document = _load(CONTROLS)
        control = next(
            row for row in document["positiveControls"]
            if row["control"] == "randomised-varies"
        )
        self.assertTrue(control["accepted"])
        self.assertEqual(control["state"], r.SIGNATURE_VARIES)

    def test_the_synthetic_reproducible_control_is_control_only(self) -> None:
        document = _load(CONTROLS)
        control = next(
            row for row in document["positiveControls"]
            if row["control"] == "artefact-reproducible-synthetic"
        )
        self.assertTrue(control["accepted"])
        self.assertTrue(control["controlOnly"])
        self.assertEqual(control["state"], r.ARTEFACT_REPRODUCIBLE)
        artefact = _load(ARTEFACT)
        self.assertEqual(artefact["counts"]["reproducible"], 0)

    def test_the_four_combinations_control_lists_all_four(self) -> None:
        document = _load(CONTROLS)
        control = next(
            row for row in document["positiveControls"]
            if row["control"] == "four-combinations"
        )
        self.assertEqual(
            sorted(control["combinations"]),
            sorted(r.COMBINATION_LABELS.values()),
        )


class CommandLine(unittest.TestCase):
    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(TOOL), *arguments],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )

    def _write(self, directory: str, name: str, document: dict) -> str:
        path = Path(directory) / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return str(path)

    def test_signature_cli_deterministic_stable_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = self._write(
                directory, "a.json", _attempt(b"same", scheme="hmac-sha256")
            )
            second = self._write(
                directory, "b.json", _attempt(b"same", scheme="hmac-sha256")
            )
            result = self._run("signature", "control", first, second)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("code=SR_OK", result.stdout)
        self.assertIn(r.SIGNATURE_STABLE, result.stdout)

    def test_signature_cli_nonce_reuse_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = self._write(
                directory,
                "a.json",
                _attempt(b"same", nonce="n1", scheme="ecdsa"),
            )
            second = self._write(
                directory,
                "b.json",
                _attempt(b"same", nonce="n1", scheme="ecdsa"),
            )
            result = self._run("signature", "control", first, second)
        self.assertEqual(result.returncode, 1)
        self.assertIn(r.SR_REFUSED_NONCE_REUSE, result.stdout)
        self.assertIn(r.SIGNATURE_NONCE_REUSED, result.stdout)

    def test_artefact_cli_absent_rebuild_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            subject = self._write(directory, "subject.json", _subject())
            result = self._run("artefact", subject, "-")
        self.assertEqual(result.returncode, 1)
        self.assertIn(r.SR_REFUSED_REBUILD_NOT_RUN, result.stdout)
        self.assertIn(r.ARTEFACT_NOT_REBUILT, result.stdout)

    def test_artefact_cli_synthetic_reproducible_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            subject = self._write(directory, "subject.json", _subject())
            rebuild = self._write(
                directory, "rebuild.json", _completed_rebuild()
            )
            result = self._run("artefact", subject, rebuild)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("code=SR_OK", result.stdout)
        self.assertIn(r.ARTEFACT_REPRODUCIBLE, result.stdout)

    def test_classify_cli_prints_every_pair(self) -> None:
        result = self._run("classify")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("combination="), 5)
        for name in ("a1-sarif", "a5-admission", "a7-delta", "a8-shard-000"):
            with self.subTest(name=name):
                self.assertIn(f"name={name}", result.stdout)
        self.assertIn(r.SR_REFUSED_REBUILD_NOT_RUN, result.stdout)
        self.assertIn(r.SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE, result.stdout)

    def test_usage_errors_exit_two(self) -> None:
        for arguments in ((), ("not-a-command",)):
            with self.subTest(arguments=arguments):
                result = self._run(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn(r.CODE_USAGE, result.stderr)


class Determinism(unittest.TestCase):
    def test_the_producer_is_deterministic_and_matches_the_committed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for output in (first, second):
                result = subprocess.run(
                    [
                        sys.executable,
                        "-B",
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
            for name in (
                "SIGNATURE.json",
                "ARTEFACT.json",
                "CLASSIFICATION.json",
                "CONTROLS.json",
            ):
                with self.subTest(name=name):
                    committed = (A13 / name).read_bytes()
                    self.assertEqual((Path(first) / name).read_bytes(), committed)
                    self.assertEqual((Path(second) / name).read_bytes(), committed)

    def test_the_source_identity_is_supplied_not_read_live(self) -> None:
        for name in (
            "SIGNATURE.json",
            "ARTEFACT.json",
            "CLASSIFICATION.json",
            "CONTROLS.json",
        ):
            document = _load(A13 / name)
            with self.subTest(name=name):
                self.assertEqual(
                    document["sourceIdentity"]["baseCommit"], BASE_COMMIT
                )
                tool = document["sourceIdentity"]["tool"]
                self.assertEqual(tool["path"], r.TOOL_PATH)
                self.assertEqual(
                    tool["sha256"],
                    r.sha256_bytes((REPO_ROOT / tool["path"]).read_bytes()),
                )


class DocumentSynchronisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8") if DOCUMENT.is_file() else ""

    def test_the_document_names_every_refusal_code(self) -> None:
        for code in r.REFUSALS:
            with self.subTest(code=code):
                self.assertIn(f"`{code}`", self.text)

    def test_the_document_names_every_control(self) -> None:
        document = _load(CONTROLS)
        for control in document["controls"]:
            with self.subTest(control=control["control"]):
                self.assertIn(control["control"], self.text)
        for control in document["positiveControls"]:
            with self.subTest(control=control["control"]):
                self.assertIn(control["control"], self.text)

    def test_the_document_names_the_implementation_tests_and_evidence(self) -> None:
        for token in (
            r.TOOL_PATH,
            "forensics/tools/tests/test_reproducibility.py",
            "evidence/a13/SIGNATURE.json",
            "evidence/a13/ARTEFACT.json",
            "evidence/a13/CLASSIFICATION.json",
            "evidence/a13/CONTROLS.json",
            "evidence/a13/build_evidence.py",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.text)

    def test_the_document_states_the_two_axes_and_four_combinations(self) -> None:
        for token in (
            "Signature reproducibility",
            "Artefact reproducibility",
            "share no input",
            *r.COMBINATION_LABELS.values(),
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.text)

    def test_the_document_states_the_real_result(self) -> None:
        for token in (
            "4 of 4",
            r.SIGNATURE_STABLE,
            r.ARTEFACT_NOT_REBUILT,
            "no build-reproducibility claim",
            "fd25cc9e6424",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.text)

    def test_the_document_states_the_boundaries(self) -> None:
        for token in ("A12", "gate-5", "release gate", "ETP-2", "verify.py rebuild"):
            with self.subTest(token=token):
                self.assertIn(token, self.text)

    def test_the_two_axes_are_orthogonal(self) -> None:
        self.assertIn("share no input", self.text)
        self.assertIn(r.SR_REFUSED_SIGNATURE_AS_ARTEFACT, self.text)
        self.assertIn(r.SR_REFUSED_ARTEFACT_AS_SIGNATURE, self.text)

    def test_independence_and_reproducibility_are_distinct(self) -> None:
        self.assertIn(r.SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE, self.text)
        self.assertIn("A12 owns independence", self.text)

    def test_the_document_declares_non_claims(self) -> None:
        self.assertIn("Non-claims", self.text)
        self.assertIn("not a claim", self.text)

    def test_the_document_declares_not_run(self) -> None:
        self.assertIn("`NOT_RUN`", self.text)
        self.assertIn("NOT_RUN", self.text)
        self.assertIn("Every subject is", self.text)


if __name__ == "__main__":
    unittest.main()
