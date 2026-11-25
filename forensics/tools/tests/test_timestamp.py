#!/usr/bin/env python3
"""Controls for ``forensics/tools/timestamp.py`` and the B2 evidence.

The verifier is exercised in both directions: the deterministic control token is
accepted when its fields agree, and a token mutated in one field is refused with
the code that names that field.  Every refusal code has one triggering case, and
every case is paired with a positive control so a refusal is attributable to the
mutation rather than to a broken fixture.

The RFC 3161 structures are encoded here only as **control fixtures**: the
signature is HMAC-SHA256 under a fixed public seed, the certificate is
structurally parseable but carries no CA signature, and no TSA issued anything.
A fixture that verifies establishes that the verifier works; it is never
``TIMESTAMP_TRUSTED`` and it is not evidence of a trusted time.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import ast
import base64
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import timestamp  # noqa: E402

B2 = REPO_ROOT / "evidence/b2"
BUILDER = B2 / "build_evidence.py"
DOCUMENT = REPO_ROOT / "docs/TRUSTED-TIMESTAMPING.md"
TOOL = TOOLS / "timestamp.py"
ARTIFACT_PATH = REPO_ROOT / "evidence/a9/STATEMENTS/a8-shard-000.json"
ARTIFACT = ARTIFACT_PATH.read_bytes()
OTHER = (REPO_ROOT / "evidence/a9/STATEMENTS/a1-sarif.json").read_bytes()


def _builder():
    spec = importlib.util.spec_from_file_location("b2_build_evidence", BUILDER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _refusal_code(callable_, *args, **kwargs) -> str:
    try:
        callable_(*args, **kwargs)
    except timestamp.Refusal as refusal:
        return refusal.code
    raise AssertionError("the call was not refused")


class StrictDER(unittest.TestCase):
    def test_a_valid_control_token_parses_and_records_its_fields(self) -> None:
        token = timestamp.control_token("valid", artifact=ARTIFACT)
        parsed = timestamp.parse_token(token)
        self.assertEqual(parsed.tst.version, 1)
        self.assertEqual(parsed.tst.algorithm, "sha256")
        self.assertEqual(parsed.tst.gen_time, timestamp.CONTROL_GEN_TIME)
        self.assertEqual(parsed.tst.policy, timestamp.POLICY_FIXTURE)
        self.assertEqual(parsed.tst.serial, 1)
        self.assertEqual(parsed.tst.nonce, 7)
        self.assertEqual(parsed.tst.accuracy, timestamp.Accuracy(0, 1, 1))
        self.assertEqual(parsed.tst.hashed_message, __import__("hashlib").sha256(ARTIFACT).digest())
        self.assertEqual(parsed.certificate_count, 1)
        self.assertEqual(parsed.signature_oid, timestamp.OID_HMAC_SHA256)

    def test_an_indefinite_length_is_refused(self) -> None:
        self.assertEqual(_refusal_code(timestamp.parse_token, b"\x30\x80\x00\x00"), "TS_REFUSED_DER")

    def test_a_non_minimal_length_is_refused(self) -> None:
        self.assertEqual(
            _refusal_code(timestamp.parse_token, b"\x30\x81\x05" + b"\x00" * 5), "TS_REFUSED_DER"
        )

    def test_a_leading_zero_in_a_long_length_is_refused(self) -> None:
        self.assertEqual(
            _refusal_code(timestamp.parse_token, b"\x30\x82\x00\x80" + b"\x00" * 128),
            "TS_REFUSED_DER",
        )

    def test_high_tag_number_form_is_refused(self) -> None:
        self.assertEqual(_refusal_code(timestamp.parse_token, b"\x3f\x01\x00"), "TS_REFUSED_DER")

    def test_a_non_minimal_integer_is_refused(self) -> None:
        self.assertEqual(
            _refusal_code(timestamp._integer_content, b"\x00\x01", "test"), "TS_REFUSED_DER"
        )

    def test_a_truncated_token_is_refused(self) -> None:
        token = timestamp.control_token("malformed-der", artifact=ARTIFACT)
        self.assertEqual(_refusal_code(timestamp.parse_token, token), "TS_REFUSED_DER")

    def test_a_trailing_byte_is_refused(self) -> None:
        token = timestamp.control_token("trailing-byte", artifact=ARTIFACT)
        self.assertEqual(_refusal_code(timestamp.parse_token, token), "TS_REFUSED_DER")

    def test_an_empty_token_is_refused(self) -> None:
        self.assertEqual(_refusal_code(timestamp.parse_token, b""), "TS_REFUSED_DER")

    def test_an_unsupported_version_is_refused(self) -> None:
        token = timestamp.control_token("unsupported-version", artifact=ARTIFACT)
        self.assertEqual(_refusal_code(timestamp.parse_token, token), "TS_REFUSED_VERSION")


class Imprint(unittest.TestCase):
    def test_the_imprint_verifies_against_the_artefact(self) -> None:
        token = timestamp.control_token("valid", artifact=ARTIFACT)
        result = timestamp.verify_token(token, ARTIFACT)
        self.assertEqual(result.code, "TS_OK")
        self.assertEqual(result.imprint, "PASS")
        self.assertEqual(result.outcome, timestamp.OUTCOME_IMPRINT_VERIFIED_UNTRUSTED)
        self.assertFalse(result.as_dict()["trusted"])

    def test_a_token_for_another_artefact_is_refused(self) -> None:
        token = timestamp.control_token("valid", artifact=ARTIFACT)
        result = timestamp.verify_token(token, OTHER)
        self.assertEqual(result.code, "TS_REFUSED_IMPRINT")

    def test_the_wrong_imprint_control_is_refused(self) -> None:
        token = timestamp.control_token("wrong-imprint", artifact=ARTIFACT)
        self.assertEqual(timestamp.verify_token(token, ARTIFACT).code, "TS_REFUSED_IMPRINT")

    def test_a_declared_algorithm_that_differs_is_refused(self) -> None:
        token = timestamp.control_token("wrong-algorithm", artifact=ARTIFACT)
        self.assertEqual(timestamp.verify_token(token, ARTIFACT).code, "TS_REFUSED_ALGORITHM")
        valid = timestamp.control_token("valid", artifact=ARTIFACT)
        self.assertEqual(timestamp.verify_token(valid, ARTIFACT, algorithm="sha512").code,
                         "TS_REFUSED_ALGORITHM")

    def test_an_unsupported_declared_algorithm_is_refused(self) -> None:
        token = timestamp.control_token("valid", artifact=ARTIFACT)
        self.assertEqual(timestamp.verify_token(token, ARTIFACT, algorithm="md5").code,
                         "TS_REFUSED_ALGORITHM")

    def test_an_absent_gen_time_is_refused(self) -> None:
        token = timestamp.control_token("absent-gen-time", artifact=ARTIFACT)
        self.assertEqual(timestamp.verify_token(token, ARTIFACT).code, "TS_REFUSED_GEN_TIME")

    def test_a_gen_time_without_utc_is_refused(self) -> None:
        from hashlib import sha256

        tstinfo = timestamp._tstinfo(digest=sha256(ARTIFACT).digest(), gen_time="20261124000000")
        self.assertEqual(_refusal_code(timestamp.parse_tstinfo, tstinfo), "TS_REFUSED_GEN_TIME")

    def test_an_impossible_gen_time_is_refused(self) -> None:
        from hashlib import sha256

        tstinfo = timestamp._tstinfo(digest=sha256(ARTIFACT).digest(), gen_time="20260230000000Z")
        self.assertEqual(_refusal_code(timestamp.parse_tstinfo, tstinfo), "TS_REFUSED_GEN_TIME")

    def test_the_accuracy_is_recorded(self) -> None:
        token = timestamp.control_token("valid", artifact=ARTIFACT)
        result = timestamp.verify_token(token, ARTIFACT)
        self.assertEqual(result.accuracy, "seconds=0,millis=1,micros=1")

    def test_an_out_of_range_accuracy_is_refused(self) -> None:
        token = timestamp.control_token("invalid-accuracy", artifact=ARTIFACT)
        self.assertEqual(timestamp.verify_token(token, ARTIFACT).code, "TS_REFUSED_ACCURACY")


class SignatureAndTrust(unittest.TestCase):
    def setUp(self) -> None:
        self.token = timestamp.control_token("valid", artifact=ARTIFACT)
        self.with_eku = timestamp.control_certificate(with_eku=True)
        self.verify = timestamp.control_verify_signature

    def test_without_a_certificate_the_signature_is_not_run(self) -> None:
        result = timestamp.verify_token(self.token, ARTIFACT)
        self.assertEqual(result.signature, "NOT_RUN")
        self.assertEqual(result.eku, "NOT_RUN")
        self.assertEqual(result.chain, "NOT_RUN")
        self.assertEqual(result.root, "NOT_RUN")
        self.assertEqual(result.outcome, timestamp.OUTCOME_IMPRINT_VERIFIED_UNTRUSTED)

    def test_with_a_certificate_and_function_the_signature_verifies_untrusted(self) -> None:
        result = timestamp.verify_token(
            self.token,
            ARTIFACT,
            certificate=self.with_eku,
            verify_signature=self.verify,
        )
        self.assertEqual(result.signature, "PASS")
        self.assertEqual(result.eku, "PASS")
        self.assertEqual(result.outcome, timestamp.OUTCOME_SIGNATURE_VERIFIED_UNTRUSTED)
        self.assertFalse(result.as_dict()["trusted"])
        self.assertNotEqual(result.outcome, timestamp.OUTCOME_TRUSTED)

    def test_a_certificate_without_the_timestamping_eku_is_refused(self) -> None:
        result = timestamp.verify_token(
            self.token,
            ARTIFACT,
            certificate=timestamp.control_certificate(with_eku=False),
            verify_signature=self.verify,
        )
        self.assertEqual(result.code, "TS_REFUSED_EKU")

    def test_a_bad_signature_is_refused(self) -> None:
        token = timestamp.control_token("bad-signature", artifact=ARTIFACT)
        result = timestamp.verify_token(
            token, ARTIFACT, certificate=self.with_eku, verify_signature=self.verify
        )
        self.assertEqual(result.code, "TS_REFUSED_SIGNATURE")

    def test_a_required_root_that_is_absent_is_refused(self) -> None:
        result = timestamp.verify_token(
            self.token,
            ARTIFACT,
            certificate=self.with_eku,
            verify_signature=self.verify,
            require_root=True,
        )
        self.assertEqual(result.code, "TS_REFUSED_ROOT")

    def test_a_root_that_is_not_self_issued_is_refused(self) -> None:
        result = timestamp.verify_token(
            self.token,
            ARTIFACT,
            certificate=self.with_eku,
            verify_signature=self.verify,
            trust_root=self.with_eku,
        )
        self.assertEqual(result.code, "TS_REFUSED_ROOT")

    def test_a_matching_root_is_presence_only_and_never_trusted(self) -> None:
        result = timestamp.verify_token(
            self.token,
            ARTIFACT,
            certificate=self.with_eku,
            verify_signature=self.verify,
            trust_root=timestamp.control_root(),
        )
        self.assertEqual(result.code, "TS_OK")
        self.assertEqual(result.root, "PRESENCE_ONLY")
        self.assertEqual(result.outcome, timestamp.OUTCOME_SIGNATURE_VERIFIED_UNTRUSTED)
        self.assertNotEqual(result.outcome, timestamp.OUTCOME_TRUSTED)

    def test_a_live_service_assertion_is_refused(self) -> None:
        token = timestamp.control_token("live-service", artifact=ARTIFACT)
        self.assertEqual(timestamp.verify_token(token, ARTIFACT).code, "TS_REFUSED_LIVE_SERVICE")
        self.assertEqual(
            timestamp.verify_token(self.token, ARTIFACT, live_service=True).code,
            "TS_REFUSED_LIVE_SERVICE",
        )

    def test_a_nonce_mismatch_is_refused_and_a_match_passes(self) -> None:
        token = timestamp.control_token("nonce-mismatch", artifact=ARTIFACT)
        self.assertEqual(
            timestamp.verify_token(token, ARTIFACT, expected_nonce=8).code, "TS_REFUSED_NONCE"
        )
        self.assertEqual(
            timestamp.verify_token(token, ARTIFACT, expected_nonce=7).code, "TS_OK"
        )

    def test_the_content_type_attribute_is_bound(self) -> None:
        token = bytearray(timestamp.control_token("valid", artifact=ARTIFACT))
        marker = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x01\x04"
        position = bytes(token).find(marker)
        self.assertGreater(position, 0)
        token[position + len(marker) - 1] = 0x05  # id-ct-TSTInfo -> an unrelated OID
        result = timestamp.verify_token(bytes(token), ARTIFACT)
        self.assertIn(result.code, {"TS_REFUSED_SIGNATURE", "TS_REFUSED_DER"})


class NineTimes(unittest.TestCase):
    def test_the_model_has_exactly_the_nine_clause_slots_in_order(self) -> None:
        names = [slot.name for slot in timestamp.SLOTS]
        self.assertEqual(
            names,
            [
                "source-creation",
                "experimental-execution",
                "evidence-production",
                "statement-authentication",
                "trusted-timestamping",
                "transparency-inclusion",
                "witness-observation",
                "release-promotion",
                "correction-or-revocation",
            ],
        )
        kinds = [slot.kind for slot in timestamp.SLOTS]
        self.assertEqual(
            kinds,
            ["local", "local", "local", "client", "authority", "log", "verifier",
             "publication", "publication"],
        )

    def test_the_order_invariants_are_the_declared_pairs(self) -> None:
        self.assertEqual(
            timestamp.ORDER_INVARIANTS,
            (
                ("source-creation", "experimental-execution"),
                ("experimental-execution", "evidence-production"),
                ("evidence-production", "statement-authentication"),
                ("statement-authentication", "trusted-timestamping"),
                ("trusted-timestamping", "transparency-inclusion"),
                ("transparency-inclusion", "witness-observation"),
                ("transparency-inclusion", "release-promotion"),
                ("release-promotion", "correction-or-revocation"),
            ),
        )

    def test_the_control_fixture_is_accepted(self) -> None:
        self.assertEqual(timestamp.validate_times(timestamp.control_times("valid")), [])

    def test_each_ordering_invariant_is_enforced(self) -> None:
        for earlier, later in timestamp.ORDER_INVARIANTS:
            fixture = timestamp.control_times("valid")
            slots = {slot["name"]: slot for slot in fixture["slots"]}
            # Move the later slot one minute before its earlier partner.
            earlier_value = datetime_of(slots[earlier]["value"])
            slots[later]["value"] = (earlier_value - timedelta(minutes=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            codes = [r["code"] for r in timestamp.validate_times(fixture)]
            self.assertIn(
                "TS_REFUSED_ORDER",
                codes,
                f"{later} before {earlier} was not refused",
            )

    def test_an_explained_inversion_is_accepted(self) -> None:
        self.assertEqual(timestamp.validate_times(timestamp.control_times("out-of-order-explained")), [])

    def test_a_collapsed_pair_is_refused(self) -> None:
        codes = [
            refusal["code"]
            for refusal in timestamp.validate_times(timestamp.control_times("collapsed"))
        ]
        self.assertEqual(set(codes), {"TS_REFUSED_TIME_COLLAPSED"})
        self.assertGreater(len(codes), 1)

    def test_an_unsourced_time_is_refused(self) -> None:
        codes = [
            refusal["code"]
            for refusal in timestamp.validate_times(timestamp.control_times("unsourced"))
        ]
        self.assertIn("TS_REFUSED_TIME_UNSOURCED", codes)

    def test_a_clock_read_is_not_a_source(self) -> None:
        codes = [
            refusal["code"]
            for refusal in timestamp.validate_times(timestamp.control_times("clock-source"))
        ]
        self.assertEqual(codes, ["TS_REFUSED_TIME_UNSOURCED"])

    def test_execution_is_never_inferred_from_a_later_timestamp(self) -> None:
        codes = [
            refusal["code"]
            for refusal in timestamp.validate_times(
                timestamp.control_times("execution-from-timestamp")
            )
        ]
        self.assertIn("TS_REFUSED_TIME_UNSOURCED", codes)

    def test_a_missing_slot_is_refused_by_the_model(self) -> None:
        codes = [
            refusal["code"]
            for refusal in timestamp.validate_times(timestamp.control_times("missing-slot"))
        ]
        self.assertEqual(codes, ["TS_REFUSED_TIME_MODEL"])

    def test_a_wrong_kind_is_refused_by_the_model(self) -> None:
        fixture = timestamp.control_times("valid")
        fixture["slots"][4]["kind"] = "local"  # trusted timestamping is an authority
        codes = [refusal["code"] for refusal in timestamp.validate_times(fixture)]
        self.assertEqual(codes, ["TS_REFUSED_TIME_MODEL"])

    def test_an_established_time_without_an_accuracy_is_refused(self) -> None:
        fixture = timestamp.control_times("bad-accuracy")
        codes = [refusal["code"] for refusal in timestamp.validate_times(fixture)]
        self.assertEqual(codes, ["TS_REFUSED_ACCURACY"])

    def test_a_single_timestamp_field_cannot_satisfy_the_model(self) -> None:
        document = {"artefacts": [{"id": "collapsed", "slots": [{"name": "timestamp"}]}]}
        codes = [refusal["code"] for refusal in timestamp.validate_times_document(document)]
        self.assertEqual(codes, ["TS_REFUSED_TIME_MODEL"])


class RealEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.times = json.loads((B2 / "TIMES.json").read_text(encoding="utf-8"))
        cls.tokens = json.loads((B2 / "TOKENS.json").read_text(encoding="utf-8"))
        cls.verification = json.loads((B2 / "VERIFICATION.json").read_text(encoding="utf-8"))
        cls.controls = json.loads((B2 / "CONTROLS.json").read_text(encoding="utf-8"))

    def test_the_real_record_has_no_refusals(self) -> None:
        self.assertEqual(timestamp.validate_times_document(self.times), [])
        for artefact in self.times["artefacts"]:
            self.assertEqual(artefact["refusals"], [])

    def test_the_real_record_has_the_nine_slots_for_every_artefact(self) -> None:
        self.assertEqual(len(self.times["artefacts"]), 5)
        for artefact in self.times["artefacts"]:
            self.assertEqual([slot["name"] for slot in artefact["slots"]], list(timestamp.SLOT_NAMES))

    def test_most_real_slots_are_unknown_and_the_authority_slots_are(self) -> None:
        self.assertEqual(self.times["summary"]["slots"], 45)
        self.assertEqual(self.times["summary"]["established"], 10)
        self.assertEqual(self.times["summary"]["unknown"], 28)
        self.assertEqual(self.times["summary"]["notEstablished"], 7)
        for artefact in self.times["artefacts"]:
            slots = {slot["name"]: slot for slot in artefact["slots"]}
            self.assertEqual(slots["trusted-timestamping"]["established"], "unknown")
            self.assertIsNone(slots["trusted-timestamping"]["value"])
            self.assertIsNone(slots["experimental-execution"]["value"])

    def test_the_two_claims_are_recorded_separately(self) -> None:
        claims = self.times["twoClaims"]
        self.assertTrue(claims["imprintMatchesArtefact"]["checkableOffline"])
        self.assertFalse(claims["authorityAssertedTheTime"]["checkableOffline"])
        self.assertEqual(claims["imprintMatchesArtefact"]["establishedForRealArtefacts"], 0)
        self.assertEqual(claims["authorityAssertedTheTime"]["establishedForRealArtefacts"], 0)

    def test_no_token_exists_in_the_tree(self) -> None:
        self.assertEqual(self.tokens["summary"]["tokensFound"], 0)
        self.assertEqual(self.tokens["tokens"], [])
        self.assertEqual(self.tokens["summary"]["fabricatedTokens"], 0)
        self.assertEqual(
            {entry["outcome"] for entry in self.tokens["perArtefact"]}, {"NO_TOKEN"}
        )
        found, _scanned = timestamp.scan_for_tokens(REPO_ROOT)
        self.assertEqual(found, [])

    def test_every_control_fixture_is_control_only_and_untrusted(self) -> None:
        self.assertTrue(self.controls["controlOnly"])
        self.assertFalse(self.controls["trusted"])
        self.assertFalse(self.controls["positiveControl"]["trusted"])
        for control in self.controls["controls"]:
            self.assertEqual(control["fixture"], "control-only")
            self.assertFalse(control["trusted"])

    def test_the_controls_cover_every_refusal_code(self) -> None:
        observed = {control["refusalCode"] for control in self.controls["controls"]}
        self.assertEqual(observed, set(timestamp.REFUSAL_CODES))
        self.assertTrue(self.controls["summary"]["onePerCode"])
        self.assertEqual(self.controls["summary"]["fired"], len(self.controls["controls"]))
        self.assertEqual(
            self.controls["summary"]["canariesAccepted"], len(self.controls["controls"])
        )
        for control in self.controls["controls"]:
            self.assertEqual(control["canaryResult"], "ACCEPTED")

    def test_every_embedded_token_is_deterministic_and_parses(self) -> None:
        for control in self.controls["controls"]:
            if control["kind"] != "token":
                continue
            raw = base64.b64decode(control["tokenBase64"])
            self.assertEqual(__import__("hashlib").sha256(raw).hexdigest(), control["tokenSha256"])
            try:
                timestamp.parse_token(raw)
            except timestamp.Refusal as refusal:
                self.assertIn(
                    refusal.code,
                    {
                        "TS_REFUSED_DER",
                        "TS_REFUSED_VERSION",
                        "TS_REFUSED_GEN_TIME",
                        "TS_REFUSED_ACCURACY",
                    },
                    control["id"],
                )

    def test_the_verification_aggregate_is_zero_trusted(self) -> None:
        self.assertEqual(self.verification["aggregate"]["trusted"], 0)
        self.assertEqual(self.verification["aggregate"]["imprintVerified"], 0)
        self.assertEqual(self.verification["aggregate"]["signatureVerified"], 0)
        for entry in self.verification["perArtefact"]:
            self.assertFalse(entry["trusted"])
            self.assertEqual(entry["outcome"], "TIMESTAMP_NO_TOKEN")

    def test_the_committed_records_are_the_current_build(self) -> None:
        records = _builder().build()
        for name, data in records.items():
            self.assertEqual((B2 / name).read_bytes(), data, name)

    def test_two_builds_are_byte_identical(self) -> None:
        first = _builder().build()
        second = _builder().build()
        self.assertEqual(first, second)


class NoNetwork(unittest.TestCase):
    def test_the_module_imports_no_network_or_process_module(self) -> None:
        tree = ast.parse(TOOL.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        for forbidden in ("socket", "subprocess", "urllib", "http", "ftplib", "ssl"):
            self.assertNotIn(forbidden, imported)

    def test_the_module_calls_no_external_client(self) -> None:
        tree = ast.parse(TOOL.read_text(encoding="utf-8"))
        names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        for forbidden in ("system", "popen", "run", "call", "check_output"):
            self.assertNotIn(forbidden, names)
        text = TOOL.read_text(encoding="utf-8")
        for forbidden in ("tsget", "curl"):
            self.assertNotIn(f"'{forbidden}'", text)
            self.assertNotIn(f'"{forbidden}"', text)

    def test_importing_the_module_loads_no_network_module(self) -> None:
        script = (
            "import sys\n"
            f"sys.path.insert(0, {str(TOOLS)!r})\n"
            "import timestamp\n"
            "loaded = [name for name in ('socket', 'subprocess', 'urllib.request', "
            "'http.client') if name in sys.modules]\n"
            "print(','.join(loaded))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")


class CommandLine(unittest.TestCase):
    def run_tool(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_times_prints_the_nine_slots_and_exits_zero(self) -> None:
        result = self.run_tool("times")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("code=TS_OK", result.stdout)
        self.assertEqual(result.stdout.count("  slot="), 45)
        for name in timestamp.SLOT_NAMES:
            self.assertIn(f"slot={name}", result.stdout)

    def test_times_refuses_an_out_of_order_record(self) -> None:
        fixture = timestamp.control_times("out-of-order")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "times.json"
            path.write_text(json.dumps({"artefacts": [fixture]}), encoding="utf-8")
            result = self.run_tool("times", "--file", str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("code=TS_REFUSED_ORDER", result.stdout)

    def test_verify_accepts_the_valid_fixture_and_says_untrusted(self) -> None:
        result = self.run_tool(
            "verify", "--artifact", str(ARTIFACT_PATH), "--control-fixture", "valid"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("code=TS_OK", result.stdout)
        self.assertIn("outcome=TIMESTAMP_SIGNATURE_VERIFIED_UNTRUSTED", result.stdout)
        self.assertIn("trusted=false", result.stdout)
        self.assertNotIn("TIMESTAMP_TRUSTED", result.stdout)

    def test_verify_refuses_a_wrong_imprint(self) -> None:
        result = self.run_tool(
            "verify", "--artifact", str(ARTIFACT_PATH), "--control-fixture", "wrong-imprint"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("code=TS_REFUSED_IMPRINT", result.stdout)

    def test_verify_without_a_token_reports_no_token(self) -> None:
        result = self.run_tool("verify", "--artifact", str(ARTIFACT_PATH))
        self.assertEqual(result.returncode, 0)
        self.assertIn("code=TS_NO_TOKEN", result.stdout)
        self.assertIn("outcome=TIMESTAMP_NO_TOKEN", result.stdout)

    def test_scan_finds_zero_tokens(self) -> None:
        result = self.run_tool("scan", "--root", str(REPO_ROOT))
        self.assertEqual(result.returncode, 0)
        self.assertIn("tokens=0", result.stdout)

    def test_no_command_is_a_usage_error(self) -> None:
        result = self.run_tool()
        self.assertEqual(result.returncode, 2)
        self.assertIn("code=TS_REFUSED_USAGE", result.stdout)

    def test_a_missing_file_is_an_io_error(self) -> None:
        result = self.run_tool("times", "--file", "/nonexistent/TIMES.json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("code=TS_REFUSED_IO", result.stdout)


class DocumentSynchronisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8")
        cls.flat = " ".join(cls.text.split())

    def test_the_document_exists_and_separates_the_claims(self) -> None:
        for phrase in ("imprint", "trusted time", "nine times", "NOT_RUN"):
            self.assertIn(phrase, self.text, phrase)

    def test_every_refusal_code_appears(self) -> None:
        for code in (*timestamp.REFUSAL_CODES, timestamp.CODE_OK, timestamp.CODE_NO_TOKEN,
                     timestamp.CODE_USAGE):
            self.assertIn(code, self.text, code)

    def test_every_slot_name_appears(self) -> None:
        for name in timestamp.SLOT_NAMES:
            self.assertIn(name, self.text, name)

    def test_the_document_states_the_non_claims(self) -> None:
        folded = self.flat.lower()
        for phrase in (
            "imprint match is not a trusted time",
            "fixture token is not an authority",
            "clock is trustworthy because it is read",
        ):
            self.assertIn(phrase, folded, phrase)
        self.assertIn("never produced", folded)
        self.assertIn("TIMESTAMP_TRUSTED", self.text)

    def test_every_rule_names_what_enforces_it(self) -> None:
        self.assertIn("enforced by", self.text.lower())

    def test_the_document_has_a_not_run_section(self) -> None:
        self.assertIn("## `NOT_RUN`", self.text)


def datetime_of(value: str):
    from datetime import datetime

    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def timedelta(**kwargs):
    from datetime import timedelta as _timedelta

    return _timedelta(**kwargs)


if __name__ == "__main__":
    unittest.main()
