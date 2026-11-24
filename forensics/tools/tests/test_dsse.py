#!/usr/bin/env python3
"""Controls for the A10 DSSE v1 envelope and the exact PAE.

Each control exercises one rule of `docs/DSSE-PAE.md`: the PAE encoding is the
specified byte string; verification is over the received bytes and never over a
parsed and re-encoded payload; the envelope is parsed strictly; and the module
makes no trust decision.

A control mutates a copy in memory or writes to a temporary directory. It proves
a refusal fires, not that the substituted form occurs anywhere in the tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import dsse as d  # noqa: E402

A10 = REPO_ROOT / "evidence" / "a10"
ENVELOPES = A10 / "ENVELOPES"
INDEX = A10 / "ENVELOPES.json"
CONTROLS = A10 / "CONTROLS.json"
PRODUCER = A10 / "build_evidence.py"
TOOL = TOOLS / "dsse.py"
DOCUMENT = REPO_ROOT / "docs" / "DSSE-PAE.md"

STATEMENTS = (
    ("a1-sarif", "evidence/a9/STATEMENTS/a1-sarif.json"),
    ("a5-admission", "evidence/a9/STATEMENTS/a5-admission.json"),
    ("a7-delta", "evidence/a9/STATEMENTS/a7-delta.json"),
    ("a8-shard-000", "evidence/a9/STATEMENTS/a8-shard-000.json"),
)

VECTOR_TYPE = "http://example.com/HelloWorld"
VECTOR_BODY = b"hello world"
VECTOR_BYTES = b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _assert_refused(test: unittest.TestCase, code: str, action) -> str:
    with test.assertRaises(d.Refusal) as raised:
        action()
    test.assertEqual(raised.exception.code, code, raised.exception.message)
    return raised.exception.message


def _envelope_document(**changes) -> dict:
    document = {
        "payloadType": d.IN_TOTO_PAYLOAD_TYPE,
        "payload": d.strict_b64encode(b'{"a":1}'),
        "signatures": [{"keyid": "k", "sig": d.strict_b64encode(b"x")}],
    }
    document.update(changes)
    return document


class PaeEncoding(unittest.TestCase):
    def test_the_specification_vector_is_exact(self) -> None:
        produced = d.pae(VECTOR_TYPE, VECTOR_BODY)
        self.assertEqual(produced, VECTOR_BYTES)
        self.assertEqual(
            produced,
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world",
        )
        self.assertEqual(len(VECTOR_TYPE.encode("utf-8")), 29)
        self.assertEqual(len(VECTOR_BODY), 11)

    def test_the_vector_is_in_the_index_and_the_producer_asserts_it(self) -> None:
        vector = _load(INDEX)["paeVector"]
        self.assertEqual(vector["expectedText"], VECTOR_BYTES.decode("ascii"))
        self.assertEqual(bytes.fromhex(vector["expectedHex"]), VECTOR_BYTES)
        self.assertEqual(vector["sha256"], hashlib.sha256(VECTOR_BYTES).hexdigest())
        self.assertEqual(vector["bodyText"], "hello world")
        self.assertEqual(vector["bodyLength"], 11)
        self.assertEqual(vector["typeLength"], 29)

    def test_the_vector_parses_to_its_own_fields(self) -> None:
        self.assertEqual(d.parse_pae(VECTOR_BYTES), (VECTOR_TYPE, VECTOR_BODY))
        self.assertEqual(
            d.pae(*d.parse_pae(VECTOR_BYTES)),
            VECTOR_BYTES,
        )

    def test_an_empty_type_and_an_empty_body_are_encoded_with_zero_lengths(self) -> None:
        self.assertEqual(d.pae("", b""), b"DSSEv1 0  0 ")
        self.assertEqual(d.parse_pae(b"DSSEv1 0  0 "), ("", b""))
        self.assertEqual(d.pae("", b"x"), b"DSSEv1 0  1 x")
        self.assertEqual(d.pae("t", b""), b"DSSEv1 1 t 0 ")

    def test_a_multi_byte_utf8_type_uses_its_byte_length(self) -> None:
        payload_type = "\u00e9"  # two UTF-8 bytes, one character
        self.assertEqual(len(payload_type), 1)
        self.assertEqual(d.pae(payload_type, b"x"), b"DSSEv1 2 \xc3\xa9 1 x")
        self.assertEqual(d.parse_pae(b"DSSEv1 2 \xc3\xa9 1 x"), (payload_type, b"x"))

    def test_a_body_of_arbitrary_bytes_is_used_exactly(self) -> None:
        body = bytes(range(256))
        encoded = d.pae("t", body)
        self.assertTrue(encoded.endswith(body))
        self.assertIn(b" 256 ", encoded)
        self.assertEqual(d.parse_pae(encoded), ("t", body))

    def test_a_long_length_is_decimal_without_padding(self) -> None:
        body = b"a" * 1000
        self.assertIn(b"DSSEv1 1 t 1000 ", d.pae("t", body))
        self.assertEqual(d.parse_pae(d.pae("t", body)), ("t", body))


class EnvelopeAndSigning(unittest.TestCase):
    def test_an_envelope_is_deterministic(self) -> None:
        first = d.encode_envelope(
            d.envelope("t", b'{"a": 1}', d.test_only_signer())
        )
        second = d.encode_envelope(
            d.envelope("t", b'{"a": 1}', d.test_only_signer())
        )
        self.assertEqual(first, second)
        self.assertEqual(
            first,
            json.dumps(
                json.loads(first), sort_keys=True, separators=(",", ":")
            ).encode("utf-8"),
        )

    def test_the_signature_is_over_the_received_bytes(self) -> None:
        payload = b'{"a":  1}\n'  # deliberately non-canonical whitespace
        raw = d.encode_envelope(d.envelope("t", payload, d.test_only_signer()))
        report = d.verify_pae(raw, d.test_only_verifier())
        self.assertEqual(report["payload"], payload)
        self.assertEqual(report["payloadType"], "t")
        self.assertEqual(
            report["paeSha256"], hashlib.sha256(d.pae("t", payload)).hexdigest()
        )

    def test_sign_appends_without_mutating_the_caller(self) -> None:
        original = _envelope_document(signatures=[])
        signed = d.sign(original, d.test_only_signer())
        self.assertEqual(original["signatures"], [])
        self.assertEqual(len(signed["signatures"]), 1)
        self.assertIsNot(original["signatures"], signed["signatures"])

    def test_strict_base64_reproduces_its_input(self) -> None:
        for raw in (b"", b"{", b"{}", bytes(range(256)), b"x" * 1000):
            encoded = d.strict_b64encode(raw)
            self.assertEqual(d.strict_b64decode(encoded, "test"), raw)
            self.assertEqual(d.strict_b64encode(d.strict_b64decode(encoded, "test")), encoded)


class Refusals(unittest.TestCase):
    """One control per refusal code: each asserts its exact code."""

    def test_envelope_invalid(self) -> None:
        for document in (
            _envelope_document(payloadType=1),
            _envelope_document(extra=True),
            b"[1,2,3]",
            b"{not json",
            b"",
        ):
            with self.subTest(document=document):
                raw = (
                    document
                    if isinstance(document, bytes)
                    else d.encode_envelope(document)
                )
                _assert_refused(
                    self,
                    d.DS_REFUSED_ENVELOPE_INVALID,
                    lambda: d.verify_pae(raw, d.test_only_verifier()),
                )

    def test_duplicate_key(self) -> None:
        raw = (
            b'{"payloadType":"a","payloadType":"b","payload":"e30=",'
            b'"signatures":[{"keyid":"k","sig":"eA=="}]}'
        )
        _assert_refused(
            self, d.DS_REFUSED_DUPLICATE_KEY,
            lambda: d.verify_pae(raw, d.test_only_verifier()),
        )
        nested = (
            b'{"payloadType":"a","payload":"e30=",'
            b'"signatures":[{"keyid":"k","keyid":"k2","sig":"eA=="}]}'
        )
        _assert_refused(
            self, d.DS_REFUSED_DUPLICATE_KEY,
            lambda: d.verify_pae(nested, d.test_only_verifier()),
        )

    def test_payload_type_missing(self) -> None:
        document = _envelope_document()
        document.pop("payloadType")
        _assert_refused(
            self, d.DS_REFUSED_PAYLOAD_TYPE_MISSING,
            lambda: d.verify_pae(d.encode_envelope(document), d.test_only_verifier()),
        )

    def test_payload_type_mismatch(self) -> None:
        raw = d.encode_envelope(d.envelope("a", b"{}", d.test_only_signer()))
        _assert_refused(
            self, d.DS_REFUSED_PAYLOAD_TYPE_MISMATCH,
            lambda: d.verify_pae(
                raw, d.test_only_verifier(), expected_payload_type="b"
            ),
        )

    def test_base64_noncanonical(self) -> None:
        cases = (
            "e30",       # missing padding
            "ex==",      # non-zero pad bits (canonically "ew==")
            "e30= ",     # whitespace
            "e3-_",      # url-safe alphabet
            "e30==",     # excess padding
        )
        for value in cases:
            with self.subTest(value=value):
                _assert_refused(
                    self,
                    d.DS_REFUSED_BASE64_NONCANONICAL,
                    lambda: d.verify_pae(
                        d.encode_envelope(_envelope_document(payload=value)),
                        d.test_only_verifier(),
                    ),
                )

    def test_payload_absent(self) -> None:
        document = _envelope_document()
        document.pop("payload")
        _assert_refused(
            self, d.DS_REFUSED_PAYLOAD_ABSENT,
            lambda: d.verify_pae(d.encode_envelope(document), d.test_only_verifier()),
        )

    def test_signatures_absent(self) -> None:
        document = _envelope_document()
        document.pop("signatures")
        _assert_refused(
            self, d.DS_REFUSED_SIGNATURES_ABSENT,
            lambda: d.verify_pae(d.encode_envelope(document), d.test_only_verifier()),
        )
        _assert_refused(
            self, d.DS_REFUSED_SIGNATURES_ABSENT,
            lambda: d.verify_pae(
                d.encode_envelope(_envelope_document(signatures=[])),
                d.test_only_verifier(),
            ),
        )

    def test_signature_invalid(self) -> None:
        raw = d.encode_envelope(d.envelope("t", b"{}", d.test_only_signer()))
        document = json.loads(raw)
        signature = d.strict_b64decode(document["signatures"][0]["sig"], "sig")
        document["signatures"][0]["sig"] = d.strict_b64encode(
            bytes([signature[0] ^ 1]) + signature[1:]
        )
        _assert_refused(
            self, d.DS_REFUSED_SIGNATURE_INVALID,
            lambda: d.verify_pae(d.encode_envelope(document), d.test_only_verifier()),
        )

    def test_pae_reserialised(self) -> None:
        canonical = b'{"a":1}'
        pretty = b'{"a": 1}'
        signed = d.envelope("t", canonical, d.test_only_signer())
        carried = dict(signed)
        carried["payload"] = d.strict_b64encode(pretty)
        _assert_refused(
            self, d.DS_REFUSED_PAE_RESERIALISED,
            lambda: d.verify_pae(d.encode_envelope(carried), d.test_only_verifier()),
        )
        # The structural rule, independent of a signature: a PAE whose body is a
        # re-encoding rather than the received bytes is refused.
        _assert_refused(
            self, d.DS_REFUSED_PAE_RESERIALISED,
            lambda: d.check_pae_body(d.pae("t", canonical), "t", pretty),
        )

    def test_pae_length(self) -> None:
        for raw in (
            b"DSSEv1 29 http://example.com/HelloWorld 12 hello world",
            b"DSSEv1 29 http://example.com/HelloWorld 10 hello world",
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world!",
            b"DSSEv1 30 http://example.com/HelloWorld 11 hello world",
            b"DSSEv1 029 http://example.com/HelloWorld 11 hello world",
        ):
            with self.subTest(raw=raw):
                _assert_refused(
                    self, d.DS_REFUSED_PAE_LENGTH, lambda: d.parse_pae(raw)
                )

    def test_payload_not_statement(self) -> None:
        raw = d.encode_envelope(
            d.envelope(d.IN_TOTO_PAYLOAD_TYPE, b'{"hello":"world"}', d.test_only_signer())
        )
        _assert_refused(
            self, d.DS_REFUSED_PAYLOAD_NOT_STATEMENT,
            lambda: d.verify_pae(
                raw, d.test_only_verifier(), require_statement=True
            ),
        )

    def test_trailing_bytes(self) -> None:
        raw = d.encode_envelope(d.envelope("t", b"{}", d.test_only_signer()))
        for suffix in (b" {}", b"null", b"\n[]", b"\x00"):
            with self.subTest(suffix=suffix):
                _assert_refused(
                    self, d.DS_REFUSED_TRAILING_BYTES,
                    lambda: d.verify_pae(raw + suffix, d.test_only_verifier()),
                )

    def test_object_supplied(self) -> None:
        raw = d.encode_envelope(d.envelope("t", b"{}", d.test_only_signer()))
        for supplied in (json.loads(raw), list(json.loads(raw).items()), raw.decode()):
            with self.subTest(kind=type(supplied).__name__):
                _assert_refused(
                    self, d.DS_REFUSED_OBJECT_SUPPLIED,
                    lambda: d.verify_pae(supplied, d.test_only_verifier()),
                )
                _assert_refused(
                    self, d.DS_REFUSED_OBJECT_SUPPLIED,
                    lambda: d.verify_received_bytes(supplied, d.test_only_verifier()),
                )


class ReceivedBytesRule(unittest.TestCase):
    def test_a_whitespace_difference_is_a_different_statement(self) -> None:
        pretty = b'{"subject": [],   "x":1}'
        canonical = b'{"subject":[],"x":1}'
        pretty_raw = d.encode_envelope(d.envelope("t", pretty, d.test_only_signer()))
        canonical_raw = d.encode_envelope(
            d.envelope("t", canonical, d.test_only_signer())
        )
        self.assertEqual(
            d.verify_pae(pretty_raw, d.test_only_verifier())["payload"], pretty
        )
        self.assertEqual(
            d.verify_pae(canonical_raw, d.test_only_verifier())["payload"], canonical
        )
        # A signature over the canonical bytes does not verify the pretty bytes.
        _assert_refused(
            self, d.DS_REFUSED_SIGNATURE_INVALID,
            lambda: d.verify_pae(
                d.encode_envelope(
                    {**d.envelope("t", canonical, d.test_only_signer()),
                     "payload": d.strict_b64encode(pretty)}
                ),
                d.test_only_verifier(),
                classify_reserialisation=False,
            ),
        )

    def test_the_payload_is_not_parsed_before_the_signature_check(self) -> None:
        payload = b"not json at all"
        raw = d.encode_envelope(d.envelope("t", payload, d.test_only_signer()))
        self.assertEqual(
            d.verify_pae(raw, d.test_only_verifier())["payload"], payload
        )

    def test_a_verified_statement_payload_is_returned_as_received(self) -> None:
        payload = (REPO_ROOT / STATEMENTS[0][1]).read_bytes()
        raw = (ENVELOPES / "a1-sarif.json").read_bytes()
        report = d.verify_pae(
            raw, d.test_only_verifier(),
            expected_payload_type=d.IN_TOTO_PAYLOAD_TYPE,
            require_statement=True,
        )
        self.assertEqual(report["payload"], payload)
        self.assertEqual(
            report["statement"]["_type"], "https://in-toto.io/Statement/v1"
        )

    def test_a_keyid_is_a_hint_and_selects_no_key(self) -> None:
        raw = d.encode_envelope(d.envelope("t", b"{}", d.test_only_signer()))
        seen = []

        def verifier(keyid: str, pae_bytes: bytes, signature: bytes) -> bool:
            seen.append(keyid)
            return True

        report = d.verify_pae(raw, verifier)
        self.assertEqual(report["keyid"], d.test_only_keyid())
        self.assertEqual(seen, [d.test_only_keyid()])
        self.assertTrue(report["keyid"].startswith("test-only:"))


class Evidence(unittest.TestCase):
    def test_the_four_envelopes_verify_and_hold_the_statement_bytes(self) -> None:
        index = _load(INDEX)
        self.assertEqual(len(index["envelopes"]), 4)
        for name, statement in STATEMENTS:
            with self.subTest(name=name):
                payload = (REPO_ROOT / statement).read_bytes()
                raw = (ENVELOPES / f"{name}.json").read_bytes()
                report = d.verify_pae(
                    raw,
                    d.test_only_verifier(),
                    expected_payload_type=d.IN_TOTO_PAYLOAD_TYPE,
                    require_statement=True,
                )
                self.assertEqual(report["payload"], payload)
                entry = next(
                    row for row in index["envelopes"] if row["name"] == name
                )
                self.assertEqual(entry["payloadSha256"], hashlib.sha256(payload).hexdigest())
                self.assertEqual(
                    entry["statementSha256"], hashlib.sha256(payload).hexdigest()
                )
                self.assertEqual(
                    entry["envelopeSha256"], hashlib.sha256(raw).hexdigest()
                )
                self.assertEqual(
                    entry["paeSha256"],
                    hashlib.sha256(d.pae(d.IN_TOTO_PAYLOAD_TYPE, payload)).hexdigest(),
                )
                self.assertEqual(entry["keyid"], d.test_only_keyid())

    def test_the_signer_is_labelled_test_only_and_is_not_a_trust_root(self) -> None:
        signer = _load(INDEX)["signer"]
        self.assertIn("test-only", signer["label"])
        self.assertEqual(signer["keyid"], d.test_only_keyid())
        self.assertEqual(bytes.fromhex(signer["seedHex"]), d.TEST_ONLY_SEED)
        joined = " ".join(signer["doesNotEstablish"]).lower()
        for word in ("authenticity", "identity", "authorisation", "transparency", "a12"):
            self.assertIn(word, joined)

    def test_the_controls_are_current_and_fire_their_codes(self) -> None:
        recorded = _load(CONTROLS)
        self.assertEqual(recorded["counts"]["codes"], len(d.REFUSALS))
        self.assertEqual(recorded["counts"]["controls"], len(recorded["controls"]))
        self.assertEqual(len(recorded["controls"]), 13)
        codes = {row["code"] for row in recorded["controls"]}
        self.assertEqual(codes, set(d.REFUSALS))
        self.assertEqual(set(recorded["codes"]), set(d.REFUSALS))

    def test_the_producer_is_deterministic_and_matches_the_committed_bytes(self) -> None:
        generated = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                result = subprocess.run(
                    [
                        sys.executable,
                        str(PRODUCER),
                        "--out",
                        str(out),
                        "--source-commit",
                        "da021a765",
                    ],
                    capture_output=True,
                    text=True,
                    cwd=REPO_ROOT,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("envelopes=4", result.stdout)
                generated.append(
                    {
                        path.relative_to(out): path.read_bytes()
                        for path in sorted(out.rglob("*"))
                        if path.is_file()
                    }
                )
        self.assertEqual(generated[0], generated[1])
        for relative, content in generated[0].items():
            with self.subTest(relative=str(relative)):
                self.assertEqual(content, (A10 / relative).read_bytes())

    def test_the_source_identity_is_supplied_not_read_live(self) -> None:
        identity = _load(INDEX)["sourceIdentity"]
        self.assertEqual(identity["commit"], "da021a765")
        self.assertEqual(len(identity["inputs"]), 6)
        for entry in identity["inputs"]:
            with self.subTest(path=entry["path"]):
                digest = hashlib.sha256(
                    (REPO_ROOT / entry["path"]).read_bytes()
                ).hexdigest()
                self.assertEqual(entry["sha256"], digest)

    def test_the_pae_vector_file_is_the_vector(self) -> None:
        self.assertEqual((A10 / "PAE-VECTOR.txt").read_text(encoding="ascii").strip(),
                         VECTOR_BYTES.hex())


class CommandLine(unittest.TestCase):
    def test_pae_prints_the_exact_bytes_and_the_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "payload.txt"
            payload.write_bytes(VECTOR_BODY)
            result = subprocess.run(
                [sys.executable, str(TOOL), "pae", VECTOR_TYPE, str(payload)],
                capture_output=True,
                cwd=REPO_ROOT,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, VECTOR_BYTES)
        self.assertIn(d.CODE_OK.encode(), result.stderr)

    def test_sign_and_verify_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "envelope.json"
            signed = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "sign",
                    STATEMENTS[0][1],
                    str(out),
                ],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
            self.assertEqual(signed.returncode, 0, signed.stderr)
            self.assertIn(d.CODE_OK, signed.stdout)
            verified = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "verify",
                    str(out),
                    "--expected-type",
                    d.IN_TOTO_PAYLOAD_TYPE,
                    "--require-statement",
                ],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn(d.CODE_OK, verified.stdout)
        self.assertIn("payloadType=" + d.IN_TOTO_PAYLOAD_TYPE, verified.stdout)

    def test_a_refusal_exits_one_and_prints_the_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "envelope.json"
            raw.write_bytes(
                d.encode_envelope(d.envelope("t", b'{"hello":1}', d.test_only_signer()))
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "verify",
                    str(raw),
                    "--require-statement",
                ],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
            missing = subprocess.run(
                [sys.executable, str(TOOL), "verify", str(Path(directory) / "no.json")],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn(d.DS_REFUSED_PAYLOAD_NOT_STATEMENT, result.stderr)
        self.assertEqual(missing.returncode, 1)
        self.assertIn(d.DS_REFUSED_ENVELOPE_INVALID, missing.stderr)

    def test_usage_errors_exit_two_and_print_a_code(self) -> None:
        for argv in (
            [sys.executable, str(TOOL)],
            [sys.executable, str(TOOL), "not-a-command"],
            [sys.executable, str(TOOL), "pae", "only-one-argument"],
        ):
            with self.subTest(argv=argv[1:]):
                result = subprocess.run(
                    argv, capture_output=True, text=True, cwd=REPO_ROOT
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn(d.CODE_USAGE, result.stderr)


class DocumentSynchronisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8") if DOCUMENT.is_file() else ""

    def test_the_document_names_every_refusal_code(self) -> None:
        for code in d.REFUSALS:
            with self.subTest(code=code):
                self.assertIn(f"`{code}`", self.text)

    def test_the_document_names_every_control(self) -> None:
        for control in _load(CONTROLS)["controls"]:
            with self.subTest(control=control["control"]):
                self.assertIn(control["control"], self.text)

    def test_the_document_names_the_implementation_tests_and_evidence(self) -> None:
        for token in (
            d.TOOL_PATH,
            "forensics/tools/tests/test_dsse.py",
            "evidence/a10/CONTROLS.json",
            "evidence/a10/ENVELOPES",
            "evidence/a10/build_evidence.py",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.text)

    def test_the_document_states_the_boundary(self) -> None:
        self.assertIn("A9", self.text)
        self.assertIn("A12", self.text)
        self.assertIn("A14", self.text)
        self.assertIn("A16", self.text)
        lowered = self.text.lower()
        self.assertIn("no trust decision", lowered)
        self.assertIn("unauthenticated hint", lowered)
        self.assertIn("test-only", lowered)
        self.assertIn("not a trust root", lowered)

    def test_the_document_states_the_received_bytes_rule(self) -> None:
        lowered = self.text.lower()
        for phrase in ("received bytes", "re-serialis", "re-encod", "whitespace"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, lowered)

    def test_the_document_declares_not_run(self) -> None:
        self.assertIn("`NOT_RUN`", self.text)
        self.assertIn("NOT_RUN", self.text)


if __name__ == "__main__":
    unittest.main()
