#!/usr/bin/env python3
"""Controls for the A9 in-toto Statement v1 attestations.

Each control exercises one rule of `docs/INTOTO-STATEMENTS.md`: a subject digest
is the content digest of the exact bytes and is recomputed; a predicate may not
assert more than the record behind it admits; and the emitted bytes must be the
canonical document this tool writes.

A control mutates a copy in memory or a temporary directory. It proves a refusal
fires, not that the substituted form occurs anywhere in the tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import intoto as t  # noqa: E402

A9 = REPO_ROOT / "evidence" / "a9"
STATEMENTS = A9 / "STATEMENTS"
INDEX = A9 / "STATEMENTS.json"
CONTROLS = A9 / "CONTROLS.json"
PRODUCER = A9 / "build_evidence.py"
TOOL = TOOLS / "intoto.py"
DOCUMENT = REPO_ROOT / "docs" / "INTOTO-STATEMENTS.md"

A1 = "evidence/a1/SARIF.json"
ADMISSION = "evidence/a5/ADMISSION.json"
DELTA = "evidence/a7/DELTA.json"
SHARD = "evidence/a8/SHARD-000.sarif"
INSTRUMENTS = "evidence/etp3/instruments.json"
SUPPRESSIONS = "evidence/a6/SUPPRESSIONS.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _a1_statement() -> dict:
    subject = t.subject_for(A1, repo_root=REPO_ROOT)
    return t.statement(
        [subject],
        t.P_SARIF_EMISSION,
        t.sarif_predicate(REPO_ROOT, A1),
    )


def _assert_refused(test: unittest.TestCase, code: str, action) -> str:
    with test.assertRaises(t.Refusal) as raised:
        action()
    test.assertEqual(raised.exception.code, code, raised.exception.message)
    return raised.exception.message


class SubjectRule(unittest.TestCase):
    def test_the_statement_type_is_exact(self) -> None:
        document = _a1_statement()
        self.assertEqual(document["_type"], t.STATEMENT_TYPE)
        self.assertEqual(document["_type"], "https://in-toto.io/Statement/v1")

    def test_a_statement_with_no_subject_is_refused(self) -> None:
        predicate = t.population_predicate(REPO_ROOT, ADMISSION, "a1-sarif-results")
        _assert_refused(
            self,
            t.IT_REFUSED_MISSING_SUBJECT,
            lambda: t.statement([], t.P_POPULATION, predicate),
        )

    def test_an_absent_subject_file_is_refused(self) -> None:
        _assert_refused(
            self,
            t.IT_REFUSED_SUBJECT_ABSENT,
            lambda: t.subject_for("evidence/a9/absent.json", repo_root=REPO_ROOT),
        )

    def test_a_git_object_id_is_not_a_content_digest(self) -> None:
        for digest in (
            {"sha256": "1efd02cbd1401c4cffb854b906c021915df94386"},
            {"sha1": "1efd02cbd1401c4cffb854b906c021915df94386"},
            {"sha256": "1efd02cbd"},
            {"sha256": "z" * 64},
            {"sha256": "A" * 64},
        ):
            with self.subTest(digest=digest):
                _assert_refused(
                    self,
                    t.IT_REFUSED_SUBJECT_DIGEST_FORM,
                    lambda digest=digest: t.statement(
                        [{"name": A1, "digest": digest}],
                        t.P_SARIF_EMISSION,
                        t.sarif_predicate(REPO_ROOT, A1),
                    ),
                )

    def test_a_duplicate_subject_is_refused(self) -> None:
        subject = t.subject_for(A1, repo_root=REPO_ROOT)
        _assert_refused(
            self,
            t.IT_REFUSED_DUPLICATE_SUBJECT,
            lambda: t.statement(
                [subject, dict(subject)],
                t.P_SARIF_EMISSION,
                t.sarif_predicate(REPO_ROOT, A1),
            ),
        )

    def test_subject_for_reads_the_bytes(self) -> None:
        subject = t.subject_for(A1, repo_root=REPO_ROOT)
        expected = hashlib.sha256((REPO_ROOT / A1).read_bytes()).hexdigest()
        self.assertEqual(subject["digest"]["sha256"], expected)
        self.assertEqual(subject["name"], A1)

    def test_subject_for_has_no_caller_supplied_digest(self) -> None:
        parameters = inspect.signature(t.subject_for).parameters
        self.assertNotIn("digest", parameters)
        self.assertNotIn("sha256", parameters)

    def test_a_caller_supplied_digest_is_refused_when_it_disagrees(self) -> None:
        message = _assert_refused(
            self,
            t.IT_REFUSED_SUBJECT_DIGEST_MISMATCH,
            lambda: t.verify_subject(
                {"name": A1, "digest": {"sha256": "0" * 64}}, REPO_ROOT
            ),
        )
        self.assertIn(hashlib.sha256((REPO_ROOT / A1).read_bytes()).hexdigest(), message)

    def test_a_missing_file_is_not_skipped_on_verification(self) -> None:
        document = _a1_statement()
        document["subject"][0]["name"] = "evidence/a9/absent.json"
        _assert_refused(
            self,
            t.IT_REFUSED_SUBJECT_ABSENT,
            lambda: t.verify_subject_files(document, REPO_ROOT),
        )


class PredicateRegistry(unittest.TestCase):
    def test_every_registered_type_declares_required_and_forbidden(self) -> None:
        self.assertGreaterEqual(len(t.PREDICATES), 4)
        for kind, entry in t.PREDICATES.items():
            with self.subTest(kind=kind):
                self.assertTrue(entry["required"])
                self.assertTrue(entry["forbidden"])
                self.assertTrue(entry["carries"])
                self.assertEqual(
                    set(entry["required"]) & set(entry["forbidden"]), set()
                )

    def test_all_four_required_predicate_types_are_registered(self) -> None:
        self.assertIn(t.P_POPULATION, t.PREDICATES)
        self.assertIn(t.P_BASELINE_DELTA, t.PREDICATES)
        self.assertIn(t.P_SARIF_EMISSION, t.PREDICATES)
        self.assertIn(t.P_INSTRUMENT, t.PREDICATES)

    def test_an_unknown_predicate_type_is_refused(self) -> None:
        subject = t.subject_for(A1, repo_root=REPO_ROOT)
        _assert_refused(
            self,
            t.IT_REFUSED_PREDICATE_TYPE,
            lambda: t.statement(
                [subject],
                "https://openssl-rs.invalid/attestation/unknown/v1",
                t.sarif_predicate(REPO_ROOT, A1),
            ),
        )

    def test_a_slsa_predicate_type_is_refused_not_borrowed(self) -> None:
        subject = t.subject_for(A1, repo_root=REPO_ROOT)
        _assert_refused(
            self,
            t.IT_REFUSED_PREDICATE_TYPE,
            lambda: t.statement(
                [subject],
                "https://slsa.dev/provenance/v1",
                t.sarif_predicate(REPO_ROOT, A1),
            ),
        )

    def test_a_missing_required_field_is_refused(self) -> None:
        subject = t.subject_for(A1, repo_root=REPO_ROOT)
        predicate = t.population_predicate(REPO_ROOT, ADMISSION, "a1-sarif-results")
        _assert_refused(
            self,
            t.IT_REFUSED_PREDICATE_FIELD,
            lambda: t.statement(
                [subject],
                t.P_POPULATION,
                {key: value for key, value in predicate.items() if key != "record"},
            ),
        )

    def test_a_forbidden_field_is_refused(self) -> None:
        subject = t.subject_for(A1, repo_root=REPO_ROOT)
        predicate = {
            **t.sarif_predicate(REPO_ROOT, A1),
            "suppressions": [],
        }
        _assert_refused(
            self,
            t.IT_REFUSED_PREDICATE_FIELD,
            lambda: t.statement([subject], t.P_SARIF_EMISSION, predicate),
        )

    def test_the_record_must_be_a_subject(self) -> None:
        subject = t.subject_for(A1, repo_root=REPO_ROOT)
        _assert_refused(
            self,
            t.IT_REFUSED_SUBJECT_DIGEST_MISMATCH,
            lambda: t.statement(
                [subject],
                t.P_SARIF_EMISSION,
                t.sarif_predicate(REPO_ROOT, SHARD),
            ),
        )

    def test_the_record_digest_must_equal_the_subject_digest(self) -> None:
        subject = t.subject_for(A1, repo_root=REPO_ROOT)
        predicate = {
            **t.sarif_predicate(REPO_ROOT, A1),
            "record": {"path": A1, "sha256": "0" * 64},
        }
        _assert_refused(
            self,
            t.IT_REFUSED_SUBJECT_DIGEST_MISMATCH,
            lambda: t.statement([subject], t.P_SARIF_EMISSION, predicate),
        )


class NoUpgrade(unittest.TestCase):
    def test_complete_over_truncated_is_refused(self) -> None:
        _assert_refused(
            self,
            t.IT_REFUSED_CLAIM_UPGRADE,
            lambda: t.population_predicate(
                REPO_ROOT, ADMISSION, "curl-residual-sites", {"state": "COMPLETE"}
            ),
        )

    def test_resolved_over_none_is_refused(self) -> None:
        facts = t.delta_facts(REPO_ROOT, DELTA, "a3-fingerprint-migration")
        self.assertEqual(facts["resolved"], 0)
        _assert_refused(
            self,
            t.IT_REFUSED_CLAIM_UPGRADE,
            lambda: t.delta_predicate(
                REPO_ROOT,
                DELTA,
                "a3-fingerprint-migration",
                {
                    "resolved": 1,
                    "dispositions": {**facts["dispositions"], "RESOLVED": 1},
                },
            ),
        )

    def test_a_census_over_an_aggregate_is_refused(self) -> None:
        facts = t.population_entry(REPO_ROOT, ADMISSION, "t4-suppressions")
        self.assertEqual(facts["state"], "AGGREGATE_ONLY")
        self.assertFalse(facts["membersRecorded"])
        _assert_refused(
            self,
            t.IT_REFUSED_CLAIM_UPGRADE,
            lambda: t.check_population({**facts, "census": True}, facts),
        )

    def test_a_verified_instrument_over_recorded_is_refused(self) -> None:
        facts = t.instrument_facts(REPO_ROOT, INSTRUMENTS, "timecop-supercop")
        self.assertEqual(facts["status"], "RECORDED")
        _assert_refused(
            self,
            t.IT_REFUSED_CLAIM_UPGRADE,
            lambda: t.instrument_predicate(
                REPO_ROOT,
                INSTRUMENTS,
                "timecop-supercop",
                {"status": "PASS", "verified": True},
            ),
        )

    def test_an_expiry_free_active_suppression_is_refused(self) -> None:
        _assert_refused(
            self,
            t.IT_REFUSED_CLAIM_UPGRADE,
            lambda: t.suppression_predicate(
                REPO_ROOT,
                SUPPRESSIONS,
                "t4-suppressions",
                {"disposition": "ACTIVE", "expiry": None},
            ),
        )

    def test_an_evidence_identity_without_a_digest_is_refused(self) -> None:
        subject = t.subject_for(A1, repo_root=REPO_ROOT)
        predicate = {
            **t.sarif_predicate(REPO_ROOT, A1),
            "evidence": [{"path": A1}],
        }
        _assert_refused(
            self,
            t.IT_REFUSED_CLAIM_UPGRADE,
            lambda: t.statement([subject], t.P_SARIF_EMISSION, predicate),
        )

    def test_an_unknown_population_cannot_be_attested(self) -> None:
        _assert_refused(
            self,
            t.IT_REFUSED_CLAIM_UPGRADE,
            lambda: t.population_predicate(
                REPO_ROOT, ADMISSION, "o11-interop-scripts"
            ),
        )

    def test_an_inadmissible_population_is_refused(self) -> None:
        _assert_refused(
            self,
            t.IT_REFUSED_RECORD_INADMISSIBLE,
            lambda: t.population_predicate(
                REPO_ROOT, ADMISSION, "t4-suppressions"
            ),
        )

    def test_a_refused_delta_cannot_be_admitted(self) -> None:
        facts = t.delta_facts(REPO_ROOT, DELTA, "claims-reconciliation")
        self.assertFalse(facts["admitted"])
        self.assertTrue(facts["codes"])
        _assert_refused(
            self,
            t.IT_REFUSED_CLAIM_UPGRADE,
            lambda: t.delta_predicate(
                REPO_ROOT, DELTA, "claims-reconciliation", {"admitted": True}
            ),
        )


class Encoding(unittest.TestCase):
    def test_the_canonical_form_is_sorted_and_compact(self) -> None:
        text = t.encode(_a1_statement())
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text.count("\n"), 1)
        self.assertNotIn(": ", text)
        self.assertNotIn(", ", text)
        parsed = json.loads(text)
        self.assertEqual(
            text,
            json.dumps(
                parsed,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n",
        )

    def test_encode_decode_round_trip(self) -> None:
        document = _a1_statement()
        text = t.encode(document)
        self.assertEqual(t.decode(text), document)
        self.assertEqual(t.decode(text.encode("utf-8")), document)

    def test_one_byte_mutation_is_refused(self) -> None:
        text = t.encode(_a1_statement())
        _assert_refused(
            self,
            t.IT_REFUSED_STATEMENT_MUTATED,
            lambda: t.decode(text[:-1]),
        )
        _assert_refused(
            self,
            t.IT_REFUSED_STATEMENT_MUTATED,
            lambda: t.decode(text.replace(",", ", ", 1)),
        )

    def test_a_non_canonical_reordering_is_refused(self) -> None:
        document = _a1_statement()
        pretty = json.dumps(document, indent=1, sort_keys=True) + "\n"
        _assert_refused(
            self,
            t.IT_REFUSED_STATEMENT_MUTATED,
            lambda: t.decode(pretty),
        )

    def test_a_wrong_type_is_refused(self) -> None:
        document = {**_a1_statement(), "_type": "https://in-toto.io/Statement/v0.1"}
        _assert_refused(
            self,
            t.IT_REFUSED_TYPE,
            lambda: t.decode(t._canonical_text(document)),
        )

    def test_verification_recomputes_the_subject_digest(self) -> None:
        document = _a1_statement()
        forged = "0" * 64
        document["subject"][0]["digest"]["sha256"] = forged
        document["predicate"]["record"]["sha256"] = forged
        text = t._canonical_text(document)
        _assert_refused(
            self,
            t.IT_REFUSED_SUBJECT_DIGEST_MISMATCH,
            lambda: t.verify_statement(text, REPO_ROOT),
        )


class RealStatements(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = _load(INDEX)

    def test_the_four_statements_exist_and_verify(self) -> None:
        self.assertEqual(len(self.index["statements"]), 4)
        for entry in self.index["statements"]:
            with self.subTest(statement=entry["statement"]):
                path = A9 / entry["statement"]
                self.assertTrue(path.is_file())
                report = t.verify_statement(path.read_bytes(), REPO_ROOT)
                self.assertEqual(report["subject"], entry["subject"])
                self.assertEqual(report["sha256"], entry["digest"]["sha256"])

    def test_the_index_matches_the_statement_bytes(self) -> None:
        for entry in self.index["statements"]:
            with self.subTest(statement=entry["statement"]):
                raw = (A9 / entry["statement"]).read_bytes()
                self.assertEqual(
                    hashlib.sha256(raw).hexdigest(), entry["statementSha256"]
                )
                document = t.decode(raw)
                self.assertEqual(document["subject"][0]["name"], entry["subject"])
                self.assertEqual(
                    document["subject"][0]["digest"], entry["digest"]
                )
                self.assertEqual(
                    document["predicateType"], entry["predicateType"]
                )

    def test_each_asserted_state_is_the_record_state(self) -> None:
        for entry in self.index["statements"]:
            with self.subTest(statement=entry["statement"]):
                self.assertEqual(entry["assertedState"], entry["recordState"])
                self.assertEqual(entry["relation"], "equal")

    def test_the_shard_is_not_presented_as_the_parent(self) -> None:
        shard = next(
            entry
            for entry in self.index["statements"]
            if entry["subject"] == SHARD
        )
        self.assertIs(shard["assertedState"]["subset"], True)
        self.assertEqual(shard["assertedState"]["parentResultCount"], 4245)
        document = t.decode((A9 / shard["statement"]).read_bytes())
        self.assertIs(document["predicate"]["subset"], True)

    def test_the_a7_statement_names_zero_resolutions(self) -> None:
        delta = next(
            entry for entry in self.index["statements"] if entry["subject"] == DELTA
        )
        self.assertEqual(delta["assertedState"]["resolved"], 0)
        self.assertIs(delta["assertedState"]["admitted"], True)

    def test_the_not_attested_list_names_real_refusals(self) -> None:
        refused = self.index["notAttested"]
        self.assertEqual(len(refused), 7)
        for entry in refused:
            with self.subTest(record=entry["record"], select=entry["select"]):
                self.assertIn(entry["code"], t.REFUSALS)
        self.assertEqual(
            {entry["code"] for entry in refused},
            {
                t.IT_REFUSED_RECORD_INADMISSIBLE,
                t.IT_REFUSED_CLAIM_UPGRADE,
            },
        )


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controls = t.build_controls(REPO_ROOT)

    def test_every_control_fires_its_named_code(self) -> None:
        for control in self.controls:
            with self.subTest(control=control["control"]):
                self.assertEqual(control["observed"], control["code"])

    def test_every_refusal_code_has_a_control(self) -> None:
        covered = {control["code"] for control in self.controls}
        self.assertEqual(covered, set(t.REFUSALS))
        names = {control["control"] for control in self.controls}
        self.assertEqual(len(names), len(self.controls))
        self.assertGreaterEqual(len(self.controls), len(t.REFUSALS))

    def test_each_upgrade_has_its_own_control(self) -> None:
        names = {control["control"] for control in self.controls}
        for name in (
            "complete-over-truncated",
            "resolved-over-none",
            "census-over-aggregate",
            "verified-over-recorded",
            "expiry-free-suppression",
            "evidence-without-digest",
        ):
            self.assertIn(name, names)

    def test_the_recorded_controls_are_current(self) -> None:
        recorded = _load(CONTROLS)
        self.assertEqual(recorded["schema"], t.CONTROLS_SCHEMA)
        self.assertEqual(len(recorded["controls"]), len(self.controls))
        self.assertEqual(
            [control["control"] for control in recorded["controls"]],
            [control["control"] for control in self.controls],
        )
        self.assertEqual(set(recorded["codes"]), set(t.REFUSALS))
        self.assertEqual(recorded["statementType"], t.STATEMENT_TYPE)
        self.assertEqual(set(recorded["predicateTypes"]), set(t.PREDICATES))


class Producer(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.commit = _load(INDEX)["sourceIdentity"]["commit"]

    @staticmethod
    def _producer_module():
        import importlib.util

        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            spec = importlib.util.spec_from_file_location("a9_producer", PRODUCER)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        finally:
            sys.dont_write_bytecode = previous
        return module

    def test_the_producer_is_deterministic(self) -> None:
        module = self._producer_module()
        first = module.build(REPO_ROOT, self.commit)
        second = module.build(REPO_ROOT, self.commit)
        self.assertEqual(first, second)

    def test_the_committed_files_match_a_fresh_build(self) -> None:
        built = self._producer_module().build(REPO_ROOT, self.commit)
        for relative, text in built.items():
            with self.subTest(file=relative):
                self.assertEqual(
                    (A9 / relative).read_text(encoding="utf-8"), text
                )

    def test_the_source_identity_is_supplied_not_read_live(self) -> None:
        self.assertEqual(self.commit, "f1c5047a5")
        index = _load(INDEX)
        self.assertEqual(index["sourceIdentity"]["commit"], "f1c5047a5")
        self.assertEqual(len(index["sourceIdentity"]["inputs"]), 7)
        for entry in index["sourceIdentity"]["inputs"]:
            with self.subTest(input=entry["path"]):
                digest = hashlib.sha256(
                    (REPO_ROOT / entry["path"]).read_bytes()
                ).hexdigest()
                self.assertEqual(entry["sha256"], digest)

    def test_the_producer_refuses_an_absent_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    sys.executable,
                    str(PRODUCER),
                    "--repo-root",
                    directory,
                    "--out",
                    directory,
                    "--source-commit",
                    self.commit,
                ],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn(t.IT_REFUSED_RECORD_ABSENT, result.stderr)


class CommandLine(unittest.TestCase):
    def test_subjects_reports_the_content_digest(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "subjects", A1],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(t.CODE_OK, result.stdout)
        expected = hashlib.sha256((REPO_ROOT / A1).read_bytes()).hexdigest()
        self.assertIn(expected, result.stdout)

    def test_subjects_refuses_a_missing_file(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "subjects", "evidence/a9/absent.json"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(t.IT_REFUSED_SUBJECT_ABSENT, result.stderr)

    def test_emit_and_verify_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "statement.json"
            emitted = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "emit",
                    "sarif-emission",
                    str(out),
                    "--subject",
                    A1,
                ],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
            self.assertEqual(emitted.returncode, 0, emitted.stderr)
            self.assertIn(t.CODE_OK, emitted.stdout)
            verified = subprocess.run(
                [sys.executable, str(TOOL), "verify", str(out)],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn(t.CODE_OK, verified.stdout)
            self.assertIn(A1, verified.stdout)

    def test_a_refusal_exits_one_and_prints_the_code(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "emit",
                "population",
                "/tmp/a9-refused.json",
                "--select",
                "no-such-population",
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(t.IT_REFUSED_RECORD_INADMISSIBLE, result.stderr)

    def test_verify_refuses_a_mutated_statement(self) -> None:
        text = t.encode(_a1_statement()).replace(",", ", ", 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutated.json"
            path.write_text(text, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(TOOL), "verify", str(path)],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn(t.IT_REFUSED_STATEMENT_MUTATED, result.stderr)

    def test_usage_errors_exit_two_and_print_a_code(self) -> None:
        for argv in (
            [sys.executable, str(TOOL)],
            [sys.executable, str(TOOL), "emit", "not-a-predicate", "/tmp/x.json"],
        ):
            with self.subTest(argv=argv[1:]):
                result = subprocess.run(
                    argv, capture_output=True, text=True, cwd=REPO_ROOT
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn(t.CODE_USAGE, result.stderr)


class DocumentSynchronisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8") if DOCUMENT.is_file() else ""

    def test_the_document_names_every_refusal_code(self) -> None:
        for code in t.REFUSALS:
            with self.subTest(code=code):
                self.assertIn(code, self.text)

    def test_the_document_names_every_predicate_type(self) -> None:
        for kind in t.PREDICATES:
            with self.subTest(kind=kind):
                self.assertIn(kind, self.text)

    def test_the_document_names_every_control(self) -> None:
        for control in t.build_controls(REPO_ROOT):
            with self.subTest(control=control["control"]):
                self.assertIn(control["control"], self.text)

    def test_the_document_names_the_implementation_and_controls(self) -> None:
        self.assertIn(t.TOOL_PATH, self.text)
        self.assertIn("forensics/tools/tests/test_intoto.py", self.text)
        self.assertIn("evidence/a9/CONTROLS.json", self.text)
        self.assertIn("evidence/a9/STATEMENTS", self.text)

    def test_the_document_states_the_a10_boundary(self) -> None:
        self.assertIn("A10", self.text)
        self.assertIn("DSSE", self.text)
        self.assertIn("PAE", self.text)
        self.assertIn("not a signed attestation", self.text.lower())

    def test_the_document_states_the_no_upgrade_rule(self) -> None:
        lowered = self.text.lower()
        for phrase in (
            "truncated_bounded",
            "resolved",
            "aggregate_only",
            "recorded",
            "expiry",
            "evidence identity",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, lowered)

    def test_every_rule_names_a_code_or_a_test(self) -> None:
        for code in t.REFUSALS:
            with self.subTest(code=code):
                self.assertIn(f"`{code}`", self.text)
        self.assertIn("test_", self.text)


if __name__ == "__main__":
    unittest.main()
