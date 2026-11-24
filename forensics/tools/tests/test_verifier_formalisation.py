#!/usr/bin/env python3
"""Controls for forensics/tools/verifier_formalisation.py and the A23 records.

The reference evaluator must not import the implementation (a structural test),
every declared domain must be enumerated at its exact size, the differential must
find no disagreement, every invariant must hold, every refusal code must fire,
a deliberately wrong reference must be detected, and the document must name every
rule and every code.

Run directly (`python3 forensics/tools/tests/test_verifier_formalisation.py`) or
with `python3 -m unittest discover -s forensics/tools/tests`.
"""

from __future__ import annotations

import contextlib
import importlib  # noqa: F401  (kept for parity with the sibling suites)
import inspect
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import verifier_formalisation as vf  # noqa: E402

TOOL = TOOLS / "verifier_formalisation.py"
DOCUMENT = REPO / "docs/VERIFIER-FORMALISATION.md"
EVIDENCE = REPO / "evidence/a23"
PRODUCER = EVIDENCE / "build_evidence.py"

SMALL = 585
POLICY = 65536
THRESHOLD = 9100
CORRECTION = 386


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


class Structure(unittest.TestCase):
    """The reference is independent, the specification is present, the sizes are exact."""

    def test_reference_does_not_import_an_implementation(self) -> None:
        for name in ("policy_engine", "thresholds", "corrections"):
            self.assertNotIn(
                name,
                vf.reference_decide.__globals__,
                f"reference_decide resolves {name} through its globals",
            )
            self.assertNotIn(
                name,
                vf.reference_threshold_count.__globals__,
                f"reference_threshold_count resolves {name}",
            )
            self.assertNotIn(
                name,
                vf.reference_chain_admissible.__globals__,
                f"reference_chain_admissible resolves {name}",
            )
        source = Path(vf.__file__).read_text(encoding="utf-8")
        self.assertTrue(source)
        for function in (
            vf.reference_decide,
            vf.reference_threshold_count,
            vf.reference_chain_admissible,
        ):
            body = inspect.getsource(function)
            self.assertNotIn("import policy_engine", body)
            self.assertNotIn("import thresholds", body)
            self.assertNotIn("import corrections", body)

    def test_the_import_refusal_fires_on_a_stub(self) -> None:
        stub = vf._stub_reference_importing_implementation()
        with self.assertRaises(vf.Refusal) as raised:
            vf.assert_reference_independent(stub)
        self.assertEqual(raised.exception.code, "VF_REFUSED_REFERENCE_IMPORTS_IMPLEMENTATION")

    def test_an_independent_reference_passes_the_check(self) -> None:
        vf.assert_reference_independent(vf.reference_decide)

    def test_spec_is_present_and_hashed(self) -> None:
        spec = vf.load_spec()
        self.assertEqual(spec["schema"], vf.SCHEMA_SPEC)
        self.assertEqual(spec["digest"], vf.spec_digest(spec))
        self.assertEqual(len(spec["rules"]), 9)
        threshold = spec["threshold"]
        self.assertEqual(list(threshold["requiredRoles"]), list(vf.THRESHOLD_REQUIRED_ROLES))
        self.assertEqual(threshold["artefactDigest"], vf.THRESHOLD_ARTEFACT_DIGEST)
        self.assertEqual(threshold["moment"], vf.THRESHOLD_MOMENT)
        self.assertEqual(threshold["catalogueSize"], vf.THRESHOLD_CATALOGUE_SIZE)
        self.assertEqual(threshold["maxApprovals"], vf.THRESHOLD_MAX_APPROVALS)

    def test_domain_sizes_are_exact(self) -> None:
        self.assertEqual(vf.domain_size(8), POLICY)
        self.assertEqual(vf.small_decision_domain_size(), SMALL)
        self.assertEqual(vf.threshold_domain_size(), THRESHOLD)
        self.assertEqual(vf.correction_domain_size(), CORRECTION)
        self.assertEqual(vf.domain_size(0), 1)

    def test_the_spec_records_the_same_domain_sizes(self) -> None:
        domains = vf.load_spec()["domains"]
        self.assertEqual(domains["decision-small"], SMALL)
        self.assertEqual(domains["decision-policy"], POLICY)
        self.assertEqual(domains["threshold"], THRESHOLD)
        self.assertEqual(domains["correction"], CORRECTION)

    def test_enumerate_domain_yields_every_vector(self) -> None:
        for size in range(4):
            self.assertEqual(len(list(vf.enumerate_domain(size))), 4**size)

    def test_domain_size_rejects_a_negative_count(self) -> None:
        with self.assertRaises(vf.Refusal) as raised:
            vf.domain_size(-1)
        self.assertEqual(raised.exception.code, "VF_REFUSED_UNSPECIFIED_RULE")


class Differential(unittest.TestCase):
    """The implementation and the reference agree over every declared domain."""

    def test_decision_differential_small_domain(self) -> None:
        record = vf._small_decision_differential(declared_size=SMALL)
        self.assertEqual(record["compared"], SMALL)
        self.assertEqual(record["disagreements"], [])
        public = vf.differential(2, declared_size=64)
        self.assertEqual(public["compared"], 64)
        self.assertEqual(public["disagreements"], [])

    def test_decision_differential_real_policy(self) -> None:
        record = vf._decision_differential(
            vf.DECISION_POLICY_OBLIGATIONS,
            [[True] * vf.DECISION_POLICY_OBLIGATIONS],
            declared_size=POLICY,
        )
        self.assertEqual(record["compared"], POLICY)
        self.assertEqual(record["disagreements"], [])

    def test_threshold_differential(self) -> None:
        record = vf.threshold_differential(declared_size=THRESHOLD)
        self.assertEqual(record["compared"], THRESHOLD)
        self.assertEqual(record["disagreements"], [])

    def test_correction_differential(self) -> None:
        record = vf.correction_differential(declared_size=CORRECTION)
        self.assertEqual(record["compared"], CORRECTION)
        self.assertEqual(record["disagreements"], [])

    def test_a_disagreement_is_a_counterexample(self) -> None:
        record = vf._decision_differential(
            2, [[True, True]], reference=vf.wrong_reference_unknown_as_met
        )
        self.assertTrue(record["disagreements"])
        first = record["disagreements"][0]
        self.assertIn("states", first)
        self.assertIn("implementation", first)
        self.assertIn("reference", first)
        self.assertIn("rule", first)
        self.assertNotEqual(first["implementation"], first["reference"])
        with self.assertRaises(vf.Refusal) as raised:
            vf.assert_agreement(record, domain="a control")
        self.assertEqual(raised.exception.code, "VF_REFUSED_DISAGREEMENT")

    def test_the_counterexample_is_the_exact_input(self) -> None:
        record = vf._decision_differential(
            2, [[True, True]], reference=vf.wrong_reference_unknown_as_met
        )
        witness = record["disagreements"][0]
        states = tuple(witness["states"])
        required = tuple(witness["required"])
        self.assertEqual(
            vf.wrong_reference_unknown_as_met(states, required), witness["reference"]
        )
        self.assertEqual(vf.implementation_decide(states, required), witness["implementation"])
        self.assertNotEqual(witness["implementation"], witness["reference"])


class Properties(unittest.TestCase):
    """Each stated invariant holds over its stated domain."""

    def check(self, identifier: str, size: int = 2, required: Any = None) -> None:
        record = vf.properties(size, required)
        row = next(item for item in record["properties"] if item["id"] == identifier)
        self.assertEqual(row["implementation"], "PASS", row)
        self.assertEqual(row["reference"], "PASS", row)

    def test_property_determinism(self) -> None:
        self.check("VF-P1", 2, [True, True])

    def test_property_adding_a_met_obligation(self) -> None:
        self.check("VF-P2", 2, [True, False])

    def test_property_adding_a_required_unmet(self) -> None:
        self.check("VF-P3", 2, [True, True])

    def test_property_unknown_never_admits(self) -> None:
        self.check("VF-P4", 2, [True, False])

    def test_property_required_inapplicable_denies(self) -> None:
        self.check("VF-P5", 2, [True, True])

    def test_property_canonical_order_independence(self) -> None:
        self.check("VF-P6", 3, None)

    def test_property_no_numeric_score(self) -> None:
        self.check("VF-P7", 2, [True, False])

    def test_every_property_holds_over_the_full_small_domain(self) -> None:
        record = vf.properties(vf.DECISION_SMALL_OBLIGATIONS, None)
        self.assertEqual(record["domain"], "4**3 = 64 state vectors x 8 required mask(s) = 512 cases")
        self.assertTrue(record["allHold"])
        self.assertEqual(len(record["properties"]), 7)
        vf.assert_properties(record)

    def test_a_wrong_reference_violates_a_property(self) -> None:
        record = vf.properties(2, [True, True], reference=vf.wrong_reference_unknown_as_met)
        self.assertFalse(record["allHold"])
        with self.assertRaises(vf.Refusal) as raised:
            vf.assert_properties(record)
        self.assertEqual(raised.exception.code, "VF_REFUSED_PROPERTY_VIOLATED")


class Refusals(unittest.TestCase):
    """One control per stable refusal code."""

    def test_refused_disagreement(self) -> None:
        record = vf._decision_differential(
            2, [[True, True]], reference=vf.wrong_reference_not_applicable_as_met
        )
        with self.assertRaises(vf.Refusal) as raised:
            vf.assert_agreement(record)
        self.assertEqual(raised.exception.code, "VF_REFUSED_DISAGREEMENT")

    def test_refused_domain_incomplete(self) -> None:
        with self.assertRaises(vf.Refusal) as raised:
            vf._decision_differential(2, [[True, True]], declared_size=3)
        self.assertEqual(raised.exception.code, "VF_REFUSED_DOMAIN_INCOMPLETE")

    def test_refused_reference_imports_implementation(self) -> None:
        with self.assertRaises(vf.Refusal) as raised:
            vf.assert_reference_independent(vf._stub_reference_importing_implementation())
        self.assertEqual(raised.exception.code, "VF_REFUSED_REFERENCE_IMPORTS_IMPLEMENTATION")

    def test_refused_property_violated(self) -> None:
        record = vf.properties(2, [True, True], reference=vf.wrong_reference_unknown_as_met)
        with self.assertRaises(vf.Refusal) as raised:
            vf.assert_properties(record)
        self.assertEqual(raised.exception.code, "VF_REFUSED_PROPERTY_VIOLATED")

    def test_refused_spec_absent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(vf.Refusal) as raised:
                vf.load_spec(Path(directory) / "SPEC.json")
        self.assertEqual(raised.exception.code, "VF_REFUSED_SPEC_ABSENT")

    def test_refused_spec_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SPEC.json"
            spec = load_json(EVIDENCE / "SPEC.json")
            spec["decision"]["minimumRequired"] = 9
            path.write_text(json.dumps(spec), encoding="utf-8")
            with self.assertRaises(vf.Refusal) as raised:
                vf.load_spec(path)
        self.assertEqual(raised.exception.code, "VF_REFUSED_SPEC_ABSENT")

    def test_refused_unspecified_rule(self) -> None:
        with self.assertRaises(vf.Refusal) as raised:
            vf.reference_decide(("MAYBE",), (True,))
        self.assertEqual(raised.exception.code, "VF_REFUSED_UNSPECIFIED_RULE")

    def test_refused_unspecified_length(self) -> None:
        with self.assertRaises(vf.Refusal) as raised:
            vf.reference_decide(("MET", "UNMET"), (True,))
        self.assertEqual(raised.exception.code, "VF_REFUSED_UNSPECIFIED_RULE")

    def test_refused_enumeration_truncated(self) -> None:
        with self.assertRaises(vf.Refusal) as raised:
            vf._decision_differential(3, [[True] * 3], limit=10)
        self.assertEqual(raised.exception.code, "VF_REFUSED_ENUMERATION_TRUNCATED")

    def test_every_code_has_a_control(self) -> None:
        rows = vf.controls()
        covered = {row["expectedCode"] for row in rows}
        self.assertEqual(covered, set(vf.REFUSAL_CODES))
        for row in rows:
            self.assertTrue(row["controlOnly"])
            self.assertEqual(row["observedCode"], row["expectedCode"], row)
        vf.assert_controls(rows)


class Records(unittest.TestCase):
    """The committed records say what this run says."""

    def test_spec_digest_matches(self) -> None:
        spec = load_json(EVIDENCE / "SPEC.json")
        self.assertEqual(spec["digest"], vf.spec_digest(spec))

    def test_the_spec_names_every_correction_rule_the_reference_uses(self) -> None:
        spec = load_json(EVIDENCE / "SPEC.json")
        ids = {rule["id"] for rule in spec["correction"]["rules"]}
        self.assertEqual(ids, set(vf.COUNTEREXAMPLES))

    def test_differential_record(self) -> None:
        record = load_json(EVIDENCE / "DIFFERENTIAL.json")
        self.assertEqual(record["code"], "VF_OK")
        self.assertEqual(record["disagreements"], 0)
        sizes = {domain["id"]: (domain["declaredSize"], domain["compared"]) for domain in record["domains"]}
        self.assertEqual(sizes["decision-small"], (SMALL, SMALL))
        self.assertEqual(sizes["decision-policy"], (POLICY, POLICY))
        self.assertEqual(sizes["threshold"], (THRESHOLD, THRESHOLD))
        self.assertEqual(sizes["correction"], (CORRECTION, CORRECTION))
        self.assertEqual(record["compared"], SMALL + POLICY + THRESHOLD + CORRECTION)

    def test_properties_record(self) -> None:
        record = load_json(EVIDENCE / "PROPERTIES.json")
        self.assertEqual(record["code"], "VF_OK")
        self.assertTrue(record["allHold"])
        self.assertEqual(len(record["properties"]), 7)

    def test_controls_record(self) -> None:
        record = load_json(EVIDENCE / "CONTROLS.json")
        self.assertEqual(record["code"], "VF_OK")
        self.assertTrue(record["coversEveryCode"])
        self.assertEqual(set(record["codesCovered"]), set(vf.REFUSAL_CODES))
        self.assertTrue(all(row["controlOnly"] for row in record["controls"]))

    def test_the_producer_is_byte_identical_and_reproduces_the_records(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for out in (first, second):
                result = subprocess.run(
                    [sys.executable, str(PRODUCER), "--out", out],
                    cwd=REPO,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in ("SPEC.json", "DIFFERENTIAL.json", "PROPERTIES.json", "CONTROLS.json"):
                a = (Path(first) / name).read_bytes()
                b = (Path(second) / name).read_bytes()
                committed = (EVIDENCE / name).read_bytes()
                self.assertEqual(a, b, f"{name} differs between two runs")
                self.assertEqual(a, committed, f"{name} differs from the committed record")


class CommandLine(unittest.TestCase):
    """Exit 0 on agreement, 1 on a refusal, 2 on usage, and the code is always printed."""

    def run_tool(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=600,
        )

    def test_spec_exits_zero(self) -> None:
        result = self.run_tool("spec")
        self.assertEqual(result.returncode, 0)
        self.assertIn("vf: codes=VF_OK", result.stdout)
        self.assertIn("vf: rule VF-R9", result.stdout)

    def test_controls_exits_zero(self) -> None:
        result = self.run_tool("controls")
        self.assertEqual(result.returncode, 0)
        self.assertIn("vf: codes=VF_OK", result.stdout)
        self.assertIn("vf: controls=10", result.stdout)

    def test_differential_exits_zero_and_enumerates_the_real_policy(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = vf.main(["differential"])
        output = buffer.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("declared=65536 compared=65536 disagreements=0", output)
        self.assertIn("disagreements=0", output)
        self.assertIn("vf: codes=VF_OK", output)

    def test_properties_exits_zero(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = vf.main(["properties"])
        output = buffer.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("allHold=true", output)
        self.assertIn("vf: codes=VF_OK", output)

    def test_usage_exits_two_with_a_code(self) -> None:
        result = self.run_tool()
        self.assertEqual(result.returncode, 2)
        self.assertIn("vf: codes=VF_USAGE", result.stdout)
        unknown = self.run_tool("nonsense")
        self.assertEqual(unknown.returncode, 2)
        self.assertIn("vf: codes=VF_USAGE", unknown.stdout)

    def test_a_refusal_exits_one_with_its_code(self) -> None:
        original = vf.SPEC_PATH
        vf.SPEC_PATH = REPO / "evidence/a23/SPEC-ABSENT.json"
        vf._SPEC_CACHE.clear()
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                code = vf.main(["spec"])
        finally:
            vf.SPEC_PATH = original
            vf._SPEC_CACHE.clear()
        self.assertEqual(code, 1)
        self.assertIn("vf: codes=VF_REFUSED_SPEC_ABSENT", buffer.getvalue())


class Document(unittest.TestCase):
    """The document names every rule, every code and every domain size."""

    def setUp(self) -> None:
        self.assertTrue(DOCUMENT.is_file(), f"{DOCUMENT} is absent")
        self.text = DOCUMENT.read_text(encoding="utf-8")

    def test_every_refusal_code_is_named(self) -> None:
        for code in vf.REFUSAL_CODES:
            self.assertIn(code, self.text, f"the document does not name {code}")

    def test_every_rule_is_named(self) -> None:
        spec = load_json(EVIDENCE / "SPEC.json")
        for rule in spec["rules"]:
            self.assertIn(rule["id"], self.text, f"the document does not name {rule['id']}")
        for rule in spec["correction"]["rules"]:
            self.assertIn(rule["id"], self.text, f"the document does not name {rule['id']}")

    def test_every_domain_size_is_stated(self) -> None:
        for fragment in ("65,536", "9,100", "585", "386", "75,607"):
            self.assertIn(fragment, self.text, f"the document does not state {fragment}")

    def test_the_limits_are_stated(self) -> None:
        for fragment in ("Article 5", "Article 7", "NOT_RUN", "machine-checked"):
            self.assertIn(fragment, self.text, f"the document does not state {fragment}")

    def test_the_no_import_rule_is_stated(self) -> None:
        self.assertIn("do not import", self.text)
        self.assertIn("policy_engine", self.text)

    def test_the_tests_are_named(self) -> None:
        self.assertIn("forensics/tools/tests/test_verifier_formalisation.py", self.text)


if __name__ == "__main__":
    unittest.main()
