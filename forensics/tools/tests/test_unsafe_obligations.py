#!/usr/bin/env python3
"""Controls for the ETP-T4 unsafe-site inventory and its vacuity refusals.

Every refusal the inventory implements has a control that makes it fire:

* a discharge with no control that could fail               (`ET4_DISCHARGE_WITHOUT_CONTROL`)
* an unreachable precondition reported as satisfied         (`ET4_VACUOUS_REPORTED_SATISFIED`)
* a caller obligation with no witness                       (`ET4_CALLER_OBLIGATION_UNESTABLISHED`)
* a tautological assertion                                  (`ET4_ASSERTION_CANNOT_FAIL`)

The restatement heuristic has a control in both directions: a support relation
moves a text from `restatement` to `argument`, and removing it moves the text
back.  The inverted-assertion control runs the test runner on an assertion that
is deliberately false and requires the runner to fail it.

Run inside the court:

    python3 forensics/tools/tests/test_unsafe_obligations.py
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
GRAPH = REPO_ROOT / "evidence" / "etp-t1" / "TRACEABILITY.json"

sys.path.insert(0, str(TOOLS))
import unsafe_obligations as u  # noqa: E402


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class UnsafeObligationControls(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="etp-t4-test-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    # ---------------------------------------------------------------- positive
    def test_committed_inventory_and_axioms_validate(self) -> None:
        problems = u.validate()
        self.assertEqual(problems, [], "\n".join(problems))

    def test_json_tool_accepts_both_evidence_files(self) -> None:
        for path in (u.SITES_OUT, u.AXIOMS_OUT):
            result = subprocess.run(
                [sys.executable, "-m", "json.tool", str(path)],
                capture_output=True, text=True, timeout=300,
            )
            self.assertEqual(result.returncode, 0, f"{path}: {result.stderr}")

    def test_counts_sum_to_the_site_population(self) -> None:
        doc = load_json(u.SITES_OUT)
        summary = doc["summary"]
        self.assertEqual(
            summary["contract_absent"] + summary["contract_restatement"]
            + summary["contract_argument"],
            summary["sites"],
        )
        self.assertEqual(
            summary["coverage_none"] + summary["coverage_argument_only"]
            + summary["coverage_test"] + summary["coverage_instrument"],
            summary["sites"],
        )
        self.assertEqual(
            sum(summary["by_class"].values()),
            summary["sites"],
        )

    def test_every_site_row_is_complete(self) -> None:
        doc = load_json(u.SITES_OUT)
        vocab = doc["vocabularies"]
        rows = u.decode_sites(doc["sites"])
        self.assertEqual(len(rows), doc["summary"]["sites"])
        for row in rows:
            self.assertTrue(row["id"].startswith("us-"))
            self.assertTrue(row["path"].startswith("src/"))
            self.assertGreaterEqual(row["line"], 1)
            self.assertIn(row["kind"], vocab["site_kind"])
            self.assertIn(row["class"], vocab["obligation_class"])
            self.assertIn(row["impact"], vocab["impact"])
            self.assertIn(row["contract_state"], vocab["contract_state"])
            self.assertIn(row["boundary_kind"], vocab["boundary_kind"])
            self.assertIn(row["coverage_kind"], vocab["coverage_kind"])
            self.assertTrue(row["symbol"])

    def test_heuristic_limits_are_stated(self) -> None:
        doc = load_json(u.SITES_OUT)
        self.assertTrue(doc["identity"]["heuristic"])
        limits = doc["heuristic"]["restatement"]["limits"]
        self.assertGreaterEqual(len(limits), 3)
        self.assertIn("lexical, not semantic", limits[0])
        self.assertEqual(doc["identity"]["scanner"], "forensics/tools/unsafe_obligations.py")

    # ------------------------------------------------- restatement heuristic
    def test_restatement_heuristic_flags_bare_operations(self) -> None:
        for text in (
            "Calls an unsafe function.",
            "This is an unsafe call.",
            "Only used internally.",
            "The pointer is valid.",
            "As [`AES_encrypt`].",
            "The caller must ensure validity.",
        ):
            state, reason, _ = u.classify_contract(text)
            self.assertEqual(state, "restatement", f"{text!r} -> {state}/{reason}")

    def test_restatement_heuristic_accepts_a_support_relation(self) -> None:
        text = ("`p` points to `n` initialised bytes of the same allocation, and the "
                "caller checked `n <= capacity` because the length came from that block.")
        state, reason, _ = u.classify_contract(text)
        self.assertEqual(state, "argument", reason)

    def test_restatement_inversion_control(self) -> None:
        argument = "`p` is valid because the caller checked it against the allocation bounds."
        restatement = "`p` is valid."
        self.assertEqual(u.classify_contract(argument)[0], "argument")
        self.assertEqual(u.classify_contract(restatement)[0], "restatement")
        # The same words with the support clause removed lose the argument.
        stripped = argument.replace(" because the caller checked it against the allocation bounds", "")
        self.assertEqual(u.classify_contract(stripped)[0], "restatement")

    # --------------------------------------------------------- vacuity: no control
    def _mutated_sites(self, mutate) -> Path:
        doc = load_json(u.SITES_OUT)
        mutate(doc)
        path = self.directory / "SAFETY-SITES.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def test_discharge_without_control_is_refused(self) -> None:
        def mutate(doc: dict) -> None:
            doc["vacuity"]["discharges"][0]["controls"] = []

        problems = u.validate(self._mutated_sites(mutate), u.AXIOMS_OUT)
        self.assertTrue(
            any(p.startswith("ET4_DISCHARGE_WITHOUT_CONTROL") for p in problems),
            problems,
        )

    def test_control_that_cannot_fail_is_refused(self) -> None:
        def mutate(doc: dict) -> None:
            doc["vacuity"]["discharges"][0]["control_could_fail"] = False

        problems = u.validate(self._mutated_sites(mutate), u.AXIOMS_OUT)
        self.assertTrue(
            any(p.startswith("ET4_DISCHARGE_WITHOUT_CONTROL") for p in problems),
            problems,
        )

    def test_vacuous_precondition_reported_satisfied_is_refused(self) -> None:
        doc = load_json(u.SITES_OUT)
        entry = next(
            f for f in doc["vacuity"]["findings"]
            if f["status"] == "VACUOUS_PRECONDITION"
        )
        self.assertFalse(entry.get("reported_satisfied", False))

        def mutate(document: dict) -> None:
            target = next(
                f for f in document["vacuity"]["findings"]
                if f["site"] == entry["site"]
            )
            target["reported_satisfied"] = True

        problems = u.validate(self._mutated_sites(mutate), u.AXIOMS_OUT)
        self.assertTrue(
            any(p.startswith("ET4_VACUOUS_REPORTED_SATISFIED") for p in problems),
            problems,
        )

    def test_caller_obligation_without_witness_is_refused(self) -> None:
        def mutate(doc: dict) -> None:
            doc["vacuity"]["findings"].append({
                "site": "us-control", "path": "src/control.rs", "line": 1,
                "symbol": "control", "status": "SATISFIED", "detail": "claimed",
                "production_callers": 1, "test_callers": 0, "witness": "",
            })

        problems = u.validate(self._mutated_sites(mutate), u.AXIOMS_OUT)
        self.assertTrue(
            any(p.startswith("ET4_CALLER_OBLIGATION_UNESTABLISHED") for p in problems),
            problems,
        )

    def test_tautological_assertion_is_refused(self) -> None:
        def mutate(doc: dict) -> None:
            doc["assertions"]["tautological"].append({
                "path": "src/control.rs", "line": 9, "test_module": "tests",
                "kind": "assert_true", "detail": "the assertion is true for every input",
            })

        problems = u.validate(self._mutated_sites(mutate), u.AXIOMS_OUT)
        self.assertTrue(
            any(p.startswith("ET4_ASSERTION_CANNOT_FAIL") for p in problems),
            problems,
        )

    def test_tautology_detector_flags_true_and_self_comparison(self) -> None:
        patterns = dict(u.ASSERTION_PATTERNS)
        for text in ("assert!(true)", "assert!(x == x)", "assert_eq!(a, a)",
                     "assert!(true || cond)", "assert!(1 == 1)"):
            self.assertTrue(
                any(p.search(text) for p in patterns.values()),
                f"no detector fired for {text!r}",
            )
        for text in ("assert!(x == y)", "assert_eq!(a, b)", "assert!(x > 0)"):
            self.assertFalse(
                any(p.search(text) for p in patterns.values()),
                f"a detector fired for a real assertion {text!r}",
            )

    # --------------------------------------------------- inverted assertion control
    def test_inverted_assertion_is_reported_as_a_failure(self) -> None:
        inverted = (
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_inverted(self):\n"
            "        self.assertEqual(2 + 2, 5)\n"
            "unittest.main(exit=True)\n"
        )
        correct = inverted.replace("2 + 2, 5", "2 + 2, 4")
        failed = subprocess.run([sys.executable, "-c", inverted],
                                capture_output=True, text=True, timeout=60)
        passed = subprocess.run([sys.executable, "-c", correct],
                                capture_output=True, text=True, timeout=60)
        self.assertNotEqual(failed.returncode, 0,
                            "the runner reported success for a deliberately false assertion")
        self.assertEqual(passed.returncode, 0,
                         "the runner failed a true assertion")

    # ------------------------------------------------------------ T1 projection
    def test_graph_has_etp_t4_obligations_and_orphans(self) -> None:
        graph = load_json(GRAPH)
        nodes = {node["id"]: node for node in graph["nodes"]}
        node = nodes["OBL-T4-RAW-DEREFERENCE"]
        self.assertEqual(node["type"], "obligation")
        inventory = node["unsafe_site_inventory"]
        self.assertGreater(inventory["sites"], 0)
        self.assertGreater(inventory["sites_without_contract_or_control"], 0)
        pairs = {(edge["from"], edge["type"], edge["to"]) for edge in graph["edges"]}
        self.assertIn(("IMP-UNSAFE-SURFACE", "raises", "OBL-T4-RAW-DEREFERENCE"), pairs)
        self.assertIn(("OBL-T4-RAW-DEREFERENCE", "evidenced_by", "EV-ETP-T4-SITES"), pairs)
        self.assertIn(("IMP-UNSAFE-SURFACE", "realised_by", "ART-UNSAFE-SITES"), pairs)
        declared = {entry["id"] for entry in graph["orphans"]}
        self.assertIn("ORPHAN-12:OBL-T4-RAW-DEREFERENCE", declared)
        self.assertIn(
            "ORPHAN-8:EV-ETP-T4-SITES:evidence/etp-t4/SAFETY-SITES.json", declared
        )

    def test_traceability_controls_still_pass(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOLS / "traceability.py"), "validate"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 undeclared, 0 stale", result.stdout)

    def test_axiom_register_is_non_vacuous(self) -> None:
        ax = load_json(u.AXIOMS_OUT)
        self.assertGreaterEqual(len(ax["axioms"]), 20)
        ids = {axiom["id"] for axiom in ax["axioms"]}
        for required in ("AX-ALLOC-SEAM", "AX-COMPILER-IDENTITY", "AX-CPU-VARIABLE-LATENCY",
                         "AX-DUDECT-MODEL", "AX-AUTHORITY-PARITY"):
            self.assertIn(required, ids)
        unchecked = {a["id"] for a in ax["axioms"] if a["status"] == "UNCHECKED"}
        self.assertTrue(unchecked, "an axiom register with no unchecked premise is suspect")
        self.assertEqual(unchecked, set(ax["summary"]["unchecked_ids"]))
        for axiom in ax["axioms"]:
            self.assertTrue(axiom["falsified_by"])
            self.assertTrue(axiom["checked_by"])
        self.assertGreater(ax["suppressions"]["total"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
