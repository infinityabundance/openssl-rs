#!/usr/bin/env python3
"""Negative controls for the ETP-T2 hazard register and its T1 projection.

The register claims three things that these tests must be able to refute:

  * every hazard has a scope and a non-empty input classification;
  * a hazard reachable from a contract-violating input never claims memory
    safety;
  * a claimed control is recorded as CLAIMED_NO_EVIDENCE rather than upgraded,
    and every fault-tree leaf names a mechanism or a recorded assumption.

The register projection into the traceability graph is checked separately, so
a register that drifts from `evidence/etp-t1/TRACEABILITY.json` is refused.

Run inside the court:

    python3 forensics/tools/tests/test_hazard_register.py
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
REGISTER_TOOL = TOOLS / "hazard_register.py"
CHECKER = TOOLS / "traceability.py"
REGISTER = REPO_ROOT / "evidence" / "etp-t2" / "HAZARDS.json"
GRAPH = REPO_ROOT / "evidence" / "etp-t1" / "TRACEABILITY.json"


def load_register() -> dict:
    return json.loads(REGISTER.read_text(encoding="utf-8"))


def load_graph() -> dict:
    return json.loads(GRAPH.read_text(encoding="utf-8"))


def hazard(document: dict, hid: str) -> dict:
    return next(entry for entry in document["hazards"] if entry["id"] == hid)


def graph_hazard(document: dict, hid: str) -> dict:
    return next(node for node in document["nodes"] if node["id"] == hid)


class HazardRegisterControls(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="etp-t2-test-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.counter = 0

    def write(self, document: dict, name: str) -> Path:
        self.counter += 1
        path = self.directory / f"{name}-{self.counter}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def run_register(self, register: dict | None = None, graph: dict | None = None):
        register_path = REGISTER if register is None else self.write(register, "register")
        graph_path = GRAPH if graph is None else self.write(graph, "graph")
        return subprocess.run(
            [
                sys.executable,
                str(REGISTER_TOOL),
                "validate",
                "--register",
                str(register_path),
                "--graph",
                str(graph_path),
                "--repo-root",
                str(REPO_ROOT),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

    def run_checker(self, graph: dict):
        graph_path = self.write(graph, "graph")
        return subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "validate",
                "--graph",
                str(graph_path),
                "--repo-root",
                str(REPO_ROOT),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

    def assert_refused(self, result, identifier: str) -> None:
        self.assertNotEqual(
            result.returncode, 0, f"accepted a mutated document:\n{result.stdout}"
        )
        self.assertIn(
            identifier,
            result.stderr,
            f"expected {identifier!r} in stderr, got:\n{result.stderr}",
        )

    # ---------------------------------------------------------------- positive
    def test_register_validates_and_matches_the_graph(self) -> None:
        result = self.run_register()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("20 hazards", result.stdout)
        self.assertIn("register and traceability graph agree", result.stdout)

    def test_validation_is_byte_identical_across_runs(self) -> None:
        first = self.run_register()
        second = self.run_register()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stderr, second.stderr)

    def test_every_hazard_has_a_scope_and_an_input_class(self) -> None:
        document = load_register()
        for entry in document["hazards"]:
            self.assertIn("api_family", entry["scope"], entry["id"])
            self.assertIn("input_class", entry["scope"], entry["id"])
            self.assertTrue(entry["trigger_classes"], entry["id"])

    # ------------------------------------------------- register-side controls
    def test_hazard_without_scope_is_refused(self) -> None:
        document = load_register()
        del hazard(document, "HAZ-08")["scope"]
        self.assert_refused(self.run_register(document), "HR_UNSCOPED_HAZARD")

    def test_hazard_without_input_class_is_refused(self) -> None:
        document = load_register()
        hazard(document, "HAZ-08")["trigger_classes"] = []
        self.assert_refused(self.run_register(document), "HR_NO_INPUT_CLASS")

    def test_class3_only_hazard_claiming_memory_safety_is_refused(self) -> None:
        document = load_register()
        entry = hazard(document, "HAZ-04")
        self.assertEqual(entry["trigger_classes"], ["contract_violation"])
        entry["memory_safe_claim"] = True
        self.assert_refused(self.run_register(document), "HR_CLASS3_SAFE_CLAIM")

    def test_class3_hazard_without_disposition_is_refused(self) -> None:
        document = load_register()
        del hazard(document, "HAZ-19")["class3_disposition"]
        self.assert_refused(self.run_register(document), "HR_CLASS3_DISPOSITION")

    def test_fault_tree_leaf_that_names_no_mechanism_is_refused(self) -> None:
        document = load_register()
        tree = next(t for t in document["fault_trees"] if t["id"] == "TE-1")
        leaf = next(n for n in tree["nodes"] if n["id"] == "TE1-L-BRANCH")
        del leaf["hazard"]
        del leaf["mechanism"]
        self.assert_refused(self.run_register(document), "HR_TREE_LEAF_UNNAMED")

    def test_fault_tree_leaf_naming_an_unknown_hazard_is_refused(self) -> None:
        document = load_register()
        tree = next(t for t in document["fault_trees"] if t["id"] == "TE-1")
        leaf = next(n for n in tree["nodes"] if n["id"] == "TE1-L-BLIND")
        leaf["hazard"] = "HAZ-NOT-REGISTERED"
        self.assert_refused(self.run_register(document), "HR_TREE_HAZARD_UNKNOWN")

    def test_fmea_evidenced_control_without_evidence_is_refused(self) -> None:
        document = load_register()
        document["fmea"][0]["evidence_status"] = "EVIDENCED"
        document["fmea"][0]["control_evidence"] = []
        self.assert_refused(self.run_register(document), "HR_FMEA_EVIDENCE")

    def test_fmea_claimed_control_citing_evidence_is_refused(self) -> None:
        document = load_register()
        document["fmea"][0]["control_evidence"] = ["EVD-INST-ALLOC_PROBE"]
        self.assert_refused(self.run_register(document), "HR_FMEA_EVIDENCE")

    def test_attack_graph_claiming_an_evidenced_barrier_is_refused(self) -> None:
        document = load_register()
        document["attack_graphs"][0]["barrier_evidenced"] = True
        document["attack_graphs"][0]["evidence"] = []
        self.assert_refused(self.run_register(document), "HR_AG_INCOMPLETE")

    def test_uca_naming_an_absent_controller_is_refused(self) -> None:
        document = load_register()
        document["stpa"]["ucas"][0]["controller"] = "CS-ABSENT"
        self.assert_refused(self.run_register(document), "HR_STPA_UCA_INCOMPLETE")

    # ----------------------------------------------------- graph-side controls
    def test_graph_scope_drift_is_refused(self) -> None:
        document = load_graph()
        graph_hazard(document, "HAZ-08")["scope"]["input_class"] = "legal"
        graph_hazard(document, "HAZ-08")["scope"]["api_family"] = "evp"
        self.assert_refused(self.run_register(graph=document), "HR_GRAPH_FIELD_MISMATCH")

    def test_graph_missing_hazard_is_refused(self) -> None:
        document = load_graph()
        document["nodes"] = [n for n in document["nodes"] if n["id"] != "HAZ-08"]
        document["edges"] = [
            e for e in document["edges"] if e["from"] != "HAZ-08" and e["to"] != "HAZ-08"
        ]
        self.assert_refused(self.run_register(graph=document), "HR_GRAPH_NODE_MISSING")

    def test_graph_missing_edge_is_refused(self) -> None:
        document = load_graph()
        document["edges"] = [
            e
            for e in document["edges"]
            if not (
                e["from"] == "HAZ-02"
                and e["type"] == "evidenced_by"
                and e["to"] == "EVD-INST-BINSEC_CHECKCT"
            )
        ]
        self.assert_refused(self.run_register(graph=document), "HR_GRAPH_EDGE_MISMATCH")

    def test_graph_register_digest_drift_is_refused(self) -> None:
        document = load_graph()
        document["hazard_register"]["sha256"] = "0" * 64
        self.assert_refused(self.run_register(graph=document), "HR_GRAPH_FIELD_MISMATCH")

    # ------------------------------------- traceability-side hazard controls
    def test_traceability_refuses_a_hazard_without_scope(self) -> None:
        document = load_graph()
        del graph_hazard(document, "HAZ-08")["scope"]
        self.assert_refused(self.run_checker(document), "TG_HAZARD_UNSCOPED")

    def test_traceability_refuses_a_hazard_without_input_class(self) -> None:
        document = load_graph()
        graph_hazard(document, "HAZ-08")["trigger_classes"] = []
        self.assert_refused(self.run_checker(document), "TG_HAZARD_NO_INPUT_CLASS")

    def test_traceability_refuses_class3_only_memory_safety(self) -> None:
        document = load_graph()
        graph_hazard(document, "HAZ-04")["memory_safe_claim"] = True
        self.assert_refused(self.run_checker(document), "TG_HAZARD_CLASS3_SAFE_CLAIM")

    def test_traceability_refuses_an_evidenced_barrier_without_evidence(self) -> None:
        document = load_graph()
        node = graph_hazard(document, "HAZ-08")
        node["barrier"]["state"] = "EVIDENCED"
        node["barrier"]["evidence"] = []
        self.assert_refused(self.run_checker(document), "TG_HAZARD_BARRIER_UNEVIDENCED")

    def test_traceability_refuses_an_unmotivated_hazard(self) -> None:
        document = load_graph()
        document["edges"] = [
            e
            for e in document["edges"]
            if not (e["from"] == "HAZ-18" and e["type"] == "motivates")
        ]
        self.assert_refused(self.run_checker(document), "TG_HAZARD_UNMOTIVATED")

    def test_traceability_refuses_a_hazard_naming_an_unrelated_claim(self) -> None:
        document = load_graph()
        graph_hazard(document, "HAZ-17")["affected_release_claims"] = ["REL-CURL-049"]
        self.assert_refused(self.run_checker(document), "TG_HAZARD_CLAIM_UNRELATED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
