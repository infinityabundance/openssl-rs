#!/usr/bin/env python3
"""Negative controls for the requirements-traceability checker.

The graph claims that it fails closed on eight named orphan classes.  These
tests mutate a copy of the committed graph, one mutation per class, and require
the checker to refuse with the exact orphan identifier the mutation creates.
A positive control requires the committed graph to validate, and a determinism
control requires two runs to be byte-identical.

Run inside the court:

    python3 forensics/tools/tests/test_traceability.py
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
CHECKER = TOOLS / "traceability.py"
SEEDER = TOOLS / "etp_t1_seed.py"
GRAPH = REPO_ROOT / "evidence" / "etp-t1" / "TRACEABILITY.json"


def load_graph() -> dict:
    return json.loads(GRAPH.read_text(encoding="utf-8"))


class TraceabilityControls(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="etp-t1-test-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def run_checker(self, document: dict | None = None, *extra: str):
        if document is None:
            graph_path = GRAPH
        else:
            graph_path = self.directory / "graph.json"
            graph_path.write_text(json.dumps(document), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(CHECKER), "validate",
             "--graph", str(graph_path), "--repo-root", str(REPO_ROOT), *extra],
            capture_output=True, text=True, timeout=300,
        )

    def assert_refused(self, result, identifier: str) -> None:
        self.assertNotEqual(
            result.returncode, 0,
            f"checker accepted a mutated graph:\n{result.stdout}",
        )
        self.assertIn(
            identifier, result.stderr,
            f"expected {identifier!r} in stderr, got:\n{result.stderr}",
        )

    def drop_edges(self, document: dict, predicate) -> None:
        document["edges"] = [
            edge for edge in document["edges"] if not predicate(edge)
        ]

    # ---------------------------------------------------------------- positive
    def test_committed_graph_validates_and_its_orphans_are_declared(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 undeclared, 0 stale", result.stdout)
        declared = load_graph()["orphans"]
        self.assertEqual(len(declared), 20)
        self.assertEqual(
            sorted({entry["class"] for entry in declared}),
            [1, 3, 6, 8],
        )

    def test_validate_output_is_byte_identical_across_runs(self) -> None:
        first = self.run_checker()
        second = self.run_checker()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stderr, second.stderr)

    def test_seed_reproduces_the_committed_graph(self) -> None:
        output = self.directory / "seed.json"
        result = subprocess.run(
            [sys.executable, str(SEEDER), "--output", str(output)],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            output.read_bytes(), GRAPH.read_bytes(),
            "the tracked seeder over unchanged records does not reproduce the graph",
        )

    def test_report_counts_match_the_graph(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER), "report", "--graph", str(GRAPH),
             "--repo-root", str(REPO_ROOT), "--json"],
            capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        document = load_graph()
        self.assertEqual(payload["total_nodes"], len(document["nodes"]))
        self.assertEqual(payload["total_edges"], len(document["edges"]))
        self.assertEqual(payload["total_orphans"], len(document["orphans"]))
        self.assertEqual(payload["orphan_register_errors"], [])

    # ---------------------------------------------------------------- class 1
    def test_class_1_requirement_without_implementation(self) -> None:
        document = load_graph()
        self.drop_edges(
            document,
            lambda e: e["type"] == "satisfied_by" and e["from"] == "REQ-MEM-01",
        )
        result = self.run_checker(document)
        self.assert_refused(result, "ORPHAN-1:REQ-MEM-01")

    # ---------------------------------------------------------------- class 2
    def test_class_2_implementation_without_artefact(self) -> None:
        document = load_graph()
        self.drop_edges(
            document,
            lambda e: e["type"] == "realised_by" and e["from"] == "IMP-RSA",
        )
        result = self.run_checker(document)
        self.assert_refused(result, "ORPHAN-2:IMP-RSA")

    # ---------------------------------------------------------------- class 3
    def test_class_3_release_claim_without_adjudication(self) -> None:
        document = load_graph()
        self.drop_edges(
            document,
            lambda e: e["type"] == "releases" and e["to"] == "REL-CURL-049",
        )
        result = self.run_checker(document)
        self.assert_refused(result, "ORPHAN-3:REL-CURL-049")
        self.assertIn("no_adjudication", result.stderr)

    # ---------------------------------------------------------------- class 4
    def test_class_4_evidence_bound_to_a_different_artefact(self) -> None:
        document = load_graph()
        node = next(n for n in document["nodes"] if n["id"] == "EVD-ETP0-RECEIPT")
        node["source"]["sha256"] = "0" * 64
        result = self.run_checker(document)
        self.assert_refused(result, "ORPHAN-4:EVD-ETP0-RECEIPT")
        self.assertIn("evidence/etp0/RECEIPT.md", result.stderr)
        self.assertIn("recorded " + "0" * 64, result.stderr)

    def test_class_4_evidence_bound_to_a_different_identity(self) -> None:
        document = load_graph()
        stale = next(
            n["id"] for n in document["nodes"]
            if n["type"] == "evidence"
            and n["source"].get("bound_commit") != document["identity"]["commit"]
        )
        document["edges"].append({
            "from": "IMP-BN-LIMBS", "type": "evidenced_by", "to": stale,
            "basis": "test-only citation of evidence bound to another candidate",
        })
        result = self.run_checker(document)
        self.assert_refused(result, f"ORPHAN-4:{stale}")
        self.assertIn("support_identity_mismatch", result.stderr)

    # ---------------------------------------------------------------- class 5
    def test_class_5_blocking_obligation_unreachable_from_claim(self) -> None:
        document = load_graph()
        self.drop_edges(
            document,
            lambda e: e["type"] == "constrains"
            and e["from"] == "OBL-C1" and e["to"] == "REL-CURL-049",
        )
        result = self.run_checker(document)
        self.assert_refused(result, "ORPHAN-5:OBL-C1:REL-CURL-049")
        self.assertIn("omission is invisible", result.stderr)

    # ---------------------------------------------------------------- class 6
    def test_class_6_specification_without_implementation(self) -> None:
        document = load_graph()
        source = next(
            n["source"] for n in document["nodes"]
            if n["source"]["path"] == "docs/NON_CLAIMS.md"
        )
        document["nodes"].append({
            "id": "SPEC-TEST",
            "type": "specification",
            "title": "A test-only specification",
            "source": dict(source, span="test", quote="test", quote_kind="test"),
        })
        document["edges"].append({
            "from": "REQ-EVID-01", "type": "refines", "to": "SPEC-TEST",
            "basis": "test-only refinement",
        })
        result = self.run_checker(document)
        self.assert_refused(result, "ORPHAN-6:SPEC:SPEC-TEST")

    def test_class_6_requirement_without_specification_is_detected(self) -> None:
        # The committed graph already declares the requirement-side gap; this
        # control removes its declaration and requires the refusal to name it.
        document = load_graph()
        document["orphans"] = [
            entry for entry in document["orphans"]
            if entry["id"] != "ORPHAN-6:REQ:REQ-SEC-02"
        ]
        result = self.run_checker(document)
        self.assert_refused(result, "ORPHAN-6:REQ:REQ-SEC-02")

    # ---------------------------------------------------------------- class 7
    def test_class_7_cycle_in_the_support_direction(self) -> None:
        document = load_graph()
        document["edges"].append({
            "from": "ADJ-ETP5-R1", "type": "evidenced_by",
            "to": "EVD-ETP5-REFUSALS",
            "basis": "test-only circular citation",
        })
        result = self.run_checker(document)
        self.assert_refused(result, "ORPHAN-7:ADJ-ETP5-R1+EVD-ETP5-REFUSALS")

    # ---------------------------------------------------------------- class 8
    def test_class_8_dangling_evidence_path(self) -> None:
        document = load_graph()
        node = next(n for n in document["nodes"] if n["id"] == "EVD-ETP0-RECEIPT")
        node["source"]["path"] = "evidence/etp0/RECEIPT-absent.md"
        result = self.run_checker(document)
        self.assert_refused(
            result, "ORPHAN-8:EVD-ETP0-RECEIPT:evidence/etp0/RECEIPT-absent.md"
        )

    def test_dangling_edge_is_a_structural_refusal(self) -> None:
        document = load_graph()
        document["edges"].append({
            "from": "REQ-MEM-01", "type": "satisfied_by",
            "to": "IMP-DOES-NOT-EXIST", "basis": "test",
        })
        result = self.run_checker(document)
        self.assert_refused(result, "TG_DANGLING_EDGE")

    # ------------------------------------------------------- register drift
    def test_stale_declared_orphan_is_refused(self) -> None:
        document = load_graph()
        document["orphans"].append({
            "id": "ORPHAN-6:REQ:REQ-NOT-PRESENT",
            "class": 6,
            "node": "REQ-NOT-PRESENT",
            "reason": "requirement_without_specification",
            "would_close": "nothing; this declaration is stale",
        })
        result = self.run_checker(document)
        self.assert_refused(result, "TG_STALE_ORPHAN")

    def test_undeclared_orphan_is_refused_even_when_connectivity_is_preserved(
        self,
    ) -> None:
        document = load_graph()
        # A release claim whose only adjudication is one party and is not
        # positive.  REL-CURL-049 is negative and needs no independent record,
        # so add a positive claim instead of mutating an existing one.
        document["nodes"].append({
            "id": "REL-TEST", "type": "release_claim", "title": "test claim",
            "source": next(
                n["source"] for n in document["nodes"] if n["id"] == "REL-CURL-049"
            ),
            "claimed_verdict": "SAFE_COMPATIBLE",
            "requires_independent_adjudication": True,
            "scope_requirements": ["REQ-GRAD-01"],
        })
        document["edges"].append({
            "from": "ADJ-ETP5-R2", "type": "releases", "to": "REL-TEST",
            "basis": "test-only same-party adjudication",
        })
        result = self.run_checker(document)
        self.assert_refused(result, "ORPHAN-3:REL-TEST")
        self.assertIn("not_independent", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
