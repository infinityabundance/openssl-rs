#!/usr/bin/env python3
"""Controls for forensics/tools/frc_registers.py and the FRC-0 registers.

What is proved here, and what is not
------------------------------------
* The committed registers validate, and the summary reproduces their declared
  shape (15 frontier entries, 6 levels, 5 edges, 0 discharged, 15 tools, 0
  admitted).
* Every refusal code has a negative control that corrupts one field and observes
  that exact code, so no code is exercised only by a document.
* Three positive controls establish that the rules are not vacuous: a complete
  admitted tool is accepted, a discharged edge with a machine-checked proof
  artefact is accepted, and a beyond-frontier claim whose matched entry is
  ESTABLISHED is accepted. None of the three describes this project's state.
* The producer is byte-identical across two runs and against the committed
  bytes; the document names every level, edge, entry, tool and code; the
  document names no implementation source path.

These are controls on the registers, not evidence that any admission, standard
reading or theorem is true. Run directly or with
``python3 -m unittest forensics.tools.tests.test_frc_registers``.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import frc_registers as fr  # noqa: E402

DOCUMENT = REPO / "docs/SPECIFICATION-HIERARCHY.md"
FRONTIER_PATH = REPO / fr.FRONTIER
HIERARCHY_PATH = REPO / fr.HIERARCHY
TOOLS_PATH = REPO / fr.TOOLS
PRODUCER = REPO / "evidence/frc/build_evidence.py"
KANI_SHA = "1bbdab14d231b24474e7ccbc306d619cb4205601ac7db71eb9f3cd4bbe364ca0"
ETP4 = "evidence/etp4/VERIFICATION-RECEIPT.md"


def load(path: Path) -> object:
    return fr.load_json_strict(path)


def committed() -> tuple[dict, dict, dict, str]:
    return (load(FRONTIER_PATH), load(HIERARCHY_PATH), load(TOOLS_PATH),
            DOCUMENT.read_text(encoding="utf-8"))


def codes_of(problems: list[tuple[str, str]]) -> set[str]:
    return {code for code, _detail in problems}


# ---------------------------------------------------------------------------
# Corruptions.  Each returns the refusal codes observed, so the individual
# tests and the coverage test share one definition.
# ---------------------------------------------------------------------------


def corrupt_schema() -> set[str]:
    frontier = load(FRONTIER_PATH)
    frontier["schema"] = "not-the-schema"
    return codes_of(fr.validate_frontier(frontier, REPO))


def corrupt_duplicate_key() -> set[str]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "dup.json"
        path.write_text('{"a": 1, "a": 2}', encoding="utf-8")
        try:
            fr.load_json_strict(path)
        except fr.Refusal as refusal:
            return {refusal.code}
    return set()


def corrupt_unclassified() -> set[str]:
    frontier = load(FRONTIER_PATH)
    frontier["entries"][0]["classification"] = "UNCLASSIFIED"
    return codes_of(fr.validate_frontier(frontier, REPO))


def corrupt_unverified_without_method() -> set[str]:
    frontier = load(FRONTIER_PATH)
    frontier["entries"][0]["verification"]["settling_method"] = ""
    return codes_of(fr.validate_frontier(frontier, REPO))


def corrupt_verification_without_source() -> set[str]:
    frontier = load(FRONTIER_PATH)
    frontier["entries"][0]["verification"] = {
        "state": "RECORDED_BY_THIS_PROJECT",
        "witness": "docs/absent-witness.md",
        "settling_method": "control",
    }
    return codes_of(fr.validate_frontier(frontier, REPO))


def corrupt_proven_without_evidence() -> set[str]:
    frontier = load(FRONTIER_PATH)
    frontier["entries"][0]["this_project"] = {
        "state": "BOUNDED_EVIDENCE", "basis": "control",
        "evidence": ["docs/absent-evidence.md"], "proof_artefact": None,
    }
    return codes_of(fr.validate_frontier(frontier, REPO))


def corrupt_frontier_without_both_properties() -> set[str]:
    frontier = load(FRONTIER_PATH)
    frontier["entries"][0]["beyond_frontier"] = {
        "claim": True, "matched_property": "a matched property",
        "added_property": "", "matched_entry": None,
    }
    return codes_of(fr.validate_frontier(frontier, REPO))


def corrupt_exceeds_frontier_unproven() -> set[str]:
    frontier = load(FRONTIER_PATH)
    frontier["entries"][0]["beyond_frontier"] = {
        "claim": True, "matched_property": "a matched property",
        "added_property": "an added property", "matched_entry": "FG-S2N-A1",
    }
    return codes_of(fr.validate_frontier(frontier, REPO))


def corrupt_tool_admitted_incomplete() -> set[str]:
    tools = load(TOOLS_PATH)
    tools["tools"][0]["admission"] = "ADMITTED"
    return codes_of(fr.validate_tools(tools, REPO))


def corrupt_tool_refusal_without_reason() -> set[str]:
    tools = load(TOOLS_PATH)
    tools["tools"][0]["refusal_reason"] = ""
    return codes_of(fr.validate_tools(tools, REPO))


def corrupt_spec_restates_implementation() -> set[str]:
    hierarchy = load(HIERARCHY_PATH)
    hierarchy["levels"][0]["implementation_derived"] = True
    return codes_of(fr.validate_hierarchy(hierarchy, REPO, refinement=None))


def corrupt_discharged_without_proof() -> set[str]:
    hierarchy = load(HIERARCHY_PATH)
    hierarchy["edges"][0]["status"] = "DISCHARGED"
    hierarchy["edges"][0]["proof"] = None
    return codes_of(fr.validate_hierarchy(hierarchy, REPO, refinement=None))


def corrupt_hierarchy_drift() -> set[str]:
    hierarchy = load(HIERARCHY_PATH)
    hierarchy["edges"][0]["status"] = "PARTIAL"
    refinement = load(REPO / fr.REFINEMENT)
    return codes_of(fr.validate_hierarchy(hierarchy, REPO, refinement=refinement))


def corrupt_digest_unsourced() -> set[str]:
    tools = load(TOOLS_PATH)
    tools["tools"][0]["digests"][0]["sha256"] = "0" * 64
    return codes_of(fr.validate_tools(tools, REPO))


def corrupt_do178_certification() -> set[str]:
    frontier = load(FRONTIER_PATH)
    for entry in frontier["entries"]:
        if entry["classification"] == "DO_178C_OBJECTIVE":
            entry["certification_claimed"] = True
    return codes_of(fr.validate_frontier(frontier, REPO))


def corrupt_document_drift() -> set[str]:
    frontier, hierarchy, tools, text = committed()
    text = text.replace("RFE-3", "RFE-X")
    return codes_of(fr.validate_document(text, frontier, hierarchy, tools))


def corrupt_usage() -> set[str]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        status = fr.main([])
    return {fr.CODE_USAGE} if status == fr.EXIT_USAGE else set()


CONTROLS = {
    "FR_REFUSED_SCHEMA": corrupt_schema,
    "FR_REFUSED_DUPLICATE_KEY": corrupt_duplicate_key,
    "FR_REFUSED_UNCLASSIFIED_CLAIM": corrupt_unclassified,
    "FR_REFUSED_UNVERIFIED_WITHOUT_METHOD": corrupt_unverified_without_method,
    "FR_REFUSED_VERIFICATION_WITHOUT_SOURCE": corrupt_verification_without_source,
    "FR_REFUSED_PROVEN_WITHOUT_EVIDENCE": corrupt_proven_without_evidence,
    "FR_REFUSED_FRONTIER_WITHOUT_BOTH_PROPERTIES": corrupt_frontier_without_both_properties,
    "FR_REFUSED_EXCEEDS_FRONTIER_UNPROVEN": corrupt_exceeds_frontier_unproven,
    "FR_REFUSED_TOOL_ADMITTED_INCOMPLETE": corrupt_tool_admitted_incomplete,
    "FR_REFUSED_TOOL_REFUSAL_WITHOUT_REASON": corrupt_tool_refusal_without_reason,
    "FR_REFUSED_SPECIFICATION_RESTATES_IMPLEMENTATION": corrupt_spec_restates_implementation,
    "FR_REFUSED_REFINEMENT_DISCHARGED_WITHOUT_PROOF": corrupt_discharged_without_proof,
    "FR_REFUSED_HIERARCHY_DRIFT": corrupt_hierarchy_drift,
    "FR_REFUSED_DIGEST_UNSOURCED": corrupt_digest_unsourced,
    "FR_REFUSED_DO178_CERTIFICATION": corrupt_do178_certification,
    "FR_REFUSED_DOCUMENT_DRIFT": corrupt_document_drift,
    "FR_REFUSED_USAGE": corrupt_usage,
}


class CommittedRegisters(unittest.TestCase):
    def test_committed_registers_validate(self) -> None:
        self.assertEqual(fr.check(*committed(), repo=REPO,
                                  refinement=load(REPO / fr.REFINEMENT)), [])

    def test_summary_reproduces_the_declared_shape(self) -> None:
        frontier, hierarchy, tools, _text = committed()
        counts = fr.summary(frontier, hierarchy, tools)
        self.assertEqual(counts["frontier_entries"], 15)
        self.assertEqual(counts["frontier_classified"], 15)
        self.assertEqual(counts["frontier_project_none"], 14)
        self.assertEqual(counts["levels"], 6)
        self.assertEqual(counts["edges"], 5)
        self.assertEqual(counts["edges_discharged"], 0)
        self.assertEqual(counts["edges_none"], 3)
        self.assertEqual(counts["edges_partial"], 2)
        self.assertEqual(counts["tools"], 15)
        self.assertEqual(counts["tools_admitted"], 0)
        self.assertEqual(counts["tools_refused"], 15)
        self.assertEqual(counts["tools_unverified"], 13)
        self.assertEqual(counts["refusal_codes"], len(fr.REFUSALS))

    def test_hierarchy_edges_equal_the_etp_t3_record(self) -> None:
        hierarchy = load(HIERARCHY_PATH)
        refinement = load(REPO / fr.REFINEMENT)
        recorded = {edge["id"]: edge for edge in refinement["edges"]}
        for edge in hierarchy["edges"]:
            self.assertEqual(edge["status"], recorded[edge["id"]]["status"])
            self.assertEqual(edge["from"], recorded[edge["id"]]["from"])
            self.assertEqual(edge["to"], recorded[edge["id"]]["to"])
        self.assertEqual(hierarchy["discharged_edges"], 0)

    def test_no_tool_is_admitted(self) -> None:
        tools = load(TOOLS_PATH)
        self.assertTrue(all(tool["admission"] == "REFUSED" for tool in tools["tools"]))

    def test_saw_question_is_recorded_as_unverified(self) -> None:
        tools = load(TOOLS_PATH)
        saw = next(tool for tool in tools["tools"] if tool["name"] == "SAW")
        self.assertEqual(saw["admission"], "REFUSED")
        self.assertEqual(saw["verification"]["state"], "UNVERIFIED")
        self.assertTrue(saw["verification"]["settling_method"])

    def test_every_digest_occurs_in_its_cited_record(self) -> None:
        tools = load(TOOLS_PATH)
        for tool in tools["tools"]:
            for digest in tool["digests"]:
                text = (REPO / digest["recorded_in"]).read_text(encoding="utf-8")
                self.assertIn(digest["sha256"], text, tool["name"])


class Document(unittest.TestCase):
    def test_document_names_every_machine_token(self) -> None:
        frontier, hierarchy, tools, text = committed()
        self.assertEqual(fr.validate_document(text, frontier, hierarchy, tools), [])

    def test_document_has_no_implementation_path(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        self.assertNotIn("src/", text)
        self.assertNotIn("crate::", text)

    def test_document_states_the_do178_distinction(self) -> None:
        self.assertIn("is not certification", DOCUMENT.read_text(encoding="utf-8"))

    def test_every_code_in_the_document_is_a_known_code(self) -> None:
        import re
        text = DOCUMENT.read_text(encoding="utf-8")
        seen = set(re.findall(r"FR_REFUSED_[A-Z0-9_]+", text))
        self.assertTrue(seen)
        self.assertLessEqual(seen, set(fr.REFUSALS))

    def test_every_known_code_is_in_the_document(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        for code in fr.REFUSALS:
            self.assertIn(code, text)


class NegativeControls(unittest.TestCase):
    """One control per refusal code; each corrupts a real record by one field."""

    def _fires(self, code: str) -> None:
        self.assertIn(code, CONTROLS[code](), f"{code} did not fire")

    def test_schema(self) -> None:
        self._fires("FR_REFUSED_SCHEMA")

    def test_duplicate_key(self) -> None:
        self._fires("FR_REFUSED_DUPLICATE_KEY")

    def test_unclassified_claim(self) -> None:
        self._fires("FR_REFUSED_UNCLASSIFIED_CLAIM")

    def test_unverified_without_method(self) -> None:
        self._fires("FR_REFUSED_UNVERIFIED_WITHOUT_METHOD")

    def test_verification_without_source(self) -> None:
        self._fires("FR_REFUSED_VERIFICATION_WITHOUT_SOURCE")

    def test_proven_without_evidence(self) -> None:
        self._fires("FR_REFUSED_PROVEN_WITHOUT_EVIDENCE")

    def test_frontier_without_both_properties(self) -> None:
        self._fires("FR_REFUSED_FRONTIER_WITHOUT_BOTH_PROPERTIES")

    def test_exceeds_frontier_unproven(self) -> None:
        self._fires("FR_REFUSED_EXCEEDS_FRONTIER_UNPROVEN")

    def test_tool_admitted_incomplete(self) -> None:
        self._fires("FR_REFUSED_TOOL_ADMITTED_INCOMPLETE")

    def test_tool_refusal_without_reason(self) -> None:
        self._fires("FR_REFUSED_TOOL_REFUSAL_WITHOUT_REASON")

    def test_specification_restates_implementation(self) -> None:
        self._fires("FR_REFUSED_SPECIFICATION_RESTATES_IMPLEMENTATION")

    def test_refinement_discharged_without_proof(self) -> None:
        self._fires("FR_REFUSED_REFINEMENT_DISCHARGED_WITHOUT_PROOF")

    def test_hierarchy_drift(self) -> None:
        self._fires("FR_REFUSED_HIERARCHY_DRIFT")

    def test_digest_unsourced(self) -> None:
        self._fires("FR_REFUSED_DIGEST_UNSOURCED")

    def test_do178_certification(self) -> None:
        self._fires("FR_REFUSED_DO178_CERTIFICATION")

    def test_document_drift(self) -> None:
        self._fires("FR_REFUSED_DOCUMENT_DRIFT")

    def test_usage(self) -> None:
        self._fires("FR_REFUSED_USAGE")

    def test_every_declared_code_has_a_firing_control(self) -> None:
        self.assertEqual(set(CONTROLS), set(fr.REFUSALS))
        for code, control in CONTROLS.items():
            self.assertIn(code, control(), f"{code} has no firing control")


class NonVacuity(unittest.TestCase):
    """The acceptance rules can accept; these controls do not describe this project."""

    def test_a_complete_admitted_tool_is_accepted(self) -> None:
        tool = {
            "name": "Control tool",
            "purpose": "a positive control for the admission rule",
            "theorem_class": "a true theorem about a synthetic harness",
            "pinned_version": "1.0",
            "digests": [{"path": "/control/tool", "sha256": KANI_SHA,
                         "recorded_in": ETP4}],
            "tcb": ["the control tool and its harness"],
            "positive_control": {"command": "control --positive",
                                 "observed": "exit 0, the theorem proved"},
            "negative_control": {"command": "control --negative",
                                 "observed": "exit 1, the false near-miss refused"},
            "supported_rustc": {"pinned": "1.98.1", "supported": "1.98.1",
                                "supports_pinned": True},
            "admission": "ADMITTED",
            "refusal_reason": None,
            "verification": {"state": "RECORDED_BY_THIS_PROJECT", "witness": ETP4,
                             "settling_method": "control"},
            "source": "docs/ETP-TODO.md",
        }
        document = {
            "schema": fr.SCHEMA_TOOLS,
            "pinned_toolchain": {"channel": "1.98.1", "source": "rust-toolchain.toml"},
            "tools": [tool],
        }
        self.assertEqual(fr.validate_tools(document, REPO), [])

    def test_a_discharged_edge_with_a_proof_is_accepted(self) -> None:
        level = {
            "id": "LVL-L1", "name": "control level", "constrains": "control",
            "implementation_derived": False,
            "normative_sources": [{
                "document": "a control standard", "clause": "clause", "edition": "edition",
                "verification": {"state": "UNVERIFIED", "witness": None,
                                 "settling_method": "read it"},
            }],
        }
        edge = {
            "id": "RFE-1", "from": "LVL-L1", "to": "LVL-L1", "status": "DISCHARGED",
            "obligation": "control", "evidence": ["evidence/etp-t5/RESULTS.json"],
            "proof": {"kind": "MACHINE_CHECKED_THEOREM",
                      "artefact": "evidence/etp-t5/RESULTS.json"},
            "reason": "control",
        }
        document = {"schema": fr.SCHEMA_HIERARCHY, "levels": [level], "edges": [edge]}
        self.assertEqual(fr.validate_hierarchy(document, REPO, refinement=None), [])

    def test_a_beyond_frontier_claim_with_an_established_match_is_accepted(self) -> None:
        def base(entry_id: str) -> dict:
            return {
                "id": entry_id, "reference": "control", "classification": "REFERENCE_PROOF",
                "proves": "control", "assumes": "control",
                "additional_theorem": "control",
                "this_project": {"state": "NONE", "basis": "control", "evidence": [],
                                 "proof_artefact": None},
                "beyond_frontier": {"claim": False, "matched_property": None,
                                    "added_property": None, "matched_entry": None},
                "verification": {"state": "UNVERIFIED", "witness": None,
                                 "settling_method": "control"},
            }

        established = base("FG-A")
        established["this_project"] = {
            "state": "ESTABLISHED", "basis": "control",
            "evidence": ["evidence/etp-t5/RESULTS.json"],
            "proof_artefact": "evidence/etp-t5/RESULTS.json",
        }
        claimant = base("FG-B")
        claimant["beyond_frontier"] = {
            "claim": True, "matched_property": "the matched property",
            "added_property": "the added property", "matched_entry": "FG-A",
        }
        document = {"schema": fr.SCHEMA_FRONTIER, "base_commit": "a" * 40,
                    "entries": [established, claimant]}
        self.assertEqual(fr.validate_frontier(document, REPO), [])


class Producer(unittest.TestCase):
    def test_producer_is_byte_identical_across_two_runs(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for directory in (first, second):
                result = subprocess.run([sys.executable, str(PRODUCER), "--out", directory],
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name, committed_path in (("FRONTIER-GAPS.json", FRONTIER_PATH),
                                         ("SPECIFICATION-HIERARCHY.json", HIERARCHY_PATH),
                                         ("TOOLS.json", TOOLS_PATH)):
                a = (Path(first) / name).read_bytes()
                b = (Path(second) / name).read_bytes()
                self.assertEqual(a, b, name)
                self.assertEqual(a, committed_path.read_bytes(), name)

    def test_producer_check_exits_zero(self) -> None:
        result = subprocess.run([sys.executable, str(PRODUCER), "--check"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("frontier_entries=15", result.stdout)


class CommandLine(unittest.TestCase):
    def test_check_exits_zero_and_prints_fr_ok(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOLS / "frc_registers.py"), "check"],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("codes=FR_OK", result.stdout)

    def test_inventory_is_deterministic(self) -> None:
        first = subprocess.run(
            [sys.executable, str(TOOLS / "frc_registers.py"), "inventory", "--json"],
            capture_output=True, text=True, check=False)
        second = subprocess.run(
            [sys.executable, str(TOOLS / "frc_registers.py"), "inventory", "--json"],
            capture_output=True, text=True, check=False)
        self.assertEqual(first.returncode, 0)
        self.assertEqual(first.stdout, second.stdout)

    def test_check_output_is_deterministic(self) -> None:
        first = subprocess.run(
            [sys.executable, str(TOOLS / "frc_registers.py"), "check", "--json"],
            capture_output=True, text=True, check=False)
        second = subprocess.run(
            [sys.executable, str(TOOLS / "frc_registers.py"), "check", "--json"],
            capture_output=True, text=True, check=False)
        self.assertEqual(first.stdout, second.stdout)


if __name__ == "__main__":
    unittest.main()
