#!/usr/bin/env python3
"""Negative controls for the ETP-T10 closure-discipline audit.

The audit makes three claims that need independent controls:

* an exclusion argument passes only when all five bar requirements hold, and
  each requirement is load-bearing on its own;
* an opaque operation is scoped only when its contract states an assumption, a
  scope and a falsifier, otherwise it is listed as unscoped;
* an aggregate that reports a pass while containing a blocked row is refused,
  and the refusal is not softened when the blocked row is a recorded dissent.

A determinism control requires two builds of the real documents to be byte
identical, and a reproduction control requires the committed evidence to match
a fresh build at the commit it names.

Run inside the court:

    python3 forensics/tools/tests/test_closure_discipline.py
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import closure_discipline as cd  # noqa: E402

EVIDENCE = cd.EVIDENCE_DIR


def check_record(procedure="proc", identity=None, absent=None) -> dict:
    return cd._check_record(
        procedure, ["input"], identity if identity is not None else {"x": 1},
        absent or [])


class ExclusionBarControls(unittest.TestCase):
    """Each of the five bar requirements is necessary, and all five suffice."""

    def test_complete_argument_passes(self) -> None:
        bar = cd._evaluate_bar({"identity": "x"}, "a reason", check_record())
        self.assertTrue(bar["passes"])
        self.assertEqual(bar["disposition"], cd.DISPOSITION_ARGUMENT)

    def test_a_missing_edge_identity_fails(self) -> None:
        bar = cd._evaluate_bar(None, "a reason", check_record())
        self.assertFalse(bar["passes"])
        self.assertIn("edge_identity", bar["missing"])

    def test_a_missing_reason_fails(self) -> None:
        bar = cd._evaluate_bar({"identity": "x"}, "", check_record())
        self.assertFalse(bar["passes"])
        self.assertIn("reason", bar["missing"])

    def test_a_missing_procedure_fails(self) -> None:
        record = cd._check_record("", ["input"], {"x": 1}, [])
        bar = cd._evaluate_bar({"identity": "x"}, "a reason", record)
        self.assertFalse(bar["passes"])
        self.assertIn("procedure", bar["missing"])

    def test_a_missing_identity_binding_fails(self) -> None:
        record = cd._check_record("proc", ["input"], {}, [])
        bar = cd._evaluate_bar({"identity": "x"}, "a reason", record)
        self.assertFalse(bar["passes"])
        self.assertIn("identity_binding", bar["missing"])

    def test_an_absent_input_fails_checkable_result(self) -> None:
        record = cd._check_record("proc", ["input"], {"x": 1}, ["input"])
        bar = cd._evaluate_bar({"identity": "x"}, "a reason", record)
        self.assertFalse(bar["passes"])
        self.assertIn("checkable_result", bar["missing"])

    def test_an_admitted_limitation_never_passes(self) -> None:
        bar = cd._evaluate_bar(None, "", None)
        self.assertFalse(bar["passes"])
        self.assertEqual(bar["disposition"], cd.DISPOSITION_ADMITTED)

    def test_a_reason_without_a_check_is_an_assertion(self) -> None:
        bar = cd._evaluate_bar(None, "a reason", None)
        self.assertFalse(bar["passes"])
        self.assertEqual(bar["disposition"], cd.DISPOSITION_ASSERTION)

    def test_an_unsampled_target_drop_is_counted_and_fails(self) -> None:
        receipt = {
            "family": "synthetic",
            "candidate_identity": {
                "install_prefix": "artifacts/install",
                "libcrypto_so_3_sha256": "0" * 64,
            },
            "source_identity": {"inventory_path": "does/not/exist.json"},
            "edge_provenance": {
                "exclusion_reasons": {"not-contributed-by-reachable-callers": 3},
                "records_sample": [{
                    "edge_id": "e",
                    "exclusions": [{"target": "T", "reason": "not-contributed"}],
                }],
            },
        }
        audit = cd.audit_receipt_dict(receipt, consumer="synthetic")
        drops = [r for r in audit["rows"]
                 if r["category"] == cd.CATEGORY_TARGET_DROP]
        self.assertEqual(len(drops), 2)
        unrecorded = [r for r in drops if r["edge"] is None]
        self.assertEqual(len(unrecorded), 1)
        self.assertFalse(unrecorded[0]["bar"]["passes"])
        self.assertEqual(
            unrecorded[0]["bar"]["disposition"], cd.DISPOSITION_ASSERTION)
        self.assertFalse(
            audit["target_drop_sample"]["complete"])


class OpaqueContractControls(unittest.TestCase):
    """A contract is scoped only with an assumption, a scope and a falsifier."""

    def test_a_registry_class_is_scoped(self) -> None:
        contract, missing = cd._contract_record("ABI_CONTRACT_PROVIDER")
        self.assertIsNotNone(contract)
        self.assertEqual(missing, [])
        self.assertTrue(contract.get("contract"))
        self.assertTrue(contract.get("covers"))
        self.assertTrue(contract.get("does_not_cover"))

    def test_an_unknown_class_is_unscoped(self) -> None:
        contract, missing = cd._contract_record("ABI_NOT_A_CLASS")
        self.assertIsNone(contract)
        self.assertTrue(missing)

    def test_an_abi_class_without_a_contract_is_listed(self) -> None:
        receipt = {"precision": {"unresolved_by_class": {"ABI_MYSTERY": 4}}}
        audit = cd.audit_opaque_dict(receipt, consumer="synthetic")
        self.assertEqual(audit["unscoped_contract_rows"], 1)
        self.assertEqual(audit["operations"][0]["operation"], "ABI_MYSTERY")
        self.assertFalse(audit["operations"][0]["scoped_contract"])

    def test_a_dlsym_literal_without_a_contract_is_listed(self) -> None:
        receipt = {"precision": {"dlsym_literals": {
            "libcrypto.so.3": {
                "ERR_get_state": {"sites": 1, "exported": True},
                "MYSTERY": {"sites": 2, "exported": True},
            }}}}
        audit = cd.audit_opaque_dict(receipt, consumer="synthetic")
        listed = {r["operation"]: r for r in audit["operations"]}
        self.assertNotIn("ERR_get_state", listed)  # covered by the registry
        self.assertIn("MYSTERY", listed)
        self.assertFalse(listed["MYSTERY"]["scoped_contract"])
        self.assertEqual(listed["MYSTERY"]["sites"], 2)

    def test_an_unmodelled_shared_object_is_listed(self) -> None:
        receipt = {"artifact_identity": {"dynamic": {
            "needed": ["libcrypto.so.3", "libc.so.6"]}}}
        audit = cd.audit_opaque_dict(receipt, consumer="synthetic")
        operations = [r["operation"] for r in audit["operations"]]
        self.assertIn("libc.so.6", operations)
        self.assertNotIn("libcrypto.so.3", operations)


class AggregateControls(unittest.TestCase):
    """An aggregate that passes while containing a blocked row is refused."""

    def test_a_pass_with_a_blocked_row_is_refused(self) -> None:
        row = {"id": "cell", "state": "NOT_ESTABLISHED", "blocked": True,
               "locator": "cell"}
        result = cd._aggregate("synthetic", Path(__file__).resolve(), {},
                               "PASS", "verdict.value", [row])
        self.assertEqual(
            result["refusal"]["code"], "CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW")
        self.assertTrue(result["blocked_rows_visible_in_document"])

    def test_a_failure_with_a_blocked_row_is_not_refused(self) -> None:
        row = {"id": "cell", "state": "NOT_ESTABLISHED", "blocked": True,
               "locator": "cell"}
        result = cd._aggregate("synthetic", Path(__file__).resolve(), {},
                               "FAIL", "verdict.value", [row])
        self.assertIsNone(result["refusal"])

    def test_the_real_freeze_keeps_its_blocked_rows_visible(self) -> None:
        result = cd.audit_aggregates()
        freeze = next(a for a in result["aggregates"]
                      if a["aggregate"] == "freeze-b85c")
        self.assertEqual(freeze["reported_overall_state"], "FAIL")
        self.assertTrue(freeze["blocked_rows"])
        self.assertTrue(freeze["blocked_rows_visible_in_document"])
        self.assertIsNone(freeze["refusal"])

    def test_the_real_risk_acceptance_reports_failure_and_is_accepted(self) -> None:
        result = cd.audit_aggregates()
        graduation = next(
            a for a in result["aggregates"]
            if a["aggregate"] == "safe-compatible-openssh-b85c")
        self.assertEqual(graduation["reported_overall_state"], "FAIL")
        self.assertIn("dissent", graduation["blocked_rows"])
        self.assertTrue(graduation["blocked_rows_visible_in_document"])
        self.assertIsNone(graduation["refusal"])

    def test_the_historical_graduation_pass_still_refuses(self) -> None:
        history = cd.REPO_ROOT / "evidence/etp-t15/history/SAFE-COMPATIBLE-openssh-b85c.json"
        result = cd._aggregate_graduation(history, "safe-compatible-openssh-b85c-history")
        self.assertEqual(result["reported_overall_state"], "PASS")
        self.assertIn("dissent", result["blocked_rows"])
        self.assertEqual(
            result["refusal"]["code"],
            "CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW")

    def test_a_retraction_of_a_sub_claim_is_not_a_blocked_row(self) -> None:
        result = cd.audit_aggregates()
        graduation = next(
            a for a in result["aggregates"]
            if a["aggregate"] == "safe-compatible-openssh-b85c")
        retraction = next(
            r for r in graduation["rows"] if r["id"] == "retraction")
        self.assertFalse(retraction["blocked"])
        self.assertEqual(retraction["state"], "RETRACTED_SUB_CLAIM")


class DeterminismControls(unittest.TestCase):
    """Two builds over the same records are byte identical and reproducible."""

    def test_build_documents_is_byte_stable(self) -> None:
        commit = cd._check_commit(cd.REPO_ROOT)
        first = cd.build_documents(commit)
        second = cd.build_documents(commit)
        for left, right in zip(first, second):
            self.assertEqual(
                json.dumps(left, indent=2, sort_keys=True).encode(),
                json.dumps(right, indent=2, sort_keys=True).encode())

    def test_aggregate_audit_is_stable(self) -> None:
        first = json.dumps(cd.audit_aggregates(), sort_keys=True)
        second = json.dumps(cd.audit_aggregates(), sort_keys=True)
        self.assertEqual(first, second)

    def test_committed_evidence_matches_a_fresh_build(self) -> None:
        exclusions_path = EVIDENCE / "EXCLUSIONS.json"
        opaque_path = EVIDENCE / "OPAQUE-OPERATIONS.json"
        if not exclusions_path.is_file() or not opaque_path.is_file():
            self.skipTest("ETP-T10 evidence has not been emitted")
        exclusions = json.loads(exclusions_path.read_text(encoding="utf-8"))
        commit = exclusions["identity"]["commit"]
        fresh_exclusions, fresh_opaque = cd.build_documents(commit)
        self.assertEqual(
            json.dumps(fresh_exclusions, indent=2, sort_keys=True) + "\n",
            exclusions_path.read_text(encoding="utf-8"))
        self.assertEqual(
            json.dumps(fresh_opaque, indent=2, sort_keys=True) + "\n",
            opaque_path.read_text(encoding="utf-8"))

    def test_self_test_passes(self) -> None:
        self.assertEqual(cd.self_test(), 0)


if __name__ == "__main__":
    unittest.main()
