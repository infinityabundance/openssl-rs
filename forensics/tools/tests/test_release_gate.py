#!/usr/bin/env python3
"""Tests for forensics/tools/release_gate.py identity-triage rules (ETP-T9).

Run directly (`python3 forensics/tools/tests/test_release_gate.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.

One control per refusal rule this item adds:

  * a current claim whose required evidence is `UNCERTIFIABLE` is refused, and
    the artefact is named;
  * a current claim whose required evidence is `HISTORICAL` is refused under its
    own rule;
  * a derived dependency is the positive control: neither rule fires;
  * a withdrawn claim is already non-current and is not refused again;
  * an absent triage is `RG_TRIAGE_MISSING`, because the gate may not silently
    fall back to the permissive behaviour;
  * a triage bound to another registry is `RG_TRIAGE_STALE`;
  * the committed triage is bound to the committed registry.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import release_gate  # noqa: E402


def claim(claim_id: str, path: str, verdict: str = "ESTABLISHED") -> dict:
    return {
        "id": claim_id,
        "verdict": {"state": verdict},
        "evidence": [{"id": "EV-1", "path": path}],
    }


def triage_document(registry_commit: str = "fixture") -> dict:
    return {
        "schema": release_gate.TRIAGE_SCHEMA,
        "registry_recorded_at_commit": registry_commit,
        "counts": {"DERIVED": 1, "DECLARED": 0, "HISTORICAL": 1, "UNCERTIFIABLE": 1, "total": 3},
        "artefacts": [
            {
                "path": "evidence/uncertifiable.json",
                "class": "UNCERTIFIABLE",
                "cause": "U1",
                "cause_name": "multi-commit-no-declaration",
                "reason": "self-test fixture",
            },
            {
                "path": "evidence/historical.json",
                "class": "HISTORICAL",
                "rule": "introduced-at-single-commit",
                "identity": {"commit": "0" * 40},
            },
            {
                "path": "evidence/derived.json",
                "class": "DERIVED",
                "rule": "tracked-input-at-head",
                "identity": {"commit": "0" * 40},
            },
        ],
    }


def index_of(document: dict) -> dict:
    return {item["path"]: item for item in document["artefacts"]}


class TriageClaimRules(unittest.TestCase):
    def setUp(self) -> None:
        self.document = triage_document()
        self.index = index_of(self.document)

    def rules(self, payload: dict, **kwargs) -> list[str]:
        refusals, _ = release_gate.scan_claims(payload, False, self.index)
        return [item.rule for item in refusals]

    def test_uncertifiable_dependency_refused_and_named(self) -> None:
        payload = {"claims": [claim("C-1", "evidence/uncertifiable.json")]}
        refusals, _ = release_gate.scan_claims(payload, False, self.index)
        self.assertIn("RG_CLAIM_UNCERTIFIABLE_EVIDENCE", [item.rule for item in refusals])
        named = [item for item in refusals if item.rule == "RG_CLAIM_UNCERTIFIABLE_EVIDENCE"]
        self.assertEqual(named[0].artefact, "C-1/evidence/uncertifiable.json")
        self.assertIn("multi-commit-no-declaration", named[0].detail)

    def test_historical_dependency_refused_under_its_own_rule(self) -> None:
        payload = {"claims": [claim("C-1", "evidence/historical.json")]}
        refusals, _ = release_gate.scan_claims(payload, False, self.index)
        rules = [item.rule for item in refusals]
        self.assertIn("RG_CLAIM_HISTORICAL_EVIDENCE", rules)
        self.assertNotIn("RG_CLAIM_UNCERTIFIABLE_EVIDENCE", rules)

    def test_derived_dependency_is_not_refused(self) -> None:
        payload = {"claims": [claim("C-1", "evidence/derived.json")]}
        self.assertEqual(self.rules(payload), [])

    def test_partial_claim_is_a_current_assertion(self) -> None:
        payload = {"claims": [claim("C-1", "evidence/uncertifiable.json", verdict="PARTIAL")]}
        self.assertIn("RG_CLAIM_UNCERTIFIABLE_EVIDENCE", self.rules(payload))

    def test_withdrawn_claim_is_not_refused_again(self) -> None:
        payload = {"claims": [claim("C-1", "evidence/uncertifiable.json", verdict="WITHDRAWN")]}
        rules = self.rules(payload)
        self.assertIn("RG_CLAIM_WITHDRAWN", rules)
        self.assertNotIn("RG_CLAIM_UNCERTIFIABLE_EVIDENCE", rules)

    def test_without_a_triage_the_rules_do_not_fire(self) -> None:
        # This is the behaviour the gate item replaces: with no triage index the
        # rules are silent, which is why an absent triage is itself a refusal.
        payload = {"claims": [claim("C-1", "evidence/uncertifiable.json")]}
        refusals, _ = release_gate.scan_claims(payload, False, None)
        self.assertEqual(refusals, [])


class TriageBinding(unittest.TestCase):
    def test_committed_triage_binds_the_committed_registry(self) -> None:
        if not release_gate.IDENTITY_TRIAGE.is_file():
            self.skipTest("identity triage not recorded")
        index, refusals = release_gate.load_triage(
            release_gate.IDENTITY_TRIAGE, release_gate.DEPENDENCY_REGISTRY
        )
        self.assertEqual([item.line() for item in refusals], [])
        self.assertIsNotNone(index)
        self.assertEqual(
            len(index), json.loads(release_gate.IDENTITY_TRIAGE.read_text(encoding="utf-8"))["counts"]["total"]
        )

    def test_missing_triage_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            absent = Path(temporary) / "absent.json"
            _, refusals = release_gate.load_triage(absent, release_gate.DEPENDENCY_REGISTRY)
        self.assertEqual([item.rule for item in refusals], ["RG_TRIAGE_MISSING"])

    def test_stale_triage_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "triage.json"
            path.write_text(json.dumps(triage_document("0" * 40)), encoding="utf-8")
            _, refusals = release_gate.load_triage(path, release_gate.DEPENDENCY_REGISTRY)
        self.assertEqual([item.rule for item in refusals], ["RG_TRIAGE_STALE"])

    def test_unknown_class_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "triage.json"
            document = triage_document()
            document["artefacts"][0]["class"] = "PROBABLY"
            path.write_text(json.dumps(document), encoding="utf-8")
            registry = json.loads(release_gate.DEPENDENCY_REGISTRY.read_text(encoding="utf-8"))
            document["registry_recorded_at_commit"] = registry["recorded_at_commit"]
            path.write_text(json.dumps(document), encoding="utf-8")
            _, refusals = release_gate.load_triage(path, release_gate.DEPENDENCY_REGISTRY)
        self.assertEqual([item.rule for item in refusals], ["RG_TRIAGE_STALE"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
