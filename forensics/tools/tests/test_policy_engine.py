#!/usr/bin/env python3
"""Controls for forensics/tools/policy_engine.py and the A20 records.

One control per refusal code, the conjunction with each obligation individually
unmet, ``UNKNOWN`` never ``MET``, an absent source record, determinism across two
evaluations and two processes, the canonical order in both its forms, the real
decision being ``DENY`` with the expected unmet set, the synthetic positive
reaching ``ADMIT``, the command line and document synchronisation.

Run directly (`python3 forensics/tools/tests/test_policy_engine.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics/tools"
sys.path.insert(0, str(TOOLS))

import policy_engine as pe  # noqa: E402

EVIDENCE = REPO / "evidence/a20"
BUILDER = EVIDENCE / "build_evidence.py"
DOCUMENT = REPO / "docs/POLICY-ENGINE.md"
POLICY_PATH = "evidence/a20/POLICY.json"
BASE_COMMIT = "f34e429f13aa3cc1566e1ecebc185a466765f321"

CLOSED = {"facts": {"state": "CLOSED"}}
OPEN = {"facts": {"state": "OPEN"}}
SKIPPED = {"facts": {"state": "CLOSED", "mode": "skip"}}
NONE_FLAGGED = {"facts": [{"id": "m1", "flag": False}, {"id": "m2", "flag": False}]}
ONE_FLAGGED = {"facts": [{"id": "m1", "flag": True}]}

RECORDS = {
    "control/closed.json": CLOSED,
    "control/open.json": OPEN,
    "control/skipped.json": SKIPPED,
    "control/members-none.json": NONE_FLAGGED,
    "control/members-one.json": ONE_FLAGGED,
}


def obligation(identifier: str, record: str, value: str = "CLOSED", **extra):
    body = {
        "id": identifier,
        "description": f"control obligation {identifier}",
        "required": True,
        "source": {
            "tool": "forensics/tools/policy_engine.py",
            "record": record,
            "locator": "/facts",
        },
        "predicate": {"op": "eq", "path": "/state", "value": value},
    }
    body.update(extra)
    return body


def evaluate(obligations, *, records=None, pin=None, policy=None, candidate=None, runs=1):
    policy = policy or pe.control_policy(obligations)
    return pe.evaluate(
        policy,
        pin if pin is not None else pe.control_pin(policy),
        candidate or pe.control_candidate(),
        reader=pe.memory_reader(records if records is not None else RECORDS),
        runs=runs,
    )


class Controls(unittest.TestCase):
    def setUp(self) -> None:
        self.controls = pe.controls()
        self.by_code = {
            control["code"]: control for control in self.controls if control["code"]
        }

    def test_one_control_per_refusal_code(self) -> None:
        self.assertEqual(sorted(self.by_code), sorted(pe.REFUSAL_CODES))
        self.assertEqual(len(self.by_code), len(pe.REFUSAL_CODES))

    def test_every_control_establishes_its_code(self) -> None:
        for control in self.controls:
            with self.subTest(control=control["id"]):
                self.assertTrue(
                    control["established"],
                    f"{control['id']} did not observe {control['code']}: {control['observed']}",
                )
                if control["code"] is not None:
                    self.assertIn(control["code"], control["observed"]["codes"])
                self.assertEqual(control["kind"], "control-only")

    def test_the_positive_control_reaches_admit(self) -> None:
        positives = [control for control in self.controls if control["code"] is None]
        self.assertEqual([control["id"] for control in positives], ["positive-admit"])
        self.assertEqual(positives[0]["observed"]["decision"], "ADMIT")
        self.assertEqual(positives[0]["observed"]["codes"], [])
        self.assertEqual(positives[0]["observed"]["unmet"], [])

    def test_required_named_controls_are_present(self) -> None:
        required = {
            "score-policy": "PE_REFUSED_SCORE",
            "default-allow": "PE_REFUSED_DEFAULT_ALLOW",
            "unevaluated-as-pass": "PE_REFUSED_OBLIGATION_UNEVALUATED",
            "policy-amended": "PE_REFUSED_POLICY_AMENDED",
            "policy-from-candidate": "PE_REFUSED_POLICY_FROM_CANDIDATE",
            "self-waiver": "PE_REFUSED_SELF_WAIVER",
            "duplicate-obligation": "PE_REFUSED_DUPLICATE_OBLIGATION",
            "decision-order": "PE_REFUSED_ORDER",
            "contradiction": "PE_REFUSED_CONTRADICTION",
        }
        for identifier, code in required.items():
            with self.subTest(control=identifier):
                self.assertIn(identifier, [c["id"] for c in self.controls])
                control = next(c for c in self.controls if c["id"] == identifier)
                self.assertEqual(control["code"], code)
                self.assertTrue(control["established"])


class Conjunction(unittest.TestCase):
    def test_each_obligation_individually_unmet_denies(self) -> None:
        for failing in ("C01.a", "C02.b", "C03.c"):
            with self.subTest(failing=failing):
                obligations = [
                    obligation("C01.a", "control/closed.json"),
                    obligation("C02.b", "control/closed.json"),
                    obligation("C03.c", "control/closed.json"),
                ]
                index = [item["id"] for item in obligations].index(failing)
                obligations[index]["source"]["record"] = "control/open.json"
                decision = evaluate(obligations)
                self.assertEqual(decision["decision"], "DENY")
                self.assertEqual(decision["unmet"], [failing])
                self.assertEqual(decision["codes"], [])
                self.assertEqual(decision["met"], [
                    item["id"] for item in obligations if item["id"] != failing
                ])

    def test_all_obligations_met_is_admit(self) -> None:
        decision = evaluate([
            obligation("C01.a", "control/closed.json"),
            obligation("C02.b", "control/closed.json"),
        ])
        self.assertEqual(decision["decision"], "ADMIT")
        self.assertEqual(decision["codes"], [])
        self.assertEqual(decision["unmet"], [])

    def test_an_advisory_obligation_is_recorded_and_does_not_block(self) -> None:
        policy = pe.control_policy([
            obligation("C01.required", "control/closed.json"),
            obligation("C02.advisory", "control/open.json", required=False),
        ])
        decision = evaluate(policy["obligations"], policy=policy)
        self.assertEqual(decision["decision"], "ADMIT")
        self.assertEqual(decision["unmet"], ["C02.advisory"])
        self.assertEqual(decision["requiredCount"], 1)

    def test_a_required_inapplicable_obligation_never_passes(self) -> None:
        policy = pe.control_policy([
            obligation(
                "C01.inapplicable", "control/skipped.json",
                applicableWhen=[{"field": "mode", "op": "eq", "value": "apply"}],
            )
        ])
        decision = evaluate(policy["obligations"], policy=policy)
        self.assertEqual(decision["decision"], "DENY")
        self.assertEqual(decision["notApplicable"], ["C01.inapplicable"])
        self.assertEqual(decision["codes"], ["PE_REFUSED_OBLIGATION_NOT_APPLICABLE"])


class Unknown(unittest.TestCase):
    def test_unknown_is_never_met(self) -> None:
        policy = pe.control_policy([
            {
                "id": "C01.unknown",
                "description": "a condition the record cannot decide",
                "required": True,
                "source": {
                    "tool": "forensics/tools/policy_engine.py",
                    "record": "control/members-none.json",
                    "locator": "/facts",
                },
                "predicate": {
                    "op": "none",
                    "path": "",
                    "where": [{"field": "absent_field", "op": "truthy"}],
                },
            }
        ])
        decision = evaluate(policy["obligations"], policy=policy)
        entry = decision["obligations"][0]
        self.assertEqual(entry["state"], "UNKNOWN")
        self.assertNotEqual(entry["state"], "MET")
        self.assertEqual(decision["decision"], "DENY")
        self.assertIn("PE_REFUSED_OBLIGATION_UNKNOWN", decision["codes"])

    def test_an_absent_source_record_is_unknown_and_denies(self) -> None:
        policy = pe.control_policy([obligation("C01.missing", "control/absent.json")])
        decision = evaluate(policy["obligations"], policy=policy)
        entry = decision["obligations"][0]
        self.assertEqual(entry["state"], "UNKNOWN")
        self.assertIsNone(entry["recordSha256"])
        self.assertEqual(decision["decision"], "DENY")
        self.assertIn("PE_REFUSED_OBLIGATION_UNEVALUATED", decision["codes"])
        self.assertEqual(decision["unmet"], [])

    def test_an_unresolvable_locator_is_unevaluated(self) -> None:
        policy = pe.control_policy([obligation("C01.locator", "control/closed.json")])
        policy["obligations"][0]["source"]["locator"] = "/nowhere"
        policy["digest"] = pe.policy_digest(policy)
        decision = evaluate(policy["obligations"], policy=policy)
        self.assertIn("PE_REFUSED_OBLIGATION_UNEVALUATED", decision["codes"])
        self.assertEqual(decision["decision"], "DENY")

    def test_an_absent_producing_tool_is_unevaluated(self) -> None:
        policy = pe.control_policy([obligation("C01.tool", "control/closed.json")])
        policy["obligations"][0]["source"]["tool"] = "forensics/tools/absent.py"
        policy["digest"] = pe.policy_digest(policy)
        decision = evaluate(policy["obligations"], policy=policy)
        self.assertIn("PE_REFUSED_OBLIGATION_UNEVALUATED", decision["codes"])


class Determinism(unittest.TestCase):
    def test_two_evaluations_are_byte_identical(self) -> None:
        policy = pe.control_policy([
            obligation("C01.a", "control/closed.json"),
            obligation("C02.b", "control/closed.json"),
        ])
        first = evaluate(policy["obligations"], policy=policy, runs=2)
        second = evaluate(policy["obligations"], policy=policy, runs=2)
        self.assertEqual(pe.decision_bytes(first), pe.decision_bytes(second))

    def test_the_committed_decision_matches_a_live_evaluation(self) -> None:
        policy = pe.load_policy()
        pin = pe.load_pin()
        candidate, problems = pe.resolve_candidate(REPO, commit=BASE_COMMIT)
        self.assertEqual(problems, [])
        decision = pe.evaluate(
            policy, pin, candidate, reader=pe.filesystem_reader(REPO),
            root=REPO, policy_path=POLICY_PATH, runs=2,
        )
        committed = (EVIDENCE / "DECISION.json").read_bytes()
        self.assertEqual(
            pe.decision_bytes(decision), committed,
            "the committed decision is stale: regenerate it with "
            "python3 evidence/a20/build_evidence.py",
        )

    def test_two_processes_are_byte_identical(self) -> None:
        command = [sys.executable, str(TOOLS / "policy_engine.py"), "evaluate", "--json"]
        first = subprocess.run(command, cwd=str(REPO), capture_output=True, text=True)
        second = subprocess.run(command, cwd=str(REPO), capture_output=True, text=True)
        self.assertEqual(first.returncode, 1)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stdout.encode("utf-8"), (EVIDENCE / "DECISION.json").read_bytes())

    def test_a_changing_source_is_refused_as_nondeterministic(self) -> None:
        policy = pe.control_policy([obligation("C01.a", "control/closed.json")])
        counter = {"n": 0}

        def alternating(relative: str):
            if relative == "control/closed.json":
                counter["n"] += 1
                body = CLOSED if counter["n"] <= 1 else OPEN
                return pe.canonical(body).encode("utf-8"), None
            return pe.memory_reader(RECORDS)(relative)

        decision = pe.evaluate(
            policy, pe.control_pin(policy), pe.control_candidate(),
            reader=alternating, runs=2,
        )
        self.assertEqual(decision["decision"], "DENY")
        self.assertIn("PE_REFUSED_NONDETERMINISTIC", decision["codes"])


class Order(unittest.TestCase):
    def test_a_policy_out_of_canonical_order_is_refused(self) -> None:
        policy = pe.control_policy([
            obligation("C02.b", "control/closed.json"),
            obligation("C01.a", "control/closed.json"),
        ])
        decision = evaluate(policy["obligations"], policy=policy)
        self.assertEqual(decision["codes"], ["PE_REFUSED_ORDER"])
        self.assertEqual(decision["decision"], "DENY")

    def test_a_reordered_decision_is_refused(self) -> None:
        policy = pe.control_policy([
            obligation("C01.a", "control/closed.json"),
            obligation("C02.b", "control/closed.json"),
        ])
        decision = evaluate(policy["obligations"], policy=policy)
        self.assertEqual(pe.verify_decision(decision, policy), [])
        reordered = json.loads(json.dumps(decision))
        reordered["obligations"] = list(reversed(reordered["obligations"]))
        reordered["order"] = list(reversed(reordered["order"]))
        problems = pe.verify_decision(reordered, policy)
        self.assertEqual({problem["code"] for problem in problems}, {"PE_REFUSED_ORDER"})

    def test_the_committed_decision_has_the_canonical_order(self) -> None:
        decision = json.loads((EVIDENCE / "DECISION.json").read_text(encoding="utf-8"))
        policy = pe.load_policy()
        self.assertEqual(pe.verify_decision(decision, policy), [])
        self.assertEqual(decision["order"], sorted(decision["order"]))


class RealPolicy(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = pe.load_policy()
        self.pin = pe.load_pin()
        self.decision = json.loads((EVIDENCE / "DECISION.json").read_text(encoding="utf-8"))

    def test_the_policy_declares_denial_by_default_and_no_score(self) -> None:
        self.assertEqual(self.policy["default"], "deny")
        self.assertIs(self.policy["scores"], False)
        self.assertEqual(pe.validate_policy(self.policy), [])
        self.assertEqual(pe.policy_digest(self.policy), self.policy["digest"])
        self.assertEqual(len(self.policy["obligations"]), 8)

    def test_the_policy_names_eight_distinct_records(self) -> None:
        ids = [item["id"] for item in self.policy["obligations"]]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(
            ids,
            [
                "A05.populations-admitted",
                "A06.suppression-member-identities",
                "A07.delta-resolution-conditions",
                "A12.independent-attestation",
                "A14.release-authorised",
                "A15.release-threshold-met",
                "A17.forward-freeze-closed",
                "A19.retraction-propagated",
            ],
        )
        for item in self.policy["obligations"]:
            self.assertTrue((REPO / item["source"]["record"]).is_file())
            self.assertTrue((REPO / item["source"]["tool"]).is_file())

    def test_the_real_decision_is_deny_with_the_expected_unmet_set(self) -> None:
        self.assertEqual(self.decision["decision"], "DENY")
        self.assertEqual(
            self.decision["unmet"],
            [
                "A06.suppression-member-identities",
                "A12.independent-attestation",
                "A14.release-authorised",
                "A15.release-threshold-met",
                "A17.forward-freeze-closed",
            ],
        )
        self.assertEqual(self.decision["met"], [
            "A05.populations-admitted",
            "A07.delta-resolution-conditions",
            "A19.retraction-propagated",
        ])
        self.assertEqual(self.decision["unknown"], [])
        self.assertEqual(self.decision["notApplicable"], [])
        self.assertEqual(self.decision["codes"], [])

    def test_the_pin_records_the_policy_and_verifies(self) -> None:
        candidate, problems = pe.resolve_candidate(REPO, commit=BASE_COMMIT)
        self.assertEqual(problems, [])
        self.assertEqual(pe.verify_pin(self.policy, self.pin, candidate, POLICY_PATH), [])
        self.assertEqual(self.pin["policyDigest"], self.policy["digest"])
        self.assertEqual(self.pin["candidate"]["commit"], BASE_COMMIT)

    def test_an_amended_policy_is_refused_against_the_pin(self) -> None:
        amended = json.loads(json.dumps(self.policy))
        amended["obligations"] = [
            item for item in amended["obligations"] if item["id"] != "A12.independent-attestation"
        ]
        amended["digest"] = pe.policy_digest(amended)
        candidate, _ = pe.resolve_candidate(REPO, commit=BASE_COMMIT)
        self.assertIn(
            "PE_REFUSED_POLICY_AMENDED",
            [problem["code"] for problem in pe.verify_pin(amended, self.pin, candidate, POLICY_PATH)],
        )

    def test_the_candidate_cannot_supply_the_policy(self) -> None:
        candidate, _ = pe.resolve_candidate(REPO, commit=BASE_COMMIT)
        producer = candidate["producedBy"]["identity"]
        self.assertNotEqual(self.policy["provenance"]["establishedBy"]["identity"], producer)
        ours = json.loads(json.dumps(self.policy))
        ours["provenance"]["establishedBy"]["identity"] = producer
        ours["digest"] = pe.policy_digest(ours)
        decision = pe.evaluate(
            ours, pe.control_pin(ours, policyId=ours["policyId"], policyDigest=ours["digest"],
                                 policyPath=POLICY_PATH),
            candidate, reader=pe.filesystem_reader(REPO), root=REPO,
            policy_path=POLICY_PATH, runs=1,
        )
        self.assertIn("PE_REFUSED_POLICY_FROM_CANDIDATE", decision["codes"])
        self.assertEqual(decision["decision"], "DENY")

    def test_the_decision_contains_no_timestamp(self) -> None:
        def keys(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    yield key
                    yield from keys(item)
            elif isinstance(value, list):
                for item in value:
                    yield from keys(item)

        forbidden = {"recordedAt", "evaluatedAt", "generatedAt", "timestamp", "time", "date"}
        self.assertEqual(sorted(forbidden & set(keys(self.decision))), [])


class CommandLine(unittest.TestCase):
    def run_cli(self, *arguments: str):
        return subprocess.run(
            [sys.executable, str(TOOLS / "policy_engine.py"), *arguments],
            cwd=str(REPO), capture_output=True, text=True,
        )

    def test_evaluate_prints_the_decision_and_the_code(self) -> None:
        result = self.run_cli("evaluate")
        self.assertEqual(result.returncode, 1)
        self.assertIn("decision: DENY", result.stdout)
        self.assertIn("codes=NONE", result.stdout)
        self.assertIn("A12.independent-attestation", result.stdout)
        self.assertIn("unmet: A06.suppression-member-identities", result.stdout)

    def test_explain_prints_the_obligation_and_exits_one_when_unmet(self) -> None:
        result = self.run_cli("explain", "A12.independent-attestation")
        self.assertEqual(result.returncode, 1)
        self.assertIn("obligation: id=A12.independent-attestation state=UNMET", result.stdout)
        self.assertIn("record=evidence/a12/VERIFICATION.json", result.stdout)
        self.assertIn("locator=/verifications", result.stdout)
        self.assertIn("decision: DENY", result.stdout)

    def test_explain_exits_zero_for_a_met_obligation(self) -> None:
        result = self.run_cli("explain", "A07.delta-resolution-conditions")
        self.assertEqual(result.returncode, 0)
        self.assertIn("state=MET", result.stdout)

    def test_explain_an_unknown_obligation_exits_two_with_a_code(self) -> None:
        result = self.run_cli("explain", "A99.not-an-obligation")
        self.assertEqual(result.returncode, 2)
        self.assertIn("code=PE_USAGE", result.stdout)

    def test_verify_pin_exits_zero_and_prints_the_decision(self) -> None:
        result = self.run_cli("verify-pin")
        self.assertEqual(result.returncode, 0)
        self.assertIn("pin-check: code=PE_OK", result.stdout)
        self.assertIn("decision: DENY", result.stdout)

    def test_verify_decision_exits_zero_for_the_committed_decision(self) -> None:
        result = self.run_cli("verify-decision")
        self.assertEqual(result.returncode, 0)
        self.assertIn("decision-check: code=PE_OK", result.stdout)

    def test_an_unreadable_policy_is_a_usage_error(self) -> None:
        result = self.run_cli("evaluate", "--policy", "evidence/a20/absent.json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("PE_USAGE", result.stdout)

    def test_a_refused_decision_exits_one_and_prints_every_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            policy = pe.control_policy([
                obligation("C01.a", "control/closed.json"),
                obligation("C02.b", "control/open.json"),
            ])
            path.write_bytes(pe.decision_bytes(policy))
            result = self.run_cli(
                "evaluate", "--policy", str(path), "--pin", str(EVIDENCE / "POLICY-PIN.json"),
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("decision: DENY", result.stdout)
            self.assertIn("PE_REFUSED_POLICY_UNRECORDED", result.stdout)


class Producer(unittest.TestCase):
    def test_the_producer_reproduces_the_committed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for directory in (first, second):
                run = subprocess.run(
                    [sys.executable, str(BUILDER), "--out", directory],
                    cwd=str(REPO), capture_output=True, text=True,
                )
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            for name in ("POLICY.json", "POLICY-PIN.json", "DECISION.json", "CONTROLS.json"):
                with self.subTest(name=name):
                    committed = (EVIDENCE / name).read_bytes()
                    self.assertEqual((Path(first) / name).read_bytes(), committed)
                    self.assertEqual((Path(second) / name).read_bytes(), committed)

    def test_the_committed_policy_is_the_produced_policy(self) -> None:
        policy = pe.load_policy()
        self.assertEqual(pe.validate_policy(policy), [])
        self.assertEqual(policy["digest"], pe.policy_digest(policy))
        self.assertEqual(policy["policyId"], "release-policy")


class DocumentSynchronisation(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DOCUMENT.read_text(encoding="utf-8")

    def test_every_refusal_code_is_named_in_the_document(self) -> None:
        for code in pe.REFUSAL_CODES:
            with self.subTest(code=code):
                self.assertIn(code, self.text)

    def test_the_document_names_no_unknown_refusal_code(self) -> None:
        import re

        named = set(re.findall(r"PE_REFUSED_[A-Z_]+", self.text))
        self.assertEqual(sorted(named - set(pe.REFUSAL_CODES)), [])

    def test_the_document_names_the_real_obligations_and_sources(self) -> None:
        for item in pe.load_policy()["obligations"]:
            with self.subTest(obligation=item["id"]):
                self.assertIn(item["id"], self.text)
                self.assertIn(item["source"]["record"], self.text)

    def test_the_document_names_the_command_line(self) -> None:
        for command in ("evaluate", "explain", "verify-pin", "verify-decision"):
            with self.subTest(command=command):
                self.assertIn(f"policy_engine.py {command}", self.text)


if __name__ == "__main__":
    unittest.main()
