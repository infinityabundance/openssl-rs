#!/usr/bin/env python3
"""Controls for forensics/tools/corrections.py and the A19 records.

One control per refusal code; a chain of two corrections; a fork; a cycle; a
retraction that propagates to a dependent and the same retraction with the
dependent left valid (refused); a spurious invalidation; the canonical chain
digest; the real log round trip; determinism; the command line with printed
codes; and document synchronisation.

Run directly (`python3 forensics/tools/tests/test_corrections.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics/tools"
sys.path.insert(0, str(TOOLS))

import corrections as cr  # noqa: E402

EVIDENCE = REPO / "evidence/a19"
BUILDER = EVIDENCE / "build_evidence.py"
DOCUMENT = REPO / "docs/CORRECTIONS.md"
EVENTS = EVIDENCE / "EVENTS.json"
STATUS = EVIDENCE / "STATUS.json"
PROPAGATION = EVIDENCE / "PROPAGATION.json"
CONTROLS = EVIDENCE / "CONTROLS.json"
NAMES = ("EVENTS.json", "PROPAGATION.json",
         "STATUS.json", "CONTROLS.json")

P_CAMPAIGN = "P-CAMPAIGN"

# The test that fires each refusal code.  The document's refusal table must
# name both this test and the control id from CONTROLS.json.
CODE_TO_TEST = {
    cr.CR_REFUSED_EVENT_INVALID: "test_event_invalid",
    cr.CR_REFUSED_UNBOUND_CORRECTION: "test_unbound_correction",
    cr.CR_REFUSED_PREDECESSOR_MISMATCH: "test_predecessor_mismatch",
    cr.CR_REFUSED_ORIGINAL_MISMATCH: "test_original_mismatch",
    cr.CR_REFUSED_HISTORY_ERASED: "test_history_erased",
    cr.CR_REFUSED_FORK: "test_fork",
    cr.CR_REFUSED_CYCLE: "test_cycle",
    cr.CR_REFUSED_SUBJECT_CHANGED: "test_subject_changed",
    cr.CR_REFUSED_RETRACTION_UNBOUND: "test_retraction_unbound",
    cr.CR_REFUSED_UNSIGNED: "test_unsigned",
    cr.CR_REFUSED_SIGNATURE: "test_signature",
    cr.CR_REFUSED_ROLE: "test_role",
    cr.CR_REFUSED_ASSERTION_EXISTS: "test_assertion_exists",
    cr.CR_REFUSED_EVENT_ID_REUSED: "test_event_id_reused",
    cr.CR_REFUSED_INVALIDATION_NOT_PROPAGATED: "test_invalidation_not_propagated",
    cr.CR_REFUSED_SPURIOUS_INVALIDATION: "test_spurious_invalidation",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_builder() -> Any:
    spec = importlib.util.spec_from_file_location("a19_builder", BUILDER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


BUILDER_MODULE = load_builder()


def value(v: Any, citation: str = "control") -> dict[str, Any]:
    return {
        "value": v,
        "digest": cr.value_digest(v),
        "citation": citation,
        "record": None,
    }


def event(
    event_id: str,
    kind: str,
    subject: str = "control-subject",
    *,
    previous: dict[str, Any] | None = None,
    old: dict[str, Any] | None = None,
    new: dict[str, Any] | None = None,
    role: str | None = None,
    identity: str = P_CAMPAIGN,
    signed: bool = True,
) -> dict[str, Any]:
    return BUILDER_MODULE.control_event(
        event_id,
        kind,
        subject,
        previous=previous,
        old=old,
        new=new,
        role=role,
        identity=identity,
        signed=signed,
    )


def chain() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    return BUILDER_MODULE._chain()


def expect(code: str, fn: Callable[[], Any]) -> None:
    try:
        fn()
    except cr.Refusal as refusal:
        if refusal.code != code:
            raise AssertionError(
                f"observed {refusal.code}, expected {code}: {refusal.message}"
            ) from refusal
    else:
        raise AssertionError(f"expected {code}, nothing was refused")


class ControlCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controls = load_json(CONTROLS)

    def test_every_refusal_code_has_a_control(self) -> None:
        covered = {row["code"] for row in self.controls["controls"]}
        self.assertEqual(covered, set(cr.REFUSALS))

    def test_every_control_observed_its_own_code(self) -> None:
        for row in self.controls["controls"]:
            self.assertTrue(row["controlOnly"], row["id"])
            self.assertEqual(row["observed"]["code"], row["code"], row["id"])

    def test_the_counts_are_the_recorded_ones(self) -> None:
        self.assertEqual(self.controls["coverage"]["refusalCodes"], 16)
        self.assertEqual(self.controls["coverage"]["controls"], 16)
        self.assertEqual(self.controls["coverage"]["positive"], 2)

    def test_both_positives_reach_cr_ok(self) -> None:
        for row in self.controls["positive"]:
            self.assertEqual(row["observed"]["code"], cr.CODE_OK, row["id"])


class Chain(unittest.TestCase):
    def test_a_chain_of_two_corrections(self) -> None:
        log, first, second, third = chain()
        row = cr.current(log, "control-subject")
        self.assertEqual(row["outcome"], cr.OUTCOME_CORRECTED)
        self.assertEqual(row["acceptedEventId"], "C3")
        self.assertEqual(row["accepted"]["value"], {"v": 3})
        self.assertEqual(
            [item["kind"] for item in row["history"]],
            ["assert", "correct", "correct"],
        )
        self.assertEqual(
            [item["eventId"] for item in row["history"]], ["C1", "C2", "C3"]
        )

    def test_canonical_chain_digest(self) -> None:
        log, _, _, _ = chain()
        self.assertEqual(log["logDigest"], cr.log_digest(log["history"]))
        for event_row, history_row in zip(log["events"], log["history"]):
            self.assertEqual(history_row["digest"], cr.event_digest(event_row))
        cr.check_log(log)
        edited = json.loads(json.dumps(log))
        edited["events"][1]["reason"] = "rewritten"
        expect(cr.CR_REFUSED_HISTORY_ERASED, lambda: cr.check_log(edited))
        deleted = json.loads(json.dumps(log))
        deleted["history"].pop(1)
        expect(cr.CR_REFUSED_HISTORY_ERASED, lambda: cr.check_log(deleted))

    def test_fork(self) -> None:
        log, first, _, _ = chain()
        fork = event(
            "F1",
            "correct",
            previous=first,
            old=first["newValue"],
            new=value({"v": 10}),
        )
        expect(cr.CR_REFUSED_FORK, lambda: cr.append(log, fork))
        # A forked log that bypasses append has no unique accepted tip.
        forked = json.loads(json.dumps(log))
        forked["events"].append(fork)
        forked["history"].append(cr._history_entry(fork))
        forked["logDigest"] = cr.log_digest(forked["history"])
        row = cr.current(forked, "control-subject")
        self.assertEqual(row["outcome"], cr.OUTCOME_DISPUTED)
        self.assertIsNone(row["accepted"])
        self.assertTrue(row["reasons"])

    def test_cycle(self) -> None:
        log, _, _, _ = chain()
        cyclic = json.loads(json.dumps(log))
        cyclic["events"][0]["supersedes"] = {
            "previousEventId": "C3",
            "previousDigest": cr.event_digest(cyclic["events"][2]),
        }
        cyclic["history"] = [cr._history_entry(item) for item in cyclic["events"]]
        cyclic["logDigest"] = cr.log_digest(cyclic["history"])
        cyclic = cr.sign_log(cyclic)
        follower = event(
            "C4",
            "correct",
            previous=cyclic["events"][2],
            old=cyclic["events"][2]["newValue"],
            new=value({"v": 11}),
        )
        expect(cr.CR_REFUSED_CYCLE, lambda: cr.append(cyclic, follower))

    def test_retraction_keeps_history_and_has_no_accepted_value(self) -> None:
        log, _, _, third = chain()
        retraction = event(
            "RT1",
            "retract",
            previous=third,
            old=third["newValue"],
            new=None,
        )
        retracted = cr.append(log, retraction)
        row = cr.current(retracted, "control-subject")
        self.assertEqual(row["outcome"], cr.OUTCOME_RETRACTED)
        self.assertIsNone(row["accepted"])
        self.assertEqual(len(row["history"]), 4)
        self.assertEqual(row["history"][-1]["kind"], "retract")
        self.assertEqual(row["history"][0]["kind"], "assert")

    def test_unknown_subject(self) -> None:
        log, _, _, _ = chain()
        row = cr.current(log, "not-a-subject")
        self.assertEqual(row["outcome"], cr.OUTCOME_UNKNOWN)
        self.assertIsNone(row["accepted"])
        self.assertEqual(row["history"], [])

    def test_retraction_propagates_to_a_dependent(self) -> None:
        log, _, _, third = chain()
        retraction = event(
            "RT1", "retract", previous=third, old=third["newValue"], new=None
        )
        retracted = cr.append(log, retraction)
        report = cr.propagate(
            retracted,
            [
                {
                    "id": "dependent",
                    "cites": [third["newValue"]["digest"]],
                    "declared": "INVALIDATED",
                }
            ],
        )
        self.assertEqual(report["code"], cr.CODE_OK)
        self.assertEqual(report["summary"]["invalidated"], 1)
        self.assertEqual(report["dependents"][0]["supersededBy"], ["RT1"])

    def test_retraction_with_a_dependent_left_valid_is_refused(self) -> None:
        log, _, _, third = chain()
        retraction = event(
            "RT1", "retract", previous=third, old=third["newValue"], new=None
        )
        retracted = cr.append(log, retraction)
        expect(
            cr.CR_REFUSED_INVALIDATION_NOT_PROPAGATED,
            lambda: cr.propagate(
                retracted,
                [
                    {
                        "id": "stale",
                        "cites": [third["newValue"]["digest"]],
                        "declared": "VALID",
                    }
                ],
            ),
        )

    def test_spurious_invalidation(self) -> None:
        log, _, _, third = chain()
        retraction = event(
            "RT1", "retract", previous=third, old=third["newValue"], new=None
        )
        retracted = cr.append(log, retraction)
        expect(
            cr.CR_REFUSED_SPURIOUS_INVALIDATION,
            lambda: cr.propagate(
                retracted,
                [{"id": "spurious", "cites": ["f" * 64], "declared": "INVALIDATED"}],
            ),
        )


class Refusals(unittest.TestCase):
    def test_event_invalid(self) -> None:
        expect(
            cr.CR_REFUSED_EVENT_INVALID,
            lambda: cr.validate_event_structure(
                {"eventId": "X", "kind": "assert", "subject": "s"}
            ),
        )

    def test_unbound_correction(self) -> None:
        log, first, _, _ = chain()
        expect(
            cr.CR_REFUSED_UNBOUND_CORRECTION,
            lambda: cr.validate_event_structure(
                {
                    "eventId": "X",
                    "kind": "correct",
                    "subject": "control-subject",
                    "supersedes": {"previousEventId": "C1"},
                    "reason": "r",
                    "oldValue": first["newValue"],
                    "newValue": value({"v": 9}),
                    "recordedAt": "2026-11-24T00:00:00Z",
                    "recordedBy": {"role": "producer", "identity": P_CAMPAIGN},
                    "evidence": ["control-only"],
                }
            ),
        )

    def test_predecessor_mismatch(self) -> None:
        log, first, _, _ = chain()
        bad = event(
            "X",
            "correct",
            previous=first,
            old=first["newValue"],
            new=value({"v": 9}),
        )
        bad["supersedes"]["previousDigest"] = "0" * 64
        bad = cr.sign_event(bad)
        expect(
            cr.CR_REFUSED_PREDECESSOR_MISMATCH,
            lambda: cr.append(cr.append(cr.new_log(), first), bad),
        )

    def test_original_mismatch(self) -> None:
        _, first, _, _ = chain()
        wrong = event(
            "X",
            "correct",
            previous=first,
            old=value({"v": 999}),
            new=value({"v": 9}),
        )
        expect(
            cr.CR_REFUSED_ORIGINAL_MISMATCH,
            lambda: cr.append(cr.append(cr.new_log(), first), wrong),
        )

    def test_history_erased(self) -> None:
        log, _, _, _ = chain()
        edited = json.loads(json.dumps(log))
        edited["events"][0]["reason"] = "rewritten"
        expect(cr.CR_REFUSED_HISTORY_ERASED, lambda: cr.check_log(edited))

    def test_fork(self) -> None:
        log, first, _, _ = chain()
        fork = event(
            "F1", "correct", previous=first, old=first["newValue"], new=value({"v": 10})
        )
        expect(cr.CR_REFUSED_FORK, lambda: cr.append(log, fork))

    def test_cycle(self) -> None:
        log, _, _, _ = chain()
        cyclic = json.loads(json.dumps(log))
        cyclic["events"][0]["supersedes"] = {
            "previousEventId": "C3",
            "previousDigest": cr.event_digest(cyclic["events"][2]),
        }
        cyclic["history"] = [cr._history_entry(item) for item in cyclic["events"]]
        cyclic["logDigest"] = cr.log_digest(cyclic["history"])
        cyclic = cr.sign_log(cyclic)
        follower = event(
            "C4",
            "correct",
            previous=cyclic["events"][2],
            old=cyclic["events"][2]["newValue"],
            new=value({"v": 11}),
        )
        expect(cr.CR_REFUSED_CYCLE, lambda: cr.append(cyclic, follower))

    def test_subject_changed(self) -> None:
        _, first, _, _ = chain()
        changed = event(
            "S1",
            "correct",
            subject="different-subject",
            previous=first,
            old=first["newValue"],
            new=value({"v": 12}),
        )
        expect(
            cr.CR_REFUSED_SUBJECT_CHANGED,
            lambda: cr.append(cr.append(cr.new_log(), first), changed),
        )

    def test_retraction_unbound(self) -> None:
        ghost = event("G1", "assert", subject="never-asserted", new=value({"v": 0}))
        unbound = event(
            "R1",
            "retract",
            subject="never-asserted",
            previous=ghost,
            old=value({"v": 0}),
            new=None,
        )
        expect(
            cr.CR_REFUSED_RETRACTION_UNBOUND,
            lambda: cr.append(cr.new_log(), unbound),
        )

    def test_unsigned(self) -> None:
        unsigned = event("U1", "assert", new=value({"v": 1}), signed=False)
        expect(cr.CR_REFUSED_UNSIGNED, lambda: cr.append(cr.new_log(), unsigned))

    def test_signature(self) -> None:
        _, first, _, _ = chain()
        tampered = json.loads(json.dumps(first))
        tampered["reason"] = "changed after signing"
        expect(
            cr.CR_REFUSED_SIGNATURE,
            lambda: cr.append(cr.new_log(), tampered),
        )

    def test_role(self) -> None:
        outsider = event("P1", "assert", new=value({"v": 1}), identity="P-UNASSIGNED")
        expect(cr.CR_REFUSED_ROLE, lambda: cr.append(cr.new_log(), outsider))

    def test_assertion_exists(self) -> None:
        _, first, _, _ = chain()
        second_assert = event("A2", "assert", new=value({"v": 2}))
        expect(
            cr.CR_REFUSED_ASSERTION_EXISTS,
            lambda: cr.append(cr.append(cr.new_log(), first), second_assert),
        )

    def test_event_id_reused(self) -> None:
        _, first, _, _ = chain()
        duplicate = event("C1", "assert", subject="another-subject", new=value({"v": 3}))
        expect(
            cr.CR_REFUSED_EVENT_ID_REUSED,
            lambda: cr.append(cr.append(cr.new_log(), first), duplicate),
        )

    def test_invalidation_not_propagated(self) -> None:
        log, _, _, third = chain()
        retraction = event(
            "RT1", "retract", previous=third, old=third["newValue"], new=None
        )
        retracted = cr.append(log, retraction)
        expect(
            cr.CR_REFUSED_INVALIDATION_NOT_PROPAGATED,
            lambda: cr.propagate(
                retracted,
                [
                    {
                        "id": "stale",
                        "cites": [third["newValue"]["digest"]],
                        "declared": "VALID",
                    }
                ],
            ),
        )

    def test_spurious_invalidation(self) -> None:
        log, _, _, third = chain()
        retraction = event(
            "RT1", "retract", previous=third, old=third["newValue"], new=None
        )
        retracted = cr.append(log, retraction)
        expect(
            cr.CR_REFUSED_SPURIOUS_INVALIDATION,
            lambda: cr.propagate(
                retracted,
                [{"id": "spurious", "cites": ["f" * 64], "declared": "INVALIDATED"}],
            ),
        )


class RealLog(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.log = load_json(EVENTS)
        cls.status = load_json(STATUS)
        cls.propagation = load_json(PROPAGATION)
        cls.controls = load_json(CONTROLS)

    def test_the_log_verifies(self) -> None:
        report = cr.verify_log(self.log)
        self.assertEqual(report["code"], cr.CODE_OK)
        self.assertEqual(report["events"], 22)
        self.assertEqual(len(report["subjects"]), 11)

    def test_status_matches_current(self) -> None:
        for row in self.status["subjects"]:
            current = cr.current(self.log, row["subject"])
            self.assertEqual(current["outcome"], row["outcome"], row["subject"])
            self.assertEqual(
                current["acceptedEventId"], row["acceptedEventId"], row["subject"]
            )
            self.assertIn("history", row)
            self.assertEqual(
                [item["eventId"] for item in current["history"]], row["history"]
            )

    def test_every_event_is_self_issued_and_unauthenticated(self) -> None:
        for event_row in self.log["events"]:
            self.assertEqual(
                event_row["authentication"]["status"], "SELF_ISSUED"
            )
            self.assertFalse(event_row["authentication"]["authenticated"])
        self.assertEqual(self.status["summary"]["authenticated"], 0)
        self.assertEqual(self.log["authentication"]["status"], "SELF_ISSUED")
        self.assertFalse(self.log["authentication"]["authenticated"])

    def test_the_outcome_counts_are_the_recorded_ones(self) -> None:
        outcomes = self.status["summary"]["outcomes"]
        self.assertEqual(outcomes[cr.OUTCOME_CORRECTED], 6)
        self.assertEqual(outcomes[cr.OUTCOME_RETRACTED], 5)
        self.assertEqual(outcomes[cr.OUTCOME_DISPUTED], 0)
        self.assertEqual(outcomes[cr.OUTCOME_UNKNOWN], 0)
        self.assertEqual(self.status["summary"]["subjects"], 11)
        self.assertEqual(self.status["summary"]["events"], 22)

    def test_every_binding_is_exact(self) -> None:
        by_id = {row["eventId"]: row for row in self.log["events"]}
        for row in self.log["events"]:
            if row["kind"] == cr.KIND_ASSERT:
                continue
            previous = by_id[row["supersedes"]["previousEventId"]]
            self.assertEqual(
                row["supersedes"]["previousDigest"], cr.event_digest(previous)
            )
            self.assertEqual(row["oldValue"]["digest"], previous["newValue"]["digest"])
            self.assertEqual(
                (row["oldValue"].get("record") or {}).get("sha256"),
                (previous["newValue"].get("record") or {}).get("sha256"),
            )

    def test_propagation_is_recorded_and_clean(self) -> None:
        summary = self.propagation["summary"]
        self.assertEqual(summary["stale"], 0)
        self.assertEqual(summary["spurious"], 0)
        self.assertEqual(summary["invalidated"], summary["dependents"])
        self.assertEqual(self.propagation["codes"], [])
        for row in self.propagation["dependents"]:
            self.assertEqual(row["state"], "INVALIDATED", row["id"])
            self.assertTrue(row["citations"], row["id"])

    def test_the_committed_propagation_recomputes(self) -> None:
        rows = self.propagation["dependents"]
        report = cr.propagate_report(self.log, rows)
        self.assertEqual(report["code"], cr.CODE_OK)
        for key in ("dependents", "invalidated", "valid", "stale", "spurious"):
            self.assertEqual(
                report["summary"][key], self.propagation["summary"][key], key
            )

    def test_every_original_is_preserved(self) -> None:
        for row in self.status["subjects"]:
            preservation = row["originalPreservation"]
            self.assertTrue(preservation["path"], row["subject"])
            self.assertTrue(preservation["section"], row["subject"])
            self.assertTrue(preservation["note"], row["subject"])
            self.assertIn(row["recordedAs"], {
                "prose-only",
                "machine-readable-unsigned",
                "signed",
                "not-recorded",
            })

    def test_the_claim_retractions_record_their_successor_state(self) -> None:
        successors = {
            row["subject"]: row["successorState"]
            for row in self.status["subjects"]
            if row["successorState"] is not None
        }
        self.assertEqual(successors["ETP0-CLM-004/verdict"], "SUPERSEDED")
        self.assertEqual(successors["ETP0-CLM-005/verdict"], "SUPERSEDED")
        self.assertEqual(successors["ETP0-CLM-030/verdict"], "RISK_ACCEPTED")
        self.assertEqual(successors["ETP0-CLM-032/verdict"], "SUPERSEDED")


class Determinism(unittest.TestCase):
    def test_two_runs_are_byte_identical_and_match_committed(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for output in (first, second):
                completed = subprocess.run(
                    [sys.executable, str(BUILDER), "--out", output],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
            for name in NAMES:
                one = (Path(first) / name).read_bytes()
                two = (Path(second) / name).read_bytes()
                committed = (EVIDENCE / name).read_bytes()
                self.assertEqual(one, two, name)
                self.assertEqual(one, committed, name)


class CommandLine(unittest.TestCase):
    def run_tool(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOLS / "corrections.py"), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_verify_exits_zero_and_prints_the_code(self) -> None:
        completed = self.run_tool("verify", "--log", str(EVENTS))
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("code=CR_OK", completed.stdout)

    def test_history_exits_zero_and_prints_the_outcome(self) -> None:
        completed = self.run_tool(
            "history", "A7/sourceIdentity", "--log", str(EVENTS)
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("code=CR_OK", completed.stdout)
        self.assertIn("outcome=CORRECTED", completed.stdout)
        self.assertIn("acceptedValue=", completed.stdout)

    def test_unknown_subject_exits_one_with_the_code(self) -> None:
        completed = self.run_tool(
            "history", "no-such-subject", "--log", str(EVENTS)
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("code=CR_UNKNOWN", completed.stdout)

    def test_propagate_exits_zero_and_prints_the_code(self) -> None:
        completed = self.run_tool("propagate", "--log", str(EVENTS))
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("code=CR_OK", completed.stdout)
        self.assertIn("invalidated=", completed.stdout)

    def test_append_refuses_an_unsigned_event_and_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "EVENTS.json"
            log_path.write_text(EVENTS.read_text(encoding="utf-8"), encoding="utf-8")
            unsigned = event("CLI-U1", "assert", subject="cli", new=value({"v": 1}), signed=False)
            event_path = Path(directory) / "event.json"
            event_path.write_text(
                json.dumps(unsigned, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            completed = self.run_tool(
                "append", str(event_path), "--log", str(log_path)
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("code=CR_REFUSED_UNSIGNED", completed.stdout)

    def test_a_usage_error_exits_two_with_the_code(self) -> None:
        completed = self.run_tool("history")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("CR_USAGE", completed.stdout + completed.stderr)


class DocumentSynchronisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8")
        cls.controls = load_json(CONTROLS)
        cls.status = load_json(STATUS)

    def test_every_code_appears_in_the_refusal_table(self) -> None:
        for code in cr.REFUSALS:
            self.assertIn(f"`{code}`", self.text, code)

    def test_every_code_names_its_control_and_its_test(self) -> None:
        control_for = {row["code"]: row["id"] for row in self.controls["controls"]}
        available = {
            name
            for cls in (Refusals, Chain, RealLog)
            for name in dir(cls)
            if name.startswith("test_")
        }
        for code, test_name in CODE_TO_TEST.items():
            self.assertIn(test_name, self.text, code)
            self.assertIn(control_for[code], self.text, code)
            self.assertIn(test_name, available, test_name)

    def test_every_control_is_named(self) -> None:
        for row in self.controls["controls"] + self.controls["positive"]:
            self.assertIn(row["id"], self.text, row["id"])

    def test_every_subject_and_authentication_status_is_named(self) -> None:
        for row in self.status["subjects"]:
            self.assertIn(row["subject"], self.text, row["subject"])
            self.assertIn(row["outcome"], self.text, row["subject"])
            self.assertIn(row["recordedAs"], self.text, row["subject"])
        self.assertIn("No event is authenticated", self.text)

    def test_the_a12_caveat_and_non_claims_are_present(self) -> None:
        self.assertIn("## 11. The A12 caveat on the signature", self.text)
        self.assertIn("test-only:hmac-sha256:8e10a5a15d233d54", self.text)
        self.assertIn("## 12. Non-claims", self.text)
        self.assertIn("## `NOT_RUN`", self.text)

    def test_the_document_names_the_mechanism(self) -> None:
        self.assertIn("forensics/tools/corrections.py", self.text)
        self.assertIn("forensics/tools/tests/test_corrections.py", self.text)
        self.assertIn("evidence/a19/", self.text)


if __name__ == "__main__":
    unittest.main()
