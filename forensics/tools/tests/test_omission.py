#!/usr/bin/env python3
"""Controls for forensics/tools/omission.py and the A17 records.

One control per refusal code; the reconciliation arithmetic with each term
individually perturbed; ``UNREADABLE`` versus ``MISSING`` in both directions; a
``PASS`` summary over a missing member refused; a signed reconciliation whose
bytes were mutated after signing refused; the real A15 cycle producing all five
members with the committed digests; the forward freeze ``OPEN`` with its
freeze-time state recorded; determinism; the live view (labelled ``LIVE``, never
written into a record); the command line's exit codes and printed codes; and
document synchronisation.

A control mutates a synthetic freeze, artefact and reconciliation in memory or in
a temporary directory. It is not a source change and not a defect report: a
control that fires proves the refusal works, not that the substituted form
occurs anywhere in the tree.

Run directly (`python3 forensics/tools/tests/test_omission.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.
"""

from __future__ import annotations

import copy
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
EVIDENCE = REPO / "evidence/a17"
BUILDER_PATH = EVIDENCE / "build_evidence.py"
TOOL = TOOLS / "omission.py"
DOCUMENT = REPO / "docs/OMISSION-RESISTANCE.md"
sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402
import omission as om  # noqa: E402

CANDIDATE = {"baseCommit": "0" * 40, "baseCommitShort": "000000000", "branch": "staging"}
FROZEN_AT = "2026-01-01T00:00:00Z"
OBSERVED_AT = "2026-01-01T01:00:00Z"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_builder() -> Any:
    spec = importlib.util.spec_from_file_location("a17_builder", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def fixture() -> Path:
    directory = Path(tempfile.mkdtemp(prefix="a17-test-"))
    (directory / "a.json").write_bytes(b"control-only bytes\n")
    return directory


def plan(members: list[dict[str, Any]] | None = None, state: str = om.STATE_FROZEN) -> dict[str, Any]:
    if members is None:
        members = [
            {
                "id": "a",
                "path": "evidence/x/a.json",
                "predicate": "the control-only artefact exists",
                "required": True,
                "phase": "control",
            }
        ]
    return {"id": "a17-test", "state": state, "members": members}


def frozen(**kwargs: Any) -> dict[str, Any]:
    return om.freeze(plan(**kwargs), FROZEN_AT, CANDIDATE)


def observed(directory: Path, **overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": "a",
        "path": "evidence/x/a.json",
        "file": str(directory / "a.json"),
        "readable": True,
        "recordedAt": OBSERVED_AT,
    }
    entry.update(overrides)
    return {"artefacts": [entry]}


def refusal(call: Callable[[], Any]) -> str:
    try:
        call()
    except om.Refusal as caught:
        return caught.code
    return "NO_REFUSAL"


def close_good(directory: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    freeze = frozen()
    return freeze, om.close(freeze, observed(directory), closed_at=OBSERVED_AT)


class RefusalCatalogue(unittest.TestCase):
    def test_every_code_is_stable_and_documented(self) -> None:
        self.assertEqual(set(om.REFUSALS), set(om.CODE_ORDER))
        self.assertEqual(len(om.CODE_ORDER), len(set(om.CODE_ORDER)))
        for code, entry in om.REFUSALS.items():
            self.assertIn(code, om.CODE_ORDER)
            self.assertTrue(entry["prevents"].strip(), code)
            self.assertTrue(entry["rule"].strip(), code)

    def test_the_required_codes_are_all_present(self) -> None:
        required = {
            "OM_REFUSED_FREEZE_ABSENT",
            "OM_REFUSED_FREEZE_AFTER_EXECUTION",
            "OM_REFUSED_FREEZE_AMENDED",
            "OM_REFUSED_MISSING_SILENT",
            "OM_REFUSED_UNEXPECTED_UNDECLARED",
            "OM_REFUSED_RECONCILIATION_UNSIGNED",
            "OM_REFUSED_RECONCILIATION_MUTATED",
            "OM_REFUSED_DUPLICATE_EXPECTED",
            "OM_REFUSED_DIGEST_MISMATCH",
            "OM_REFUSED_EXIT_AS_PRODUCED",
            "OM_REFUSED_PASS_WITH_MISSING",
            "OM_REFUSED_POPULATION_DRIFT",
            "OM_REFUSED_UNREADABLE_AS_ABSENT",
        }
        self.assertTrue(required <= set(om.REFUSALS))


class ControlsRecord(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.record = load_json(EVIDENCE / "CONTROLS.json")

    def test_every_control_is_control_only(self) -> None:
        self.assertTrue(self.record["note"].startswith("Every control here is control-only"))
        for control in self.record["controls"]:
            self.assertTrue(control["controlOnly"], control["id"])
        self.assertTrue(self.record["positive"]["controlOnly"])

    def test_every_refusal_code_has_a_control(self) -> None:
        codes = {control["code"] for control in self.record["controls"]}
        self.assertEqual(codes, set(om.REFUSALS))

    def test_every_control_observed_its_expected_code(self) -> None:
        for control in self.record["controls"]:
            self.assertEqual(
                control["observed"]["codes"], [control["code"]], control["id"]
            )

    def test_rebuilding_the_controls_reproduces_the_committed_record(self) -> None:
        builder = load_builder()
        rebuilt = builder.controls_document()
        self.assertEqual(
            [(entry["id"], entry["code"], entry["observed"]) for entry in rebuilt["controls"]],
            [
                (entry["id"], entry["code"], entry["observed"])
                for entry in self.record["controls"]
            ],
        )
        self.assertEqual(
            rebuilt["positive"]["observed"], self.record["positive"]["observed"]
        )

    def test_the_two_named_controls_are_present(self) -> None:
        by_id = {control["id"]: control for control in self.record["controls"]}
        self.assertEqual(
            by_id["pass-with-missing"]["code"], om.OM_REFUSED_PASS_WITH_MISSING
        )
        self.assertEqual(
            by_id["reconciliation-mutated"]["code"],
            om.OM_REFUSED_RECONCILIATION_MUTATED,
        )


class ReconciliationArithmetic(unittest.TestCase):
    def test_the_freeze_carries_only_the_member_count(self) -> None:
        document = frozen()
        self.assertEqual(document["memberCount"], len(document["members"]))
        counts = [
            key
            for key in document
            if key != "memberCount"
            and ("count" in key.lower() or key.lower() in {"total", "size", "length"})
        ]
        self.assertEqual(counts, [])

    def test_each_term_is_counted_and_reconciles(self) -> None:
        directory = fixture()
        freeze = frozen(
            members=[
                {"id": "p", "path": "evidence/x/p.json", "predicate": "produced",
                 "required": True, "phase": "control"},
                {"id": "m", "path": "evidence/x/m.json", "predicate": "missing",
                 "required": True, "phase": "control"},
                {"id": "u", "path": "evidence/x/u.json", "predicate": "unreadable",
                 "required": True, "phase": "control"},
                {"id": "d", "path": "evidence/x/d.json", "predicate": "digest",
                 "required": True, "phase": "control",
                 "expectedDigest": "0" * 64},
            ]
        )
        observations = {
            "artefacts": [
                {"id": "p", "path": "evidence/x/p.json",
                 "file": str(directory / "a.json"), "recordedAt": OBSERVED_AT},
                {"id": "u", "path": "evidence/x/u.json",
                 "file": str(directory / "a.json"), "readable": False,
                 "recordedAt": OBSERVED_AT},
                {"id": "d", "path": "evidence/x/d.json",
                 "file": str(directory / "a.json"), "recordedAt": OBSERVED_AT},
            ]
        }
        reconciliation = om.close(freeze, observations, closed_at=OBSERVED_AT)
        summary = reconciliation["summary"]
        self.assertEqual(summary["expected"], 4)
        self.assertEqual(summary["produced"], 1)
        self.assertEqual(summary["missing"], 1)
        self.assertEqual(summary["unreadable"], 1)
        self.assertEqual(summary["digestMismatch"], 1)
        self.assertEqual(summary["unexpected"], 0)
        self.assertEqual(
            summary["expected"],
            summary["produced"]
            + summary["missing"]
            + summary["unreadable"]
            + summary["digestMismatch"],
        )
        self.assertFalse(summary["pass"])

    def test_each_perturbed_term_is_refused(self) -> None:
        directory = fixture()
        freeze, reconciliation = close_good(directory)
        for term in ("produced", "missing", "unreadable", "digestMismatch"):
            broken = copy.deepcopy(reconciliation)
            broken["summary"][term] += 1
            self.assertEqual(
                refusal(lambda: om.check(freeze, broken)),
                om.OM_REFUSED_COUNT_UNBALANCED,
                term,
            )

    def test_unexpected_is_separate_from_expected(self) -> None:
        directory = fixture()
        freeze = frozen()
        observations = {
            "artefacts": observed(directory)["artefacts"]
            + [{"id": "z", "path": "evidence/x/z.json", "recordedAt": OBSERVED_AT}]
        }
        reconciliation = om.close(freeze, observations, closed_at=OBSERVED_AT)
        summary = reconciliation["summary"]
        self.assertEqual(summary["expected"], 1)
        self.assertEqual(summary["unexpected"], 1)
        self.assertEqual(
            summary["produced"]
            + summary["missing"]
            + summary["unreadable"]
            + summary["digestMismatch"],
            summary["expected"],
        )


class UnreadableVersusMissing(unittest.TestCase):
    def test_the_two_states_are_recorded_distinctly(self) -> None:
        directory = fixture()
        freeze = frozen()
        missing = om.close(
            freeze, observed(directory, file="absent.json"), closed_at=OBSERVED_AT
        )
        unreadable = om.close(
            freeze, observed(directory, readable=False), closed_at=OBSERVED_AT
        )
        self.assertEqual(missing["members"][0]["state"], om.STATE_MISSING)
        self.assertEqual(unreadable["members"][0]["state"], om.STATE_UNREADABLE)

    def test_unreadable_closed_as_missing_is_refused(self) -> None:
        directory = fixture()
        freeze = frozen()
        observations = observed(directory, readable=False)
        reconciliation = om.close(freeze, observations, closed_at=OBSERVED_AT)
        reconciliation["members"][0]["state"] = om.STATE_MISSING
        reconciliation["summary"]["unreadable"] = 0
        reconciliation["summary"]["missing"] = 1
        reconciliation["summary"]["unreadableIds"] = []
        reconciliation["summary"]["missingIds"] = ["a"]
        self.assertEqual(
            refusal(
                lambda: om.check(freeze, reconciliation, observed=observations)
            ),
            om.OM_REFUSED_UNREADABLE_AS_ABSENT,
        )

    def test_absent_closed_as_unreadable_is_refused(self) -> None:
        directory = fixture()
        freeze = frozen()
        observations = observed(directory, file="absent.json")
        reconciliation = om.close(freeze, observations, closed_at=OBSERVED_AT)
        reconciliation["members"][0]["state"] = om.STATE_UNREADABLE
        reconciliation["summary"]["missing"] = 0
        reconciliation["summary"]["unreadable"] = 1
        reconciliation["summary"]["missingIds"] = []
        reconciliation["summary"]["unreadableIds"] = ["a"]
        self.assertEqual(
            refusal(
                lambda: om.check(freeze, reconciliation, observed=observations)
            ),
            om.OM_REFUSED_UNREADABLE_AS_ABSENT,
        )


class PassSummaries(unittest.TestCase):
    def _missing(self) -> tuple[dict[str, Any], dict[str, Any]]:
        directory = fixture()
        freeze = frozen()
        reconciliation = om.close(
            freeze, observed(directory, file="absent.json"), closed_at=OBSERVED_AT
        )
        return freeze, reconciliation

    def test_pass_over_missing_is_refused(self) -> None:
        freeze, reconciliation = self._missing()
        reconciliation["summary"]["pass"] = True
        self.assertEqual(
            refusal(lambda: om.check(freeze, reconciliation)),
            om.OM_REFUSED_PASS_WITH_MISSING,
        )

    def test_pass_over_unreadable_is_refused(self) -> None:
        directory = fixture()
        freeze = frozen()
        reconciliation = om.close(
            freeze, observed(directory, readable=False), closed_at=OBSERVED_AT
        )
        reconciliation["summary"]["pass"] = True
        self.assertEqual(
            refusal(lambda: om.check(freeze, reconciliation)),
            om.OM_REFUSED_UNREADABLE_AS_ABSENT,
        )

    def test_pass_over_digest_mismatch_is_refused(self) -> None:
        directory = fixture()
        freeze = frozen()
        reconciliation = om.close(
            freeze, observed(directory, digest="0" * 64), closed_at=OBSERVED_AT
        )
        reconciliation["summary"]["pass"] = True
        self.assertEqual(
            refusal(lambda: om.check(freeze, reconciliation)),
            om.OM_REFUSED_DIGEST_MISMATCH,
        )

    def test_a_closed_open_freeze_never_passes(self) -> None:
        directory = fixture()
        freeze = frozen(state=om.STATE_OPEN)
        reconciliation = om.close(
            freeze, observed(directory), closed_at=OBSERVED_AT
        )
        self.assertFalse(reconciliation["summary"]["pass"])
        self.assertIn("OPEN", reconciliation["summary"]["note"])


class Signing(unittest.TestCase):
    def test_a_valid_envelope_verifies(self) -> None:
        directory = fixture()
        freeze, reconciliation = close_good(directory)
        envelope = om.sign(reconciliation)
        result = om.verify(freeze, reconciliation, envelope)
        self.assertEqual(result["code"], om.CODE_VERIFIED)
        self.assertTrue(result["summary"]["pass"])

    def test_the_signature_is_over_the_canonical_bytes(self) -> None:
        directory = fixture()
        _freeze, reconciliation = close_good(directory)
        envelope = om.sign(reconciliation)
        payload = dsse.strict_b64decode(envelope["payload"], "payload")
        self.assertEqual(payload, om.canonical_bytes(reconciliation))

    def test_an_unsigned_reconciliation_is_refused(self) -> None:
        directory = fixture()
        freeze, reconciliation = close_good(directory)
        self.assertEqual(
            refusal(lambda: om.verify(freeze, reconciliation, None)),
            om.OM_REFUSED_RECONCILIATION_UNSIGNED,
        )

    def test_a_mutated_signed_reconciliation_is_refused(self) -> None:
        directory = fixture()
        freeze, reconciliation = close_good(directory)
        envelope = om.sign(reconciliation)
        mutated = copy.deepcopy(reconciliation)
        mutated["members"][0]["predicate"] = "mutated after signing"
        self.assertEqual(
            refusal(lambda: om.verify(freeze, mutated, envelope)),
            om.OM_REFUSED_RECONCILIATION_MUTATED,
        )

    def test_a_tampered_signature_is_refused(self) -> None:
        directory = fixture()
        freeze, reconciliation = close_good(directory)
        envelope = om.sign(reconciliation)
        envelope["signatures"][0]["sig"] = dsse.strict_b64encode(b"\x00" * 32)
        self.assertEqual(
            refusal(lambda: om.verify(freeze, reconciliation, envelope)),
            om.OM_REFUSED_SIGNATURE_INVALID,
        )


class RealA15Cycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.freeze = load_json(EVIDENCE / "FREEZE-a15.json")
        cls.reconciliation = load_json(EVIDENCE / "RECONCILIATION-a15.json")
        cls.envelope = (EVIDENCE / "RECONCILIATION-a15.envelope.json").read_bytes()

    def test_all_five_members_are_produced(self) -> None:
        summary = self.reconciliation["summary"]
        self.assertEqual(summary["expected"], 5)
        self.assertEqual(summary["produced"], 5)
        self.assertEqual(summary["missing"], 0)
        self.assertEqual(summary["unreadable"], 0)
        self.assertEqual(summary["digestMismatch"], 0)
        self.assertEqual(summary["unexpected"], 0)
        self.assertTrue(summary["pass"])

    def test_every_produced_digest_equals_the_committed_one(self) -> None:
        for member in self.reconciliation["members"]:
            self.assertEqual(member["state"], om.STATE_PRODUCED, member["id"])
            self.assertEqual(
                member["digest"],
                om.sha256_file(REPO / member["path"]),
                member["id"],
            )
        for member in self.freeze["members"]:
            self.assertEqual(
                member["expectedDigest"],
                om.sha256_file(REPO / member["path"]),
                member["id"],
            )

    def test_the_signed_cycle_verifies(self) -> None:
        result = om.verify(self.freeze, self.reconciliation, self.envelope)
        self.assertEqual(result["code"], om.CODE_VERIFIED)
        self.assertTrue(result["summary"]["pass"])

    def test_the_envelope_names_the_test_only_key(self) -> None:
        envelope = json.loads(self.envelope.decode("utf-8"))
        self.assertEqual(
            envelope["signatures"][0]["keyid"], dsse.test_only_keyid()
        )


class ForwardFreeze(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.freeze = load_json(EVIDENCE / "FREEZE-forward.json")
        cls.status = load_json(EVIDENCE / "STATUS.json")

    def test_the_forward_freeze_is_open(self) -> None:
        self.assertEqual(self.freeze["state"], om.STATE_OPEN)
        self.assertEqual(self.freeze["memberCount"], 20)
        self.assertEqual(len(self.freeze["members"]), 20)

    def test_it_declares_the_remaining_queue_items(self) -> None:
        ids = {member["id"] for member in self.freeze["members"]}
        expected = {f"a{index}-receipt" for index in range(18, 28)}
        expected |= {f"b{index}-receipt" for index in range(1, 9)}
        expected |= {"b0-registry", "b0-service-configuration"}
        self.assertEqual(ids, expected)
        for member in self.freeze["members"]:
            self.assertTrue(member["required"])

    def test_it_is_not_closed_and_has_no_reconciliation(self) -> None:
        self.assertFalse((EVIDENCE / "RECONCILIATION-forward.json").exists())
        cycle = next(
            entry
            for entry in self.status["cycles"]
            if entry["id"] == "forward-open-freeze"
        )
        self.assertEqual(cycle["kind"], "OPEN")
        self.assertEqual(cycle["state"], om.STATE_OPEN)
        self.assertFalse(cycle["closed"])
        self.assertIsNone(cycle["reconciliation"])
        self.assertFalse(self.status["forwardFreeze"]["closed"])

    def test_closing_it_today_reports_every_member_missing(self) -> None:
        workdir = Path(tempfile.mkdtemp(prefix="a17-forward-"))
        reconciliation = om.close(self.freeze, observed_dir=workdir)
        summary = reconciliation["summary"]
        self.assertEqual(summary["expected"], 20)
        self.assertEqual(summary["produced"], 0)
        self.assertEqual(summary["missing"], 20)
        self.assertFalse(summary["pass"])

    def test_the_status_records_the_freeze_time_state_not_the_present(self) -> None:
        cycle = next(
            entry
            for entry in self.status["cycles"]
            if entry["id"] == "forward-open-freeze"
        )
        self.assertEqual(cycle["presentAtFreeze"], 0)
        self.assertEqual(cycle["missingAtFreeze"], 20)
        self.assertEqual(cycle["memberCount"], 20)
        self.assertEqual(cycle["freezeCandidate"], self.freeze["candidate"]["baseCommit"])
        self.assertNotIn("presentToday", cycle)
        self.assertNotIn("missingToday", cycle)
        self.assertEqual(self.status["forwardFreeze"]["presentAtFreeze"], 0)
        self.assertEqual(self.status["forwardFreeze"]["missingAtFreeze"], 20)
        self.assertEqual(self.status["forwardFreeze"]["memberCount"], 20)
        self.assertIn("status --live", cycle["note"])


class LiveView(unittest.TestCase):
    """A live count is an observation; the committed status is a record."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.freeze = load_json(EVIDENCE / "FREEZE-forward.json")
        cls.status = load_json(EVIDENCE / "STATUS.json")

    def test_the_live_view_is_labelled_live_and_reconciles(self) -> None:
        view = om.live_view(self.freeze, root=REPO)
        self.assertEqual(view["state"], om.MARK_LIVE)
        self.assertTrue(view["liveView"])
        self.assertFalse(view["record"])
        self.assertEqual(view["memberCount"], 20)
        self.assertEqual(view["present"] + view["missing"], 20)
        self.assertEqual(view["present"], len(view["presentIds"]))
        self.assertEqual(view["missing"], len(view["missingIds"]))
        # Later items have landed, so the live tree disagrees with the frozen
        # record. The exact number is deliberately not asserted: it moves.
        self.assertGreaterEqual(view["present"], 1)

    def test_a_synthetic_member_moves_only_the_live_view(self) -> None:
        mirror = Path(tempfile.mkdtemp(prefix="a17-mirror-"))
        extra = "evidence/z-synthetic/RECEIPT.md"
        (mirror / extra).parent.mkdir(parents=True)
        (mirror / extra).write_bytes(b"synthetic mirror member\n")
        members = list(self.freeze["members"]) + [
            {
                "id": "z-synthetic-receipt",
                "path": extra,
                "predicate": "a synthetic member that exists only in the mirror",
                "required": True,
                "phase": "SYNTHETIC",
            }
        ]
        synthetic = om.freeze(
            {"id": "forward-open-freeze", "state": om.STATE_OPEN, "members": members},
            self.freeze["frozenAt"],
            self.freeze["candidate"],
        )
        view = om.live_view(synthetic, root=mirror)
        self.assertEqual(view["state"], om.MARK_LIVE)
        self.assertEqual(view["memberCount"], 21)
        self.assertEqual(view["present"], 1)
        self.assertEqual(view["missing"], 20)
        self.assertEqual(view["presentIds"], ["z-synthetic-receipt"])

        committed = (EVIDENCE / "STATUS.json").read_bytes()
        self.assertNotIn(b"z-synthetic", committed)
        self.assertEqual(self.status["forwardFreeze"]["memberCount"], 20)
        self.assertEqual(self.status["forwardFreeze"]["presentAtFreeze"], 0)

        output = Path(tempfile.mkdtemp(prefix="a17-status-"))
        completed = subprocess.run(
            [sys.executable, str(BUILDER_PATH), "--out", str(output)],
            cwd=str(REPO),
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual((output / "STATUS.json").read_bytes(), committed)


class Determinism(unittest.TestCase):
    def test_two_runs_and_the_committed_bytes_are_identical(self) -> None:
        first = Path(tempfile.mkdtemp(prefix="a17-run1-"))
        second = Path(tempfile.mkdtemp(prefix="a17-run2-"))
        for target in (first, second):
            completed = subprocess.run(
                [sys.executable, str(BUILDER_PATH), "--out", str(target)],
                cwd=str(REPO),
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        names = (
            "FREEZE-a15.json",
            "FREEZE-forward.json",
            "RECONCILIATION-a15.json",
            "RECONCILIATION-a15.envelope.json",
            "STATUS.json",
            "CONTROLS.json",
        )
        for name in names:
            first_bytes = (first / name).read_bytes()
            second_bytes = (second / name).read_bytes()
            committed = (EVIDENCE / name).read_bytes()
            self.assertEqual(first_bytes, second_bytes, name)
            self.assertEqual(first_bytes, committed, name)


class CommandLine(unittest.TestCase):
    def run_tool(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            cwd=str(REPO),
            capture_output=True,
            text=True,
        )

    def test_freeze_close_sign_and_verify(self) -> None:
        directory = fixture()
        workdir = Path(tempfile.mkdtemp(prefix="a17-cli-"))
        plan_path = workdir / "plan.json"
        plan_path.write_text(
            json.dumps(
                {
                    "id": "cli",
                    "state": om.STATE_FROZEN,
                    "frozenAt": FROZEN_AT,
                    "candidate": CANDIDATE,
                    "members": [
                        {
                            "id": "a",
                            "path": "evidence/x/a.json",
                            "predicate": "exists",
                            "required": True,
                            "phase": "control",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        freeze_path = workdir / "freeze.json"
        result = self.run_tool("freeze", str(plan_path), str(freeze_path))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("code=OM_OK", result.stdout)

        observe_dir = workdir / "produced"
        observe_dir.mkdir()
        (observe_dir / "a.json").write_bytes((directory / "a.json").read_bytes())
        reconciliation_path = workdir / "reconciliation.json"
        result = self.run_tool(
            "close",
            str(freeze_path),
            str(reconciliation_path),
            "--observe-dir",
            str(observe_dir),
            "--recorded-at",
            OBSERVED_AT,
            "--closed-at",
            OBSERVED_AT,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("code=OM_CLOSED", result.stdout)
        self.assertIn("pass=true", result.stdout)

        envelope_path = workdir / "envelope.json"
        result = self.run_tool("sign", str(reconciliation_path), str(envelope_path))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("code=OM_OK", result.stdout)

        result = self.run_tool(
            "verify", str(freeze_path), str(reconciliation_path), str(envelope_path)
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("code=OM_VERIFIED", result.stdout)

    def test_a_missing_freeze_exits_one_with_the_code(self) -> None:
        workdir = Path(tempfile.mkdtemp(prefix="a17-cli-missing-"))
        result = self.run_tool(
            "close", str(workdir / "absent.json"), str(workdir / "out.json")
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("code=OM_REFUSED_FREEZE_ABSENT", result.stdout)

    def test_a_mutated_envelope_exits_one_with_the_code(self) -> None:
        directory = fixture()
        _freeze, reconciliation = close_good(directory)
        workdir = Path(tempfile.mkdtemp(prefix="a17-cli-mutated-"))
        freeze_path = workdir / "freeze.json"
        reconciliation_path = workdir / "reconciliation.json"
        envelope_path = workdir / "envelope.json"
        freeze_path.write_text(json.dumps(_freeze), encoding="utf-8")
        envelope = om.sign(reconciliation)
        mutated = copy.deepcopy(reconciliation)
        mutated["members"][0]["predicate"] = "mutated"
        reconciliation_path.write_text(json.dumps(mutated), encoding="utf-8")
        envelope_path.write_bytes(dsse.encode_envelope(envelope))
        result = self.run_tool(
            "verify", str(freeze_path), str(reconciliation_path), str(envelope_path)
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("code=OM_REFUSED_RECONCILIATION_MUTATED", result.stdout)

    def test_status_live_prints_the_marker_and_writes_nothing(self) -> None:
        before = {
            path.name: path.read_bytes()
            for path in EVIDENCE.iterdir()
            if path.is_file()
        }
        result = self.run_tool("status", "--live")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("state=LIVE", result.stdout)
        self.assertIn("members=20", result.stdout)
        self.assertIn("present=", result.stdout)
        self.assertIn("missing=", result.stdout)
        after = {
            path.name: path.read_bytes()
            for path in EVIDENCE.iterdir()
            if path.is_file()
        }
        self.assertEqual(before, after)

        machine = self.run_tool("status", "--live", "--json")
        self.assertEqual(machine.returncode, 0, machine.stdout + machine.stderr)
        document = json.loads(machine.stdout)
        self.assertEqual(document["state"], om.MARK_LIVE)
        self.assertTrue(document["liveView"])
        self.assertFalse(document["record"])
        self.assertEqual(document["memberCount"], 20)

    def test_status_without_live_is_a_usage_error(self) -> None:
        result = self.run_tool("status")
        self.assertEqual(result.returncode, 2)
        self.assertIn("code=OM_USAGE", result.stdout)
        self.assertIn("STATUS.json", result.stdout)

    def test_no_command_is_a_usage_error(self) -> None:
        result = self.run_tool()
        self.assertEqual(result.returncode, 2)
        self.assertIn("code=OM_USAGE", result.stdout)


class DocumentSynchronisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8")

    def test_the_document_exists_and_names_the_claim_algebra_receipt(self) -> None:
        self.assertIn("evidence/etp/OMISSION-RESISTANCE.md", self.text)
        self.assertIn("claim-algebra", self.text)
        self.assertTrue(
            "does not supersede" in self.text or "not supersede" in self.text
        )

    def test_every_refusal_code_appears(self) -> None:
        for code in om.CODE_ORDER:
            self.assertIn(code, self.text, code)

    def test_the_document_states_the_test_key_caveat(self) -> None:
        self.assertIn("test-only", self.text)
        self.assertIn("A12", self.text)

    def test_the_document_states_the_non_claims(self) -> None:
        flat = " ".join(self.text.split())
        self.assertIn("PRODUCED", flat)
        self.assertIn("not `PASS`", flat)
        self.assertIn("not a safety", flat)

    def test_the_document_names_both_real_cycles(self) -> None:
        self.assertIn("A15", self.text)
        self.assertIn("A18", self.text)
        self.assertIn("OPEN", self.text)

    def test_the_document_has_a_not_run_section(self) -> None:
        self.assertIn("## `NOT_RUN`", self.text)

    def test_every_rule_names_what_enforces_it(self) -> None:
        self.assertIn("enforced by", self.text)


if __name__ == "__main__":
    unittest.main()
