#!/usr/bin/env python3
"""Controls for verification economics.

Each control exercises one rule of `docs/VERIFICATION-ECONOMICS.md`: a cost is
recorded with the machine that produced it; the units are fixed by the field
names; a required check is never skipped because it costs time; reuse is bound
to an applicability identity; one measured point is not a curve; an over-budget
tier is reported and a waiver is never permission; a not-run is not a measured
zero; a cost measured at another candidate is not this candidate's cost.

A control mutates a record, a policy or an invocation in memory. It is not a
source change and not a defect report: a control that fires proves the refusal
works, not that the substituted form occurs anywhere in the tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import verification_economics as ve  # noqa: E402

A26 = REPO_ROOT / "evidence" / "a26"
COSTS = A26 / "COSTS.json"
BUDGET = A26 / "BUDGET.json"
CONTROLS = A26 / "CONTROLS.json"
MEASUREMENTS = A26 / "MEASUREMENTS.json"
POLICY = A26 / "POLICY.json"
PRODUCER = A26 / "build_evidence.py"
DOCUMENT = REPO_ROOT / "docs" / "VERIFICATION-ECONOMICS.md"
TOOL = TOOLS / "verification_economics.py"

REQUIRED_MEASURED_STEPS = {
    "a23-differential",
    "a8-export",
    "a8-export-verify",
    "a24-package-verify",
    "a22-qualification-run",
}
REQUIRED_NOT_RUN_STEPS = {"verify-all", "rust-library-suite", "external-reproduction"}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def control_record(**overrides) -> dict:
    record = {
        "step": "control-step",
        "tier": "BATCH",
        "wallSeconds": 1.0,
        "cpuSeconds": 1.0,
        "peakRssMiB": 1.0,
        "artefactsBytes": 1,
        "machine": dict(ve.CONTROL_MACHINE),
        "method": "control-only fixture",
        "measuredAt": "2026-01-01T00:00:00Z",
        "citedBy": ["control-only"],
        "status": "MEASURED",
        "candidate": "control-candidate",
        "units": dict(ve.UNITS),
        "unavailable": {},
    }
    record.update(overrides)
    return record


def control_policy(**budget_overrides) -> dict:
    return ve._control_policy(**budget_overrides)


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )


class ControlsForEveryRefusalCode(unittest.TestCase):
    def test_one_control_per_code_and_each_fires_exactly(self) -> None:
        controls = ve.build_controls()
        self.assertTrue(controls["coversEveryCode"])
        self.assertEqual(controls["failing"], [])
        observed = {row["code"] for row in controls["controls"]}
        self.assertEqual(observed, set(ve.REFUSALS))
        for row in controls["controls"]:
            self.assertTrue(row["controlOnly"], row["id"])
            self.assertEqual(row["observed"], [row["code"]], row["id"])

    def test_every_code_is_documented_with_a_wrong_conclusion(self) -> None:
        self.assertEqual(set(ve.REFUSALS), set(ve.REFUSALS))
        for code, text in ve.REFUSALS.items():
            self.assertTrue(code.startswith("EC_REFUSED_"))
            self.assertTrue(text.strip(), code)


class UnitRule(unittest.TestCase):
    def test_a_second_record_is_accepted(self) -> None:
        self.assertEqual(ve.record_problems(control_record()), [])

    def test_milliseconds_declared_for_seconds_is_refused(self) -> None:
        record = control_record(units=dict(ve.UNITS, wallSeconds="ms"))
        self.assertEqual(ve.record_codes(ve.record_problems(record)),
                         ["EC_REFUSED_UNIT_MISMATCH"])

    def test_mebibytes_against_megabytes_is_refused(self) -> None:
        record = control_record(units=dict(ve.UNITS, peakRssMiB="MB"))
        self.assertIn("EC_REFUSED_UNIT_MISMATCH",
                      ve.record_codes(ve.record_problems(record)))

    def test_a_millisecond_named_field_is_refused(self) -> None:
        record = control_record()
        record["wallMs"] = 1000
        self.assertEqual(ve.record_codes(ve.record_problems(record)),
                         ["EC_REFUSED_UNIT_MISMATCH"])

    def test_an_uncited_cost_is_refused(self) -> None:
        record = control_record(
            wallSeconds=None, cpuSeconds=None, peakRssMiB=None, artefactsBytes=None,
            citedBy=[], unavailable={field: "not read" for field in ve.KINDS},
        )
        self.assertEqual(ve.record_codes(ve.record_problems(record)),
                         ["EC_REFUSED_UNCITED_COST"])

    def test_a_required_check_skipped_for_cost_is_refused(self) -> None:
        record = control_record(status="SKIPPED", skippedBecause="cost")
        self.assertEqual(ve.record_codes(ve.record_problems(record)),
                         ["EC_REFUSED_SKIP_AS_SAVING"])

    def test_a_record_whose_tier_is_unknown_is_refused(self) -> None:
        record = control_record(tier="NOT-A-TIER")
        self.assertEqual(ve.record_codes(ve.record_problems(record)),
                         ["EC_REFUSED_RECORD_INVALID"])


class MachineRule(unittest.TestCase):
    def test_a_cost_without_its_machine_is_refused(self) -> None:
        record = control_record(machine={})
        self.assertEqual(ve.record_codes(ve.record_problems(record)),
                         ["EC_REFUSED_MACHINE_UNSTATED"])

    def test_a_machine_missing_one_field_is_refused(self) -> None:
        machine = dict(ve.CONTROL_MACHINE)
        del machine["courtMemCapGiB"]
        record = control_record(machine=machine)
        self.assertIn("EC_REFUSED_MACHINE_UNSTATED",
                      ve.record_codes(ve.record_problems(record)))

    def test_a_populated_machine_is_accepted(self) -> None:
        record = control_record()
        for field in ve.MACHINE_FIELDS:
            self.assertIsNotNone(record["machine"][field])
        self.assertEqual(ve.record_problems(record), [])


class WaiverRule(unittest.TestCase):
    def test_over_budget_without_a_waiver_is_refused(self) -> None:
        result = ve.budget([control_record()], control_policy(BATCH={"wallSeconds": 0.5}))
        self.assertEqual(result["tiers"]["BATCH"]["status"], "OVER")
        self.assertEqual(result["codes"], ["EC_REFUSED_BUDGET_OVER"])
        self.assertEqual(result["overall"], "OVER")

    def test_a_recorded_waiver_is_a_fact_not_permission(self) -> None:
        policy = control_policy(BATCH={"wallSeconds": 0.5})
        policy["waivers"] = {"BATCH": {"recorded": True, "note": "slow host"}}
        result = ve.budget([control_record()], policy)
        self.assertEqual(result["tiers"]["BATCH"]["status"], "OVER")
        self.assertEqual(result["tiers"]["BATCH"]["waiver"]["authorising"], False)
        self.assertEqual(result["codes"], ["EC_OK"])

    def test_a_waiver_naming_an_authority_is_refused(self) -> None:
        policy = control_policy(BATCH={"wallSeconds": 0.5})
        policy["waivers"] = {"BATCH": {"recorded": True, "authority": "self"}}
        result = ve.budget([control_record()], policy)
        self.assertEqual(result["codes"], ["EC_REFUSED_WAIVER_AS_AUTHORITY"])

    def test_an_unrecorded_waiver_is_refused(self) -> None:
        policy = control_policy(BATCH={"wallSeconds": 0.5})
        policy["waivers"] = {"BATCH": {"recorded": False}}
        result = ve.budget([control_record()], policy)
        self.assertEqual(result["codes"], ["EC_REFUSED_WAIVER_UNRECORDED"])


class NotRunRule(unittest.TestCase):
    def test_a_not_run_record_has_nulls_and_a_reason(self) -> None:
        record = ve.not_run(
            "x", "SEAL", "the venue cap forbids a build", "decision", candidate="c",
            machine_identity="control-only court",
        )
        for field in ve.KINDS:
            self.assertIsNone(record[field])
        self.assertEqual(ve.record_problems(record), [])

    def test_a_not_run_recorded_as_zero_is_refused(self) -> None:
        record = control_record(
            status="NOT_RUN", wallSeconds=0.0, cpuSeconds=0.0, peakRssMiB=0.0,
            artefactsBytes=0, notRunReason="did not run",
        )
        self.assertEqual(ve.record_codes(ve.record_problems(record)),
                         ["EC_REFUSED_NOT_RUN_AS_ZERO"])

    def test_a_not_run_counted_as_zero_is_refused(self) -> None:
        record = ve.not_run("x", "SEAL", "did not run", "decision", candidate="c")
        record["countedAsZero"] = True
        self.assertIn("EC_REFUSED_NOT_RUN_AS_ZERO",
                      ve.record_codes(ve.record_problems(record)))


class CacheAndExtrapolationRules(unittest.TestCase):
    def test_reuse_without_an_identity_is_refused(self) -> None:
        record = control_record(reused=True, reuseIdentity={"source": "abc"})
        self.assertEqual(ve.record_codes(ve.record_problems(record)),
                         ["EC_REFUSED_CACHE_UNBOUND"])

    def test_reuse_with_the_complete_identity_is_accepted(self) -> None:
        identity = {field: f"{field}-digest" for field in ve.REUSE_FIELDS}
        record = control_record(reused=True, reuseIdentity=identity)
        self.assertEqual(ve.record_problems(record), [])

    def test_one_point_is_not_a_curve(self) -> None:
        record = control_record(derived=True, basis=["one point"])
        self.assertEqual(ve.record_codes(ve.record_problems(record)),
                         ["EC_REFUSED_EXTRAPOLATION"])

    def test_two_points_permit_a_derived_figure(self) -> None:
        record = control_record(derived=True, basis=["one", "two"])
        self.assertEqual(ve.record_problems(record), [])


class StalenessRule(unittest.TestCase):
    def test_a_cost_from_another_candidate_is_refused(self) -> None:
        record = control_record(candidate="another-candidate")
        policy = control_policy()
        self.assertEqual(ve.record_codes(ve.validate_records([record], policy)),
                         ["EC_REFUSED_STALE_MEASUREMENT"])

    def test_a_cost_at_the_named_candidate_is_accepted(self) -> None:
        record = control_record(candidate="control-candidate")
        self.assertEqual(ve.validate_records([record], control_policy()), [])


class TheRealMeasurements(unittest.TestCase):
    def test_the_records_exist_and_name_the_candidate(self) -> None:
        for path in (COSTS, BUDGET, CONTROLS, MEASUREMENTS, POLICY):
            self.assertTrue(path.is_file(), path)
        policy = load(POLICY)
        costs = load(COSTS)
        self.assertEqual(costs["candidate"], policy["candidate"])
        self.assertEqual(load(MEASUREMENTS)["candidate"], policy["candidate"])

    def test_every_measured_record_carries_its_machine_method_and_citation(self) -> None:
        costs = load(COSTS)
        measured = [r for r in costs["records"] if r["status"] == "MEASURED"]
        self.assertGreaterEqual(len(measured), 6)
        for record in measured:
            for field in ve.MACHINE_FIELDS:
                self.assertIsNotNone(record["machine"][field], record["step"])
            self.assertTrue(record["method"].strip(), record["step"])
            self.assertTrue(record["citedBy"], record["step"])
            self.assertIsNotNone(record["wallSeconds"], record["step"])

    def test_the_required_steps_are_measured(self) -> None:
        steps = {record["step"] for record in load(COSTS)["records"]}
        self.assertTrue(REQUIRED_MEASURED_STEPS <= steps)

    def test_the_not_run_steps_are_present_and_not_zero(self) -> None:
        records = {r["step"]: r for r in load(COSTS)["records"]}
        for step in REQUIRED_NOT_RUN_STEPS:
            self.assertIn(step, records)
            self.assertEqual(records[step]["status"], "NOT_RUN")
            for field in ve.KINDS:
                self.assertIsNone(records[step][field], step)
            self.assertTrue(records[step]["notRunReason"].strip(), step)

    def test_every_record_validates_against_the_policy(self) -> None:
        self.assertEqual(ve.validate_records(load(COSTS)["records"], load(POLICY)), [])

    def test_the_budget_is_under(self) -> None:
        result = ve.budget(load(COSTS)["records"], load(POLICY))
        self.assertEqual(result["overall"], "UNDER")
        self.assertEqual(result["codes"], ["EC_OK"])


class TheProducer(unittest.TestCase):
    def _build(self, out: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(PRODUCER),
                "--out",
                str(out),
                "--measurements",
                str(MEASUREMENTS),
                "--policy",
                str(POLICY),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_the_producer_takes_the_measured_values_as_inputs(self) -> None:
        measurements = {r["step"]: r for r in load(MEASUREMENTS)["records"]}
        costs = {r["step"]: r for r in load(COSTS)["records"]}
        for step, record in measurements.items():
            self.assertEqual(costs[step]["wallSeconds"], record["wallSeconds"], step)
            self.assertEqual(costs[step]["cpuSeconds"], record["cpuSeconds"], step)
            self.assertEqual(costs[step]["measuredAt"], record["measuredAt"], step)

    def test_two_runs_are_byte_identical_and_match_the_committed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one = self._build(Path(first))
            two = self._build(Path(second))
            self.assertEqual(one.returncode, 0, one.stdout + one.stderr)
            self.assertEqual(two.returncode, 0, two.stdout + two.stderr)
            for name, committed in (
                ("COSTS.json", COSTS),
                ("BUDGET.json", BUDGET),
                ("CONTROLS.json", CONTROLS),
            ):
                first_bytes = (Path(first) / name).read_bytes()
                second_bytes = (Path(second) / name).read_bytes()
                self.assertEqual(first_bytes, second_bytes, name)
                self.assertEqual(first_bytes, committed.read_bytes(), name)


class TheCommandLine(unittest.TestCase):
    def test_report_exits_zero_and_prints_the_code(self) -> None:
        result = run_cli(
            "report", "--records", str(COSTS), "--policy", str(POLICY)
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("codes=EC_OK", result.stdout)

    def test_budget_exits_zero_and_prints_the_code(self) -> None:
        result = run_cli(
            "budget", "--records", str(COSTS), "--policy", str(POLICY)
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("codes=EC_OK", result.stdout)
        self.assertIn("overall=UNDER", result.stdout)

    def test_a_usage_error_exits_two_and_prints_the_code(self) -> None:
        result = run_cli("not-a-command")
        self.assertEqual(result.returncode, 2)
        self.assertIn("EC_REFUSED_USAGE", result.stdout)

    def test_an_over_budget_report_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            costs = Path(temporary) / "costs.json"
            policy = Path(temporary) / "policy.json"
            costs.write_bytes(json.dumps({"records": [control_record()]}).encode("utf-8"))
            policy.write_bytes(
                json.dumps(control_policy(BATCH={"wallSeconds": 0.5})).encode("utf-8")
            )
            result = run_cli("report", "--records", str(costs), "--policy", str(policy))
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("EC_REFUSED_BUDGET_OVER", result.stdout)

    def test_measure_records_a_real_command(self) -> None:
        result = run_cli(
            "measure", "--tier", "FAST", "--method", "test", "--step", "cli-measure",
            "--candidate", "control-candidate", "--", sys.executable, "-c", "print(1)",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("codes=EC_OK", result.stdout)
        body = result.stdout.split("verification-economics:")[0]
        record = json.loads(body)
        self.assertEqual(record["step"], "cli-measure")
        self.assertGreater(record["wallSeconds"], 0.0)


class TheDocument(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DOCUMENT.read_text(encoding="utf-8")

    def test_every_refusal_code_is_documented(self) -> None:
        for code in ve.REFUSALS:
            self.assertIn(code, self.text, code)

    def test_every_measured_step_is_named(self) -> None:
        for step in REQUIRED_MEASURED_STEPS | REQUIRED_NOT_RUN_STEPS:
            self.assertIn(step, self.text, step)

    def test_the_machine_and_waiver_rules_are_stated(self) -> None:
        self.assertIn("machine", self.text.lower())
        self.assertIn("waiver", self.text.lower())
        self.assertIn("never permission", self.text.lower())

    def test_every_enforced_by_names_a_test_or_a_control(self) -> None:
        rows = [
            line
            for line in self.text.splitlines()
            if line.startswith("| `EC_REFUSED_")
        ]
        self.assertEqual(len(rows), len(ve.REFUSALS))
        for line in rows:
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            enforced = cells[-1]
            self.assertTrue(
                "test_" in enforced or "control" in enforced,
                line,
            )

    def test_the_not_run_section_names_the_two_refused_gates(self) -> None:
        self.assertIn("verify all", self.text)
        self.assertIn("Rust", self.text)
        self.assertIn("NOT_RUN", self.text)


if __name__ == "__main__":
    unittest.main()
