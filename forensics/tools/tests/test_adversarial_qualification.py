#!/usr/bin/env python3
"""Controls for forensics/tools/adversarial_qualification.py and the A22 records.

One control per refusal code; the canary detection for each of the eight
experiments; that ``NOT_RUN`` never counts as a qualification; that an
unstable harness is refused rather than summarised; the recorded behaviour of
the BINSEC mixed transcript in full; the reported coverage basis of the branch
audit and the reported timing thresholds; both repaired register consumers
refusing the duplicate key with the observed code; the SARIF halves that refuse
and the live emission that is accepted; determinism of the producer across two
invocations and against the committed bytes; the command line's exit codes; and
document synchronisation. The verdicts are asserted per experiment from the
recorded measurement, so a regression that turns a ``QUALIFIED`` into a
``DEFECT`` fails the suite rather than reading as a clean summary.

A control mutates a synthetic experiment or a temporary copy of a record. It is
not a source change and not a repair: a control that fires proves the refusal
works, not that the substituted form occurs anywhere in the tree.

Run directly (`python3 forensics/tools/tests/test_adversarial_qualification.py`)
or with `python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics/tools"
EVIDENCE = REPO / "evidence/a22"
BUILDER = EVIDENCE / "build_evidence.py"
DOCUMENT = REPO / "docs/ADVERSARIAL-QUALIFICATION.md"
sys.path.insert(0, str(TOOLS))

import adversarial_qualification as aq  # noqa: E402

BASELINE: dict = {}


def _produce(out: Path) -> int:
    return subprocess.run(
        [sys.executable, str(BUILDER), "--out", str(out)],
        capture_output=True,
        text=True,
        cwd=str(REPO),
    ).returncode


def setUpModule() -> None:
    first = Path(tempfile.mkdtemp(prefix="a22-a-"))
    second = Path(tempfile.mkdtemp(prefix="a22-b-"))
    BASELINE["first"] = first
    BASELINE["second"] = second
    BASELINE["rc_first"] = _produce(first)
    BASELINE["rc_second"] = _produce(second)
    BASELINE["experiments"] = json.loads((first / "EXPERIMENTS.json").read_text())
    BASELINE["results"] = json.loads((first / "RESULTS.json").read_text())
    BASELINE["controls"] = json.loads((first / "CONTROLS.json").read_text())


def _by_id(results: dict) -> dict:
    return {entry["id"]: entry for entry in results["experiments"]}


def _observation(experiment: dict, case: str) -> dict:
    for item in experiment["observations"]:
        if item["case"] == case:
            return item
    raise AssertionError(f"no observation {case!r} in {experiment['id']}")


class Registry(unittest.TestCase):
    def test_the_eight_required_experiments_are_present(self) -> None:
        self.assertEqual([spec.id for spec in aq.EXPERIMENTS], list(aq.REQUIRED_EXPERIMENTS))
        self.assertEqual(len({spec.id for spec in aq.EXPERIMENTS}), 8)

    def test_every_named_instrument_exists(self) -> None:
        for spec in aq.EXPERIMENTS:
            for relative in spec.instruments:
                with self.subTest(experiment=spec.id, instrument=relative):
                    self.assertTrue((REPO / relative).is_file(), relative)

    def test_every_experiment_declares_its_canary_witnesses(self) -> None:
        for spec in aq.EXPERIMENTS:
            cases = {case for case, _, _ in aq._declared_witnesses(spec)}
            with self.subTest(experiment=spec.id):
                self.assertIn(spec.canary_accepted, cases)
                self.assertIn(spec.canary_detection, cases)

    def test_every_rejected_witness_declares_an_expectation(self) -> None:
        for spec in aq.EXPERIMENTS:
            for case, kind, expectation in aq._declared_witnesses(spec):
                if kind not in ("rejected", "detection"):
                    continue
                with self.subTest(experiment=spec.id, case=case):
                    self.assertIsNotNone(expectation.get("exit"))
                    self.assertTrue(expectation.get("code"))


class RefusalCodes(unittest.TestCase):
    def test_every_code_has_a_control(self) -> None:
        controls = aq.build_controls()
        by_code: dict[str, list[dict]] = {}
        for control in controls["controls"]:
            if control["code"]:
                by_code.setdefault(control["code"], []).append(control)
        self.assertEqual(sorted(by_code), sorted(aq.REFUSALS))
        for code, entries in by_code.items():
            with self.subTest(code=code):
                self.assertGreaterEqual(len(entries), 1)
                for entry in entries:
                    self.assertTrue(entry["established"], entry["observed"])

    def test_the_positive_control_reaches_qualified(self) -> None:
        controls = aq.build_controls()
        positives = [control for control in controls["controls"] if control["code"] is None]
        self.assertEqual([control["id"] for control in positives], ["positive-qualified"])
        self.assertTrue(positives[0]["established"])
        self.assertEqual(positives[0]["observed"]["verdict"], aq.VERDICT_QUALIFIED)

    def test_the_recorded_controls_cover_every_code(self) -> None:
        self.assertTrue(BASELINE["controls"]["coversEveryCode"])
        recorded = {
            control["code"] for control in BASELINE["controls"]["controls"] if control["code"]
        }
        self.assertEqual(sorted(recorded), sorted(aq.REFUSALS))
        for control in BASELINE["controls"]["controls"]:
            with self.subTest(control=control["id"]):
                self.assertEqual(control["kind"], "control-only")
                self.assertTrue(control["established"], control["observed"])

    def test_experiment_absent_is_refused(self) -> None:
        seven = [spec for spec in aq.EXPERIMENTS if spec.id != "E8"]
        with self.assertRaises(aq.Refusal) as caught:
            aq.select(seven, None)
        self.assertEqual(caught.exception.code, aq.AQ_REFUSED_EXPERIMENT_ABSENT)

    def test_absent_instrument_is_refused(self) -> None:
        spec = aq._stub_spec("C", aq._stub_harness(True), instruments=("forensics/tools/absent.py",))
        with self.assertRaises(aq.Refusal) as caught:
            aq.run_experiment(spec)
        self.assertEqual(caught.exception.code, aq.AQ_REFUSED_EXPERIMENT_ABSENT)

    def test_no_canary_is_refused(self) -> None:
        spec = aq._stub_spec("C", aq._stub_harness(True), canary_accepted="absent-witness")
        with self.assertRaises(aq.Refusal) as caught:
            aq.run_experiment(spec)
        self.assertEqual(caught.exception.code, aq.AQ_REFUSED_NO_CANARY)

    def test_expected_absent_is_refused(self) -> None:
        def harness(tmp: Path, canon: aq.Canon):
            del tmp, canon
            return (
                [
                    aq._stub_observation("rejected", "rejected", 1, "AQ_REFUSED_SYNTHETIC",
                                         aq._expectation(None, None)),
                    aq._stub_observation("accepted", "accepted", 0, "AQ_ACCEPTED",
                                         aq._expectation([0], None)),
                ],
                {},
            )

        with self.assertRaises(aq.Refusal) as caught:
            aq.run_experiment(aq._stub_spec("C", harness))
        self.assertEqual(caught.exception.code, aq.AQ_REFUSED_EXPECTED_ABSENT)

    def test_witness_absent_is_refused(self) -> None:
        def harness(tmp: Path, canon: aq.Canon):
            del tmp, canon
            raise aq.WitnessAbsent("the declared input is absent")

        with self.assertRaises(aq.Refusal) as caught:
            aq.run_experiment(aq._stub_spec("C", harness))
        self.assertEqual(caught.exception.code, aq.AQ_REFUSED_WITNESS_ABSENT)

    def test_unstable_harness_is_refused(self) -> None:
        with self.assertRaises(aq.Refusal) as caught:
            aq.run_experiment(aq._stub_spec("C", aq._unstable_harness()), runs=2)
        self.assertEqual(caught.exception.code, aq.AQ_REFUSED_UNSTABLE)

    def test_canary_not_detected_is_refused(self) -> None:
        spec = aq._stub_spec("C", aq._stub_harness(True, hardwired=True))
        result = aq.run_experiment(spec, runs=1)
        self.assertEqual(result.verdict, aq.VERDICT_QUALIFIED)
        self.assertIn(aq.AQ_REFUSED_CANARY_NOT_DETECTED, result.codes)
        self.assertFalse(result.canary.detected)
        with self.assertRaises(aq.Refusal) as caught:
            aq.assert_all_qualified([result])
        self.assertEqual(caught.exception.code, aq.AQ_REFUSED_CANARY_NOT_DETECTED)

    def test_defect_found_is_named(self) -> None:
        result = aq.run_experiment(aq._stub_spec("C", aq._stub_harness(False)), runs=1)
        self.assertEqual(result.verdict, aq.VERDICT_DEFECT)
        self.assertIn(aq.AQ_DEFECT_FOUND, result.codes)
        with self.assertRaises(aq.Refusal) as caught:
            aq.assert_all_qualified([result])
        self.assertEqual(caught.exception.code, aq.AQ_DEFECT_FOUND)


class NotRunNeverQualifies(unittest.TestCase):
    def _not_run(self) -> aq.ExperimentResult:
        def harness(tmp: Path, canon: aq.Canon):
            del tmp, canon
            raise aq.PrerequisiteMissing("cc is not on PATH")

        return aq.run_experiment(aq._stub_spec("C", harness), runs=1)

    def test_a_missing_prerequisite_is_not_run_with_a_reason(self) -> None:
        result = self._not_run()
        self.assertEqual(result.verdict, aq.VERDICT_NOT_RUN)
        self.assertIn("cc is not on PATH", result.reason)
        self.assertEqual(result.refused, 0)

    def test_not_run_is_refused_by_assert_all_qualified(self) -> None:
        with self.assertRaises(aq.Refusal) as caught:
            aq.assert_all_qualified([self._not_run()])
        self.assertEqual(caught.exception.code, aq.AQ_REFUSED_NOT_RUN_AS_QUALIFIED)

    def test_a_not_run_is_not_in_the_qualified_count(self) -> None:
        results = [
            aq.run_experiment(aq._stub_spec("C", aq._stub_harness(True)), runs=1),
            self._not_run(),
        ]
        totals = aq.summary(results)
        self.assertEqual(totals["qualified"], 1)
        self.assertEqual(totals["notRun"], 1)
        self.assertFalse(totals["allQualified"])


class TheEightResults(unittest.TestCase):
    def test_the_producer_exit_status_describes_the_recorded_verdicts(self) -> None:
        # The records are written either way; the status describes the evidence.
        # Deriving it from the summary means a regression that records a defect
        # but still exits 0 (or the reverse) is caught.
        totals = BASELINE["results"]["summary"]
        expected = 0 if totals["allQualified"] else 1
        self.assertEqual(BASELINE["rc_first"], expected)
        self.assertEqual(BASELINE["rc_second"], expected)

    def test_every_experiment_reports_its_observed_verdict(self) -> None:
        # The actual verdict of each experiment, not a single clean flag. A
        # regression that turns one QUALIFIED into DEFECT or PARTIAL fails here.
        entries = _by_id(BASELINE["results"])
        for identifier in aq.REQUIRED_EXPERIMENTS:
            with self.subTest(experiment=identifier):
                self.assertEqual(entries[identifier]["verdict"], aq.VERDICT_QUALIFIED)
                self.assertEqual(
                    entries[identifier]["refusedWitnesses"],
                    entries[identifier]["rejectedWitnesses"],
                )
                self.assertEqual(entries[identifier]["codes"], [])

    def test_the_recorded_summary_is_recomputed_from_the_verdicts(self) -> None:
        entries = _by_id(BASELINE["results"])
        verdicts = [entries[identifier]["verdict"] for identifier in aq.REQUIRED_EXPERIMENTS]
        totals = BASELINE["results"]["summary"]
        self.assertEqual(totals["experiments"], 8)
        self.assertEqual(totals["qualified"], verdicts.count(aq.VERDICT_QUALIFIED))
        self.assertEqual(totals["defect"], verdicts.count(aq.VERDICT_DEFECT))
        self.assertEqual(totals["partial"], verdicts.count(aq.VERDICT_PARTIAL))
        self.assertEqual(totals["notRun"], verdicts.count(aq.VERDICT_NOT_RUN))
        self.assertEqual(
            totals["allQualified"],
            all(verdict == aq.VERDICT_QUALIFIED for verdict in verdicts),
        )
        self.assertEqual(totals["codes"], [])

    def test_every_experiment_canary_is_detected(self) -> None:
        self.assertTrue(BASELINE["controls"]["allCanariesDetected"])
        for entry in BASELINE["results"]["experiments"]:
            with self.subTest(experiment=entry["id"]):
                self.assertTrue(entry["canary"]["detected"], entry["canary"])
                probes = {probe["probe"]: probe for probe in entry["canary"]["probes"]}
                self.assertEqual(len(probes), 3)
                for name, probe in probes.items():
                    self.assertTrue(probe["ok"], f"{entry['id']}: {name}")

    def test_the_binsec_mixed_transcript_is_recorded_in_full(self) -> None:
        entry = _by_id(BASELINE["results"])["E1"]
        mixed = _observation(entry, "conflicting-verdicts")
        self.assertEqual(mixed["exit"], 6)
        self.assertIn("[checkct:result] Program status is : secure", mixed["output"])
        self.assertIn("[checkct:result] Program status is : insecure", mixed["output"])
        self.assertIn("reason=mixed-verdicts", mixed["output"])
        # No verdict is printed: the wrapper refuses before dispatching one.
        self.assertNotIn("T16 verdict:", mixed["output"])
        reported = entry["reported"]["mixed_case"]
        self.assertEqual(reported["exit"], 6)
        self.assertEqual(len(reported["verdict_lines"]), 2)
        self.assertIsNone(reported["verdict_printed"])
        self.assertIn("reason=mixed-verdicts", reported["refusal"])

    def test_the_branch_audit_reports_decoded_length_coverage(self) -> None:
        reported = _by_id(BASELINE["results"])["E3"]["reported"]
        self.assertIn("decoded instruction byte lengths", reported["coverage_from"])
        self.assertIn("len(raw)", reported["coverage_from"])
        self.assertIn("not the coverage test", reported["max_insn_bytes"])

    def test_the_timing_thresholds_and_sample_counts_are_reported(self) -> None:
        reported = _by_id(BASELINE["results"])["E4"]["reported"]
        thresholds = reported["thresholds"]
        self.assertEqual(thresholds["t_threshold_moderate"], 10)
        self.assertEqual(thresholds["t_threshold_bananas"], 500)
        self.assertEqual(thresholds["enough_measurements"], 10000)
        self.assertEqual(reported["declared_geometry"]["per_batch"], 10000)
        self.assertEqual(reported["declared_geometry"]["max_batches"], 3)
        for name, counts in reported["sample_counts_used"].items():
            with self.subTest(mode=name):
                self.assertEqual(counts["total_measurements"], 30000)
                self.assertEqual(counts["batches_run"], 3)

    def test_both_register_consumers_refuse_the_duplicate_key(self) -> None:
        reported = _by_id(BASELINE["results"])["E7"]["reported"]
        self.assertEqual(reported["permissive_consumer_count"], 0)
        self.assertEqual(reported["permissive_consumers"], [])
        probes = {probe["path"]: probe for probe in reported["consumer_probes"]}
        self.assertEqual(
            sorted(probes),
            ["forensics/tools/etp_t1_seed.py", "forensics/tools/freshness.py"],
        )
        for path, probe in probes.items():
            with self.subTest(consumer=path):
                self.assertEqual(probe["exit"], 1)
                self.assertTrue(probe["refusalObserved"], probe)
        self.assertIn("historical", reported["finding"])
        self.assertIn("PH_REFUSED_DUPLICATE_KEY", reported["finding"])
        loaders = {entry["path"]: entry["loader"] for entry in reported["consumers"]}
        self.assertEqual(loaders["forensics/tools/instrument_qualify.py"], "strict")
        self.assertEqual(loaders["forensics/tools/etp_t1_seed.py"], "strict")
        self.assertEqual(loaders["forensics/tools/freshness.py"], "strict")
        entry = _by_id(BASELINE["results"])["E7"]
        for case in ("duplicate-key-etp-t1-seed", "duplicate-key-freshness"):
            observation = _observation(entry, case)
            self.assertEqual(observation["exit"], 1)
            self.assertIn("PH_REFUSED_DUPLICATE_KEY", observation["output"])

    def test_the_sarif_native_and_emission_halves_both_refuse(self) -> None:
        entry = _by_id(BASELINE["results"])["E6"]
        native = _observation(entry, "native-population-mismatch")
        emission = _observation(entry, "emission-result-count-mismatch")
        for observation in (native, emission):
            with self.subTest(case=observation["case"]):
                self.assertEqual(observation["exit"], 1)
                self.assertIn("SARIF_REFUSED_POPULATION_MISMATCH", observation["output"])
        shape = entry["reported"]["emission_shape"]
        self.assertEqual(shape["results_before"], shape["results_after"] + 1)
        self.assertIn("refuses", entry["reported"]["emission_population"])

    def test_the_ctgrind_experiment_refuses_all_three_cases(self) -> None:
        entry = _by_id(BASELINE["results"])["E5"]
        refused = {
            item["case"]: (item["exit"], item["output"])
            for item in entry["observations"]
            if item["kind"] == "rejected"
        }
        self.assertEqual(sorted(refused), ["candidate-identity-mismatch", "empty-log",
                                           "unrelated-log-only"])
        self.assertEqual(refused["empty-log"][0], 3)
        self.assertIn("CT_SUMMARY_EMPTY_LOG", refused["empty-log"][1])
        self.assertEqual(refused["unrelated-log-only"][0], 4)
        self.assertIn("CT_SUMMARY_UNRELATED_LOG", refused["unrelated-log-only"][1])
        self.assertEqual(refused["candidate-identity-mismatch"][0], 1)
        self.assertIn("CTGRIND_BINARY_IDENTITY_MISMATCH",
                      refused["candidate-identity-mismatch"][1])
        reported = entry["reported"]
        self.assertIn("expected identity", reported["identity_binding"])
        self.assertIn("presence-only", reported["residual"])
        self.assertIn("fixture", reported["identity_expectation"]["scope"])


class Determinism(unittest.TestCase):
    def test_the_producer_reproduces_its_bytes(self) -> None:
        for name in ("EXPERIMENTS.json", "RESULTS.json", "CONTROLS.json"):
            with self.subTest(document=name):
                self.assertEqual(
                    (BASELINE["first"] / name).read_bytes(),
                    (BASELINE["second"] / name).read_bytes(),
                )

    def test_the_committed_records_are_the_live_records(self) -> None:
        for name in ("EXPERIMENTS.json", "RESULTS.json", "CONTROLS.json"):
            with self.subTest(document=name):
                committed = (EVIDENCE / name).read_bytes()
                self.assertEqual((BASELINE["first"] / name).read_bytes(), committed,
                                 f"{name} is stale: run python3 evidence/a22/build_evidence.py")

    def test_the_design_witnesses_equal_the_observed_witnesses(self) -> None:
        declared = {
            entry["id"]: sorted(witness["case"] for witness in entry["witnesses"])
            for entry in BASELINE["experiments"]["experiments"]
        }
        observed = {
            entry["id"]: sorted(item["case"] for item in entry["observations"])
            for entry in BASELINE["results"]["experiments"]
        }
        self.assertEqual(declared, observed)

    def test_every_record_names_its_candidate_and_tool(self) -> None:
        for name in ("EXPERIMENTS.json", "RESULTS.json", "CONTROLS.json"):
            document = json.loads((EVIDENCE / name).read_text())
            with self.subTest(document=name):
                self.assertEqual(document["baseCommit"], aq.BASE_COMMIT)
                self.assertEqual(document["tool"]["path"], aq.TOOL_PATH)
                self.assertRegex(document["tool"]["sha256"], r"^[0-9a-f]{64}$")

    def test_every_experiment_binds_its_instrument_digests(self) -> None:
        for entry in BASELINE["results"]["experiments"]:
            with self.subTest(experiment=entry["id"]):
                for relative, digest in entry["instrumentSha256"].items():
                    self.assertEqual(digest, aq.sha256_file(REPO / relative))


class CommandLine(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = aq.main(argv)
        return code, out.getvalue() + err.getvalue()

    def test_run_prints_every_experiment_and_exits_with_the_summary(self) -> None:
        code, output = self._run(["run", "--runs", "1"])
        totals = BASELINE["results"]["summary"]
        expected = aq.EXIT_OK if totals["allQualified"] else aq.EXIT_REFUSED
        self.assertEqual(code, expected)
        for identifier in aq.REQUIRED_EXPERIMENTS:
            self.assertIn(f"aq: {identifier} ", output)
        self.assertIn(
            f"allQualified={str(totals['allQualified']).lower()}", output
        )
        if totals["allQualified"]:
            self.assertIn("codes=NONE", output)
        else:
            self.assertIn("codes=AQ_DEFECT_FOUND", output)

    def test_only_is_a_diagnostic_not_a_qualification(self) -> None:
        code, output = self._run(["run", "--only", "E1", "--runs", "1"])
        self.assertEqual(code, aq.EXIT_REFUSED)
        self.assertIn("aq: E1 QUALIFIED", output)
        self.assertIn("allQualified=false", output)

    def test_canary_exits_zero_when_every_canary_is_detected(self) -> None:
        code, output = self._run(["canary"])
        self.assertEqual(code, aq.EXIT_OK)
        self.assertIn("aq: canary experiments=8 detected=8", output)

    def test_explain_exits_zero_for_a_known_experiment(self) -> None:
        code, output = self._run(["explain", "E1"])
        self.assertEqual(code, aq.EXIT_OK)
        self.assertIn("experiment: id=E1", output)
        self.assertIn("witness: case=conflicting-verdicts", output)

    def test_explain_refuses_an_unknown_experiment(self) -> None:
        code, output = self._run(["explain", "E9"])
        self.assertEqual(code, aq.EXIT_REFUSED)
        self.assertIn(aq.AQ_REFUSED_EXPERIMENT_ABSENT, output)

    def test_no_command_is_a_usage_error(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            with contextlib.redirect_stderr(io.StringIO()):
                aq.main([])
        self.assertEqual(caught.exception.code, aq.EXIT_USAGE)

    def test_zero_runs_is_a_usage_error(self) -> None:
        code, output = self._run(["run", "--runs", "0"])
        self.assertEqual(code, aq.EXIT_USAGE)
        self.assertIn(aq.CODE_USAGE, output)


class DocumentSynchronisation(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DOCUMENT.read_text(encoding="utf-8")

    @staticmethod
    def _test_methods() -> set[str]:
        names: set[str] = set()
        for value in list(globals().values()):
            if isinstance(value, type) and issubclass(value, unittest.TestCase):
                names |= {name for name in dir(value) if name.startswith("test_")}
        return names

    def test_every_refusal_code_is_named_in_the_document(self) -> None:
        for code in aq.REFUSALS:
            with self.subTest(code=code):
                self.assertIn(code, self.text)

    def test_the_document_names_no_unregistered_code(self) -> None:
        named = set(re.findall(r"\bAQ_[A-Z0-9_]+\b", self.text))
        named -= {aq.CODE_OK, aq.CODE_USAGE}
        unregistered = sorted(named - set(aq.REFUSALS))
        self.assertEqual(unregistered, [], f"the document names codes the tool does not: {unregistered}")

    def test_every_code_names_a_test_that_exists(self) -> None:
        methods = self._test_methods()
        self.assertGreater(len(methods), 20)
        for code in aq.REFUSALS:
            with self.subTest(code=code):
                rows = [
                    line for line in self.text.splitlines()
                    if line.startswith("|") and f"`{code}`" in line
                ]
                self.assertTrue(rows, f"no refusal-table row for {code}")
                named = set(re.findall(r"`(test_[a-z0-9_]+)`", " ".join(rows)))
                self.assertTrue(named, f"no test named for {code}")
                self.assertTrue(named <= methods, f"{code} names unknown tests {sorted(named - methods)}")

    def test_the_document_states_the_eight_verdicts(self) -> None:
        entries = _by_id(BASELINE["results"])
        rows = [
            line for line in self.text.splitlines()
            if re.match(r"^\| `E[1-8]` \|", line)
        ]
        self.assertEqual(len(rows), 8)
        for line in rows:
            identifier = re.match(r"^\| `(E[1-8])`", line).group(1)
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            with self.subTest(experiment=identifier):
                self.assertEqual(len(cells), 5, line)
                self.assertEqual(cells[3].strip("`"), entries[identifier]["verdict"])

    def test_the_document_preserves_the_before_and_records_the_after(self) -> None:
        # The historical findings and their owners stay readable; the repair is
        # recorded beside them, not substituted for them.
        self.assertIn("**Owning item: ETP-T7**", self.text)
        self.assertIn("**Owning item: A1**", self.text)
        self.assertIn("Queued obligation", self.text)
        self.assertIn("**This is not a clean qualification**", self.text)
        self.assertIn("after repair (`e4029e0d5`)", self.text)
        self.assertIn("**This is a clean qualification after repair**", self.text)

    def test_the_document_states_the_canary_rule(self) -> None:
        self.assertIn("accept_any", self.text)
        self.assertIn("weak detector", self.text.lower())


if __name__ == "__main__":
    unittest.main()
