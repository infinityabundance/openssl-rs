#!/usr/bin/env python3
"""Controls for the PFP-19 performance arm admission validator.

The validator must refuse to call an arm a candidate when the candidate
conjunction is incomplete. Every refusal code has a negative control; a complete
synthetic candidate and a measured-but-incomplete experiment are positive
controls, so the rules are shown to accept a legitimate record as well as refuse
a defective one.

The committed register is cross-bound to the claim record, the build identity
and the workload population it describes, and the one measured arm in the
repository is checked to be an `EXPERIMENT` rather than a `CANDIDATE`.

Run:

    python3 forensics/tools/tests/test_performance_admission.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
TOOL = TOOLS / "performance_admission.py"
REGISTER = REPO_ROOT / "evidence" / "performance-frontier" / "admission" / "ARMS.json"
CLAIM = REPO_ROOT / "evidence" / "performance-frontier" / "claims" / "PFP-1.claim.json"
RESULTS = REPO_ROOT / "evidence/performance-frontier/campaigns/PFP-1/performance/results.json"
BUILD = REPO_ROOT / "evidence/performance-frontier/campaigns/PFP-1/performance/build-identity.json"
CTGRIND = REPO_ROOT / "evidence/performance-frontier/campaigns/PFP-1/ctgrind/summary.json"
WORKLOADS = REPO_ROOT / "forensics" / "performance" / "WORKLOADS.json"

sys.path.insert(0, str(TOOLS))
import performance_admission as pa  # noqa: E402


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def codes(register: dict) -> list[str]:
    return sorted({problem.code for problem in pa.check_register(register)})


class CommittedRegister(unittest.TestCase):
    def test_the_committed_register_is_accepted(self) -> None:
        self.assertEqual(pa.check_register(load(REGISTER)), [])

    def test_the_cli_accepts_the_committed_register(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "check"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 register(s) accepted, 0 refused", result.stdout)

    def test_the_measured_arm_is_an_experiment_not_a_candidate(self) -> None:
        register = load(REGISTER)
        arms = {arm["arm_id"]: arm for arm in register["arms"]}
        self.assertIn("PFP-1", arms)
        arm = arms["PFP-1"]
        self.assertEqual(arm["status"], "EXPERIMENT")
        self.assertIsNone(arm["differential_courts"])
        self.assertEqual(arm["constant_time_audit"]["kind"], "CTGRIND")
        self.assertNotIn(
            arm["constant_time_audit"]["kind"], pa.CT_KINDS_ACCEPTED_FOR_CANDIDATE
        )

    def test_the_refreeze_arm_is_an_experiment_with_no_candidate_conjunct(self) -> None:
        register = load(REGISTER)
        arms = {arm["arm_id"]: arm for arm in register["arms"]}
        arm = arms["PFP-0-refreeze-2e9c4c5cf"]
        self.assertEqual(arm["status"], "EXPERIMENT")
        self.assertIsNone(arm["differential_courts"])
        self.assertNotIn(
            arm["constant_time_audit"]["kind"], pa.CT_KINDS_ACCEPTED_FOR_CANDIDATE
        )
        self.assertEqual(
            arm["measurement"]["candidate_sha256"], arm["candidate"]["artefact"]["sha256"]
        )

    def test_promoting_the_experiment_to_candidate_is_refused(self) -> None:
        register = load(REGISTER)
        register["arms"][0]["status"] = "CANDIDATE"
        got = codes(register)
        self.assertIn(pa.PA_CANDIDATE_WITHOUT_COURTS, got)
        self.assertIn(pa.PA_CANDIDATE_WITHOUT_CONSTANT_TIME_AUDIT, got)

    def test_the_measurement_matches_the_claim_record_and_build_identity(self) -> None:
        register = load(REGISTER)
        arm = register["arms"][0]
        claim = load(CLAIM)
        build = load(BUILD)
        self.assertEqual(arm["measurement"]["record"]["path"], str(CLAIM.relative_to(REPO_ROOT)))
        self.assertEqual(
            arm["measurement"]["candidate_sha256"],
            claim["candidate"]["artefact"]["sha256"],
        )
        self.assertEqual(arm["measurement"]["candidate_sha256"], build["candidate"]["sha256"])
        self.assertEqual(arm["candidate"]["source_commit"], build["source"]["head"])
        self.assertEqual(arm["measurement"]["classification"], claim["classification"])

    def test_the_population_digest_is_the_frozen_workload_population(self) -> None:
        register = load(REGISTER)
        arm = register["arms"][0]
        identifiers = [entry["id"] for entry in load(WORKLOADS)["workloads"]]
        digest = pa.population_digest(identifiers)
        self.assertEqual(arm["measurement"]["population"]["digest"], digest)
        self.assertEqual(arm["measurement"]["identity"]["population"], digest)
        self.assertEqual(
            arm["measurement"]["population"]["frozen_at"],
            load(WORKLOADS)["frozen_at_source"],
        )

    def test_the_audit_reference_is_bound(self) -> None:
        register = load(REGISTER)
        audit = register["arms"][0]["constant_time_audit"]
        self.assertEqual(
            pa.pc.sha256_file(REPO_ROOT / audit["reference"]["path"]),
            audit["reference"]["sha256"],
        )
        self.assertEqual(audit["reference"]["path"], str(CTGRIND.relative_to(REPO_ROOT)))
        self.assertEqual(audit["candidate_sha256"], load(BUILD)["candidate"]["sha256"])

    def test_the_results_file_has_no_candidate_status(self) -> None:
        # The campaign result is a measurement, not an admission. Its own record
        # says so; this test pins the separation the register relies on.
        results = load(RESULTS)
        self.assertEqual(results["classification"], "SCOPED_OBSERVATION")
        self.assertNotIn("status", results)


class RuleCoverage(unittest.TestCase):
    def test_every_code_has_at_least_one_negative_control(self) -> None:
        fired: set[str] = set()
        for name, register, code in pa._controls():
            problems = pa.check_register(register)
            if code is None:
                self.assertEqual(problems, [], name)
            else:
                self.assertIn(code, {problem.code for problem in problems}, name)
                fired.add(code)
        for text, code in (
            ("{", pa.PA_JSON_MALFORMED),
            ('{"a": 1, "a": 1}', pa.PA_JSON_DUPLICATE_KEY),
            ('{"a": NaN}', pa.PA_JSON_NON_FINITE),
        ):
            with self.assertRaises(pa.Refusal) as caught:
                pa.loads_document(text)
            self.assertEqual(caught.exception.code, code)
            fired.add(code)
        self.assertEqual(sorted(fired), sorted(pa.CODES))

    def test_the_rule_table_names_every_code(self) -> None:
        self.assertEqual(sorted(pa.RULES), sorted(pa.CODES))

    def test_the_shortcut_vocabulary_is_the_programme_list(self) -> None:
        self.assertEqual(
            pa.SHORTCUTS,
            {
                "DISABLE_RSA_BLINDING",
                "SECRET_INDEXED_LOOKUP",
                "REMOVE_CLEANSING",
                "SKIP_CERTIFICATE_VALIDATION",
                "REDUCE_KEY_SIZE",
                "REUSE_STALE_MONTGOMERY_PARAMETERS",
                "IGNORE_CUSTOM_METHOD_OR_CALLBACK",
                "BENCHMARK_STALE_BINARY",
                "CHANGE_POPULATION_SILENTLY",
                "COMPARE_AGAINST_SLOWED_COMPETITOR",
                "PUBLISH_ONLY_WINNING_CASES",
            },
        )

    def test_the_cli_prints_every_code(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "rules"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for code in pa.CODES:
            self.assertIn(code, result.stdout)


class NonVacuity(unittest.TestCase):
    def test_a_complete_candidate_is_accepted(self) -> None:
        register = pa._valid_register()
        self.assertEqual(pa.check_register(register), [])

    def test_an_incomplete_experiment_is_accepted(self) -> None:
        register = pa._valid_register()
        arm = register["arms"][0]
        arm["status"] = "EXPERIMENT"
        arm["measurement"] = None
        arm["differential_courts"] = None
        arm["constant_time_audit"] = None
        self.assertEqual(pa.check_register(register), [])


class Determinism(unittest.TestCase):
    def test_check_output_is_byte_identical(self) -> None:
        first = subprocess.run(
            [sys.executable, str(TOOL), "check"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        second = subprocess.run(
            [sys.executable, str(TOOL), "check"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(first.returncode, second.returncode)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stderr, second.stderr)

    def test_the_self_test_passes(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "self-test"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("0 failure(s)", result.stdout)


if __name__ == "__main__":
    unittest.main()
