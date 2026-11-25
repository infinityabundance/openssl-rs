#!/usr/bin/env python3
"""Controls for the PFP-18 performance classification binding validator.

The validator must be able to refuse a record that claims a performance
classification it has not bound. Every refusal code has a negative control that
must be refused by name; the frontier, scoped-observation and independently
reproduced fixtures are positive controls, so the rule set is shown to accept a
complete record as well as reject an incomplete one.

The committed claim records are also cross-bound to the campaign files they
describe: a record whose candidate digest, population or venue class disagrees
with `results.json`, `build-identity.json` or `WORKLOADS.json` fails here even
though the generic validator cannot know those campaign shapes.

Run:

    python3 forensics/tools/tests/test_performance_classification.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
TOOL = TOOLS / "performance_classification.py"
CLAIMS = REPO_ROOT / "evidence" / "performance-frontier" / "claims"
PFP0 = CLAIMS / "PFP-0.claim.json"
PFP1 = CLAIMS / "PFP-1.claim.json"
PFP1_MANIFEST = CLAIMS / "PFP-1.raw-manifest.json"
WORKLOADS = REPO_ROOT / "forensics" / "performance" / "WORKLOADS.json"
PFP0_RESULTS = REPO_ROOT / "evidence/performance-frontier/campaigns/PFP-0/results.json"
PFP0_BUILD = REPO_ROOT / "evidence/performance-frontier/campaigns/PFP-0/build-identity.json"
PFP0_PREREG = REPO_ROOT / "evidence/performance-frontier/campaigns/PFP-0/preregistration.json"
PFP1_RESULTS = REPO_ROOT / "evidence/performance-frontier/campaigns/PFP-1/performance/results.json"
PFP1_BUILD = REPO_ROOT / "evidence/performance-frontier/campaigns/PFP-1/performance/build-identity.json"
PFP1_RAW = REPO_ROOT / "evidence/performance-frontier/campaigns/PFP-1/performance/raw"

sys.path.insert(0, str(TOOLS))
import performance_classification as pc  # noqa: E402


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def codes(record: dict) -> list[str]:
    return sorted({problem.code for problem in pc.check_record(record)})


class CommittedRecords(unittest.TestCase):
    def test_every_committed_record_is_accepted(self) -> None:
        for path in sorted(CLAIMS.glob("*.claim.json")):
            record = load(path)
            self.assertEqual(pc.check_record(record), [], path.name)
            self.assertEqual(record["classification"], "SCOPED_OBSERVATION", path.name)

    def test_the_committed_records_pass_the_cli(self) -> None:
        claims = sorted(CLAIMS.glob("*.claim.json"))
        self.assertTrue(claims, "the claim glob must not be empty")
        result = subprocess.run(
            [sys.executable, str(TOOL), "check"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"{len(claims)} record(s) accepted, 0 refused", result.stdout)
        accepted = [
            line for line in result.stdout.splitlines() if line.startswith("OK ")
        ]
        self.assertEqual(
            len(accepted), len(claims), "every glob match must be accepted exactly once"
        )
        for path in claims:
            self.assertIn(path.name, result.stdout, path.name)

    def test_pfp0_record_matches_its_campaign_files(self) -> None:
        record = load(PFP0)
        results = load(PFP0_RESULTS)
        build = load(PFP0_BUILD)
        workloads = [entry["id"] for entry in load(WORKLOADS)["workloads"]]
        self.assertEqual(record["classification"], results["classification"])
        self.assertEqual(
            record["candidate"]["artefact"]["sha256"],
            results["identity"]["artefacts"]["distribution_dso"]["sha256"],
        )
        self.assertEqual(
            record["candidate"]["artefact"]["sha256"],
            build["artefacts"]["distribution_dso"]["sha256"],
        )
        self.assertEqual(record["candidate"]["source_commit"], build["source"]["head"])
        self.assertEqual(sorted(record["population"]["expected"]), sorted(workloads))
        self.assertEqual(sorted(record["population"]["realised"]), sorted(workloads))
        self.assertEqual(
            record["instrument"]["preregistration"]["sha256"], sha256(PFP0_PREREG)
        )
        self.assertEqual(results["pmu"]["cpu_event_source"], "absent")
        self.assertEqual(record["venue"]["class"], "VIRTUALISED_COURT")
        self.assertFalse(record["venue"]["pmu_exposed"])

    def test_pfp1_record_matches_its_campaign_files(self) -> None:
        record = load(PFP1)
        results = load(PFP1_RESULTS)
        build = load(PFP1_BUILD)
        workloads = [entry["id"] for entry in load(WORKLOADS)["workloads"]]
        self.assertEqual(record["classification"], results["classification"])
        self.assertEqual(
            record["candidate"]["artefact"]["sha256"], build["candidate"]["sha256"]
        )
        self.assertEqual(record["candidate"]["source_commit"], build["source"]["head"])
        self.assertEqual(
            sorted(record["population"]["realised"]), sorted(results["family"])
        )
        self.assertEqual(sorted(record["population"]["expected"]), sorted(workloads))
        self.assertEqual(record["venue"]["pmu_exposed"], results["venue_has_pmu"])
        self.assertFalse(results["venue_has_pmu"])
        self.assertEqual(
            record["instrument"]["samples"]["sha256"], sha256(PFP1_MANIFEST)
        )

    def test_pfp1_raw_manifest_reproduces_from_the_raw_directory(self) -> None:
        manifest = load(PFP1_MANIFEST)
        self.assertEqual(manifest["schema"], "openssl-rs/performance/raw-manifest/1")
        derived = []
        for path in sorted(PFP1_RAW.rglob("*")):
            if path.is_file():
                derived.append(
                    {
                        "path": str(path.relative_to(REPO_ROOT)),
                        "size_bytes": path.stat().st_size,
                        "sha256": sha256(path),
                    }
                )
        self.assertEqual(manifest["files"], derived)
        for entry in manifest["files"]:
            self.assertEqual(sha256(REPO_ROOT / entry["path"]), entry["sha256"])

    def test_the_manifest_is_byte_stable(self) -> None:
        payload = load(PFP1_MANIFEST)
        text = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        self.assertEqual(text.encode("utf-8"), PFP1_MANIFEST.read_bytes())


class FrontierBindingRefusals(unittest.TestCase):
    """The critical control: a frontier claim with a missing binding is refused."""

    def assert_refused(self, record: dict, code: str) -> None:
        got = codes(record)
        self.assertIn(code, got, f"expected {code}, got {got}")

    def test_a_complete_frontier_record_is_accepted(self) -> None:
        self.assertEqual(pc.check_record(pc._valid_record("FRONTIER_LEADING")), [])

    def test_missing_instrument_is_refused(self) -> None:
        record = pc._valid_record("FRONTIER_LEADING")
        record.pop("instrument")
        self.assert_refused(record, pc.PF_INSTRUMENT_IDENTITY_ABSENT)

    def test_missing_population_is_refused(self) -> None:
        record = pc._valid_record("FRONTIER_LEADING")
        record.pop("population")
        self.assert_refused(record, pc.PF_POPULATION_ABSENT)

    def test_missing_candidate_is_refused(self) -> None:
        record = pc._valid_record("FRONTIER_LEADING")
        record.pop("candidate")
        self.assert_refused(record, pc.PF_CANDIDATE_IDENTITY_ABSENT)

    def test_missing_threat_model_is_refused(self) -> None:
        record = pc._valid_record("FRONTIER_LEADING")
        record.pop("threat_model")
        self.assert_refused(record, pc.PF_THREAT_MODEL_ABSENT)

    def test_missing_obligations_is_refused(self) -> None:
        record = pc._valid_record("FRONTIER_LEADING")
        record.pop("obligations")
        self.assert_refused(record, pc.PF_OBLIGATIONS_ABSENT)

    def test_a_virtualised_frontier_claim_is_refused(self) -> None:
        record = pc._valid_record("FRONTIER_LEADING")
        record["venue"] = {
            "class": "VIRTUALISED_COURT",
            "description": "court",
            "pmu_exposed": False,
            "controls": {
                "frequency_pinned": False,
                "turbo_disabled": False,
                "smt_disabled": False,
                "core_isolation": False,
            },
        }
        self.assert_refused(record, pc.PF_VENUE_CLASS_INSUFFICIENT)

    def test_an_unmeasured_frontier_comparator_is_refused(self) -> None:
        record = pc._valid_record("FRONTIER_LEADING")
        record["comparators"].append(
            {"id": "absent", "status": "UNAVAILABLE", "reason": "control"}
        )
        self.assert_refused(record, pc.PF_COMPARATOR_NOT_QUALIFIED)

    def test_a_frontier_record_over_a_non_pmu_campaign_is_refused(self) -> None:
        record = pc._valid_record("FRONTIER_LEADING")
        record["venue"]["pmu_exposed"] = False
        self.assert_refused(record, pc.PF_VENUE_EVIDENCE_CONTRADICTS)

    def test_a_performance_record_may_not_carry_safe_compatible(self) -> None:
        record = pc._valid_record("FRONTIER_LEADING")
        record["assurance"] = {"safe_compatible": True}
        self.assert_refused(record, pc.PF_CLASSIFICATION_CONFLATES_ASSURANCE)

    def test_a_performance_record_may_not_discharge_t23(self) -> None:
        record = pc._valid_record("FRONTIER_LEADING")
        record["obligations"]["attempted_discharge"] = ["T23"]
        self.assert_refused(
            record, pc.PF_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE
        )


class RuleCoverage(unittest.TestCase):
    """Every refusal code must be reachable by a control."""

    def test_every_code_has_at_least_one_negative_control(self) -> None:
        fired: set[str] = set()
        for _name, record, code in pc._controls() + pc._independent_controls():
            problems = pc.check_record(record)
            if code is None:
                self.assertEqual(problems, [], _name)
            else:
                self.assertIn(code, {problem.code for problem in problems}, _name)
                fired.add(code)
        # Loader controls.
        for text, code in (
            ("{", pc.PF_JSON_MALFORMED),
            ('{"a": 1, "a": 1}', pc.PF_JSON_DUPLICATE_KEY),
            ('{"a": NaN}', pc.PF_JSON_NON_FINITE),
        ):
            with self.assertRaises(pc.Refusal) as caught:
                pc.loads_document(text)
            self.assertEqual(caught.exception.code, code)
            fired.add(code)
        # Collection control.
        collection = pc.check_records(
            [
                (Path("a.json"), pc._valid_record("SCOPED_OBSERVATION")),
                (Path("b.json"), pc._valid_record("SCOPED_OBSERVATION")),
            ]
        )
        self.assertIn(
            pc.PF_DUPLICATE_RECORD_ID,
            {problem.code for problem in collection[Path("b.json")]},
        )
        fired.add(pc.PF_DUPLICATE_RECORD_ID)
        self.assertEqual(sorted(fired), sorted(pc.CODES))

    def test_the_rule_table_names_every_code(self) -> None:
        self.assertEqual(sorted(pc.RULES), sorted(pc.CODES))
        self.assertEqual(set(pc.CLASSIFICATION_REQUIREMENTS), set(pc.CLASSIFICATIONS))

    def test_the_cli_prints_every_code(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "rules"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for code in pc.CODES:
            self.assertIn(code, result.stdout)


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

    def test_a_refused_record_exits_one(self) -> None:
        record = pc._valid_record("FRONTIER_LEADING")
        record.pop("instrument")
        with self.subTest("in-process"):
            self.assertNotEqual(pc.check_record(record), [])


if __name__ == "__main__":
    unittest.main()
