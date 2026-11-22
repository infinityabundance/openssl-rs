#!/usr/bin/env python3
"""Negative controls for the instrument-qualification checker itself.

The register claims that it fails closed. These tests mutate a copy of the
committed register and require a named refusal for each mutation, so the
checker cannot quietly accept a stale version, a missing instrument, a control
that no longer fires, or a recorded control whose bound evidence changed.

Run inside the court:

    python3 forensics/tools/tests/test_instrument_qualify.py
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
QUALIFY = TOOLS / "instrument_qualify.py"
REGISTRY = REPO_ROOT / "evidence" / "etp3" / "instruments.json"

sys.path.insert(0, str(TOOLS))
import instrument_qualify as iq  # noqa: E402


def load_registry() -> dict:
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


class RegistryMutationControls(unittest.TestCase):
    """A mutated register must be refused, with the mutation named."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="etp3-test-")
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def write(self, document, name: str = "instruments.json") -> Path:
        path = self.dir / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def run_validate(self, document, extra: list[str] | None = None):
        path = self.write(document)
        return subprocess.run(
            [sys.executable, str(QUALIFY), "validate", "--registry", str(path),
             "--repo-root", str(REPO_ROOT), *(extra or [])],
            capture_output=True, text=True, timeout=300,
        )

    def instrument(self, document, ident):
        for entry in document["instruments"]:
            if entry["id"] == ident:
                return entry
        raise AssertionError(f"instrument {ident} not present in the register")

    def assert_refused(self, result, code: str) -> None:
        self.assertNotEqual(result.returncode, 0,
                            f"checker accepted a mutated register:\n{result.stdout}")
        self.assertIn(code, result.stderr,
                      f"expected {code} in stderr, got:\n{result.stderr}")

    def test_committed_register_validates(self) -> None:
        result = subprocess.run(
            [sys.executable, str(QUALIFY), "validate",
             "--repo-root", str(REPO_ROOT)],
            capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REGISTER ok", result.stdout)

    def test_stale_version_is_refused(self) -> None:
        document = load_registry()
        self.instrument(document, "binary-branch-audit")["version_validation"]["observed"] = \
            "objdump from a different decade"
        self.assert_refused(self.run_validate(document), "IQ_VERSION_MISMATCH")

    def test_missing_instrument_path_is_refused(self) -> None:
        document = load_registry()
        self.instrument(document, "dudect")["paths"] = ["courts/phase18/timing/absent.c"]
        self.assert_refused(self.run_validate(document), "IQ_PATH_MISSING")

    def test_unknown_control_is_refused(self) -> None:
        document = load_registry()
        self.instrument(document, "alloc-probe")["sensitivity_control"]["control_id"] = \
            "a-control-that-does-not-exist"
        self.assert_refused(self.run_validate(document), "IQ_CONTROL_UNKNOWN")

    def test_recorded_binding_change_is_refused(self) -> None:
        document = load_registry()
        self.instrument(document, "timecop-supercop")["sensitivity_control"]["binding"]["sha256"] = \
            "0" * 64
        self.assert_refused(self.run_validate(document), "IQ_RECORD_STALE")

    def test_recorded_assertion_absence_is_refused(self) -> None:
        document = load_registry()
        control = self.instrument(document, "tsc-smi-fallbacks")["sensitivity_control"]
        control["assertions"] = ["a-string-that-is-not-in-the-bound-runner"]
        self.assert_refused(self.run_validate(document), "IQ_RECORD_STALE")

    def test_prerequisite_change_is_refused(self) -> None:
        document = load_registry()
        self.instrument(document, "dudect")["sensitivity_control"]["prerequisite"]["sha256"] = \
            "0" * 64
        self.assert_refused(self.run_validate(document), "IQ_CONTROL_PREREQUISITE")

    def test_disclaimer_must_name_the_limit(self) -> None:
        document = load_registry()
        document["disclaimer"] = "everything here is proved"
        self.assert_refused(self.run_validate(document), "IQ_DISCLAIMER")

    def test_pmu_venue_must_match_the_venue(self) -> None:
        document = load_registry()
        document["venue"]["pmu_present"] = True
        self.assert_refused(self.run_validate(document), "IQ_VENUE")

    def test_recorded_control_may_not_claim_pass(self) -> None:
        document = load_registry()
        self.instrument(document, "timecop-supercop")["sensitivity_control"]["status"] = "PASS"
        self.assert_refused(self.run_validate(document), "IQ_CONTROL_STATUS")

    def test_duplicate_json_key_is_refused(self) -> None:
        text = REGISTRY.read_text(encoding="utf-8")
        duplicate = text.replace('"schema":', '"disclaimer": "x", "schema":', 1)
        path = self.dir / "duplicate.json"
        path.write_text(duplicate, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(QUALIFY), "validate", "--registry", str(path),
             "--repo-root", str(REPO_ROOT)],
            capture_output=True, text=True, timeout=300,
        )
        self.assert_refused(result, "IQ_JSON_DUPLICATE_KEY")

    def test_stale_case_table_is_refused(self) -> None:
        document = load_registry()
        control = self.instrument(document, "binary-branch-audit")["sensitivity_control"]
        control["observed"]["cases"][0]["exit"] = 7
        path = self.write(document)
        result = subprocess.run(
            [sys.executable, str(QUALIFY), "check", "--registry", str(path),
             "--repo-root", str(REPO_ROOT), "--only", "binary-branch-audit"],
            capture_output=True, text=True, timeout=600,
        )
        self.assert_refused(result, "CONTROL_STALE")


class ControlFailureControls(unittest.TestCase):
    """A control that does not fire must stop the check, not be ignored."""

    def test_a_control_that_does_not_fire_is_refused(self) -> None:
        document = load_registry()
        entry = next(e for e in document["instruments"] if e["id"] == "alloc-probe")
        entry["sensitivity_control"]["observed"]["cases"] = [
            {"name": "the probe counts every allocation entry point it interposes", "exit": 0},
            {"name": "the forced-failure path fails exactly the requested allocation", "exit": 0},
        ]
        stub = iq.ControlResult("alloc-probe-control")
        stub.cases = [
            iq.Case("the probe counts every allocation entry point it interposes",
                    1, (0,), False, "simulated instrument failure"),
            iq.Case("the forced-failure path fails exactly the requested allocation",
                    1, (0,), False, "simulated instrument failure"),
        ]
        original = iq.CONTROLS["alloc-probe-control"]
        iq.CONTROLS["alloc-probe-control"] = lambda _tmp: stub
        try:
            with self.assertRaises(iq.Refusal) as caught:
                iq.check_against_controls([entry])
        finally:
            iq.CONTROLS["alloc-probe-control"] = original
        self.assertEqual(caught.exception.code, "IQ_CONTROL_FAILED")
        self.assertIn("CONTROL_FAILED alloc-probe", caught.exception.message)


if __name__ == "__main__":
    unittest.main(verbosity=2)
