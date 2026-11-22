#!/usr/bin/env python3
"""Controls for the implementation-shaped specification guard.

The committed registry must pass, the inventory must reproduce the measured
population, and every negative control must be refused with the recorded code.
Run inside the court:

    python3 forensics/tools/tests/test_spec_guard.py
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
GUARD = TOOLS / "spec_guard.py"
CONFIG = REPO_ROOT / "evidence" / "etp-t3" / "SPECIFICATIONS.json"

sys.path.insert(0, str(TOOLS))
import spec_guard  # noqa: E402


def load_config() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


class SpecGuardControls(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="etp-t3-spec-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def run_guard(self, command: str, config: dict | None = None, *extra: str):
        if config is None:
            path = CONFIG
        else:
            path = self.directory / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(GUARD), command, "--config", str(path),
             "--repo-root", str(REPO_ROOT), *extra],
            capture_output=True, text=True, timeout=300,
        )

    def assert_refused(self, result, code: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(code, result.stderr)

    # ---------------------------------------------------------------- positive
    def test_committed_registry_passes(self) -> None:
        result = self.run_guard("check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 unclassified", result.stdout)

    def test_inventory_reproduces_the_measured_population(self) -> None:
        result = self.run_guard("inventory", None, "--json")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["population"], 15)
        self.assertEqual(payload["failing"], 5)

    def test_check_output_is_deterministic(self) -> None:
        first = self.run_guard("check")
        second = self.run_guard("check")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stderr, second.stderr)

    def test_self_test_controls(self) -> None:
        result = self.run_guard("self-test")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("6 controls behaved as recorded", result.stdout)

    # ------------------------------------------------------- artefact controls
    def artefact_codes(self, path: str, level, exemptions) -> list[str]:
        levels = spec_guard.level_ids(load_config())
        lexicon = spec_guard.internal_identifiers(REPO_ROOT)
        errors = spec_guard.check_artefact(
            REPO_ROOT, path, level, exemptions, levels, lexicon
        )
        return sorted({error.split(":", 1)[0] for error in errors})

    def test_internal_identifier_is_refused(self) -> None:
        codes = self.artefact_codes(
            "evidence/etp-t3/controls/spec-internal-identifier.md",
            "L1-abstract-specification", [],
        )
        self.assertEqual(codes, ["SP_INTERNAL_IDENTIFIER"])

    def test_justified_exemption_is_accepted(self) -> None:
        codes = self.artefact_codes(
            "evidence/etp-t3/controls/spec-justified-exemption.md",
            "L4-abi-contract",
            [{"token": "OwnedBuf", "justification": "the release site is fixed",
              "reviewer": "independent review", "reviewed": "794a7c549"}],
        )
        self.assertEqual(codes, [])

    def test_unjustified_exemption_is_refused(self) -> None:
        codes = self.artefact_codes(
            "evidence/etp-t3/controls/spec-unjustified-exemption.md",
            "L4-abi-contract", [{"token": "OwnedBuf"}],
        )
        self.assertEqual(codes, ["SP_EXEMPTION_UNJUSTIFIED", "SP_INTERNAL_IDENTIFIER"])

    def test_specification_with_no_declared_level_is_refused(self) -> None:
        codes = self.artefact_codes(
            "evidence/etp-t3/controls/spec-no-level.md", None, []
        )
        self.assertEqual(codes, ["SP_NO_LEVEL"])

    def test_unknown_level_is_refused(self) -> None:
        codes = self.artefact_codes(
            "evidence/etp-t3/controls/spec-unknown-level.md", "L9-none", []
        )
        self.assertEqual(codes, ["SP_UNKNOWN_LEVEL"])

    def test_stale_exemption_is_refused(self) -> None:
        codes = self.artefact_codes(
            "evidence/etp-t3/controls/spec-stale-exemption.md",
            "L1-abstract-specification",
            [{"token": "OwnedBuf", "justification": "stale", "reviewer": "r",
              "reviewed": "794a7c549"}],
        )
        self.assertEqual(codes, ["SP_STALE_EXEMPTION"])

    # --------------------------------------------------------- config controls
    def test_unclassified_population_member_is_refused(self) -> None:
        config = load_config()
        config["specifications"] = [
            entry for entry in config["specifications"]
            if entry["path"] != "docs/ABI_POLICY.md"
        ]
        result = self.run_guard("check", config)
        self.assert_refused(result, "SP_UNCLASSIFIED")
        self.assertIn("docs/ABI_POLICY.md", result.stderr)

    def test_known_failure_drift_is_refused(self) -> None:
        config = load_config()
        entry = next(e for e in config["known_failures"] if e["path"] == "AGENTS.md")
        entry["tokens"] = ["OwnedBuf"]
        result = self.run_guard("check", config)
        self.assert_refused(result, "SP_KNOWN_FAILURE_DRIFT")

    def test_stale_known_failure_is_refused(self) -> None:
        config = load_config()
        config["specifications"] = [
            entry for entry in config["specifications"]
            if entry["path"] != "docs/ABI_POLICY.md"
        ]
        config["known_failures"].append({
            "path": "docs/ABI_POLICY.md",
            "level": "L4-abi-contract",
            "status": "KNOWN_NONCONFORMANCE",
            "tokens": ["OwnedBuf"],
            "would_close": "nothing; this declaration is stale",
        })
        result = self.run_guard("check", config)
        self.assert_refused(result, "SP_STALE_KNOWN_FAILURE")

    def test_known_failure_without_level_is_refused(self) -> None:
        config = load_config()
        entry = next(e for e in config["known_failures"] if e["path"] == "AGENTS.md")
        entry["level"] = None
        result = self.run_guard("check", config)
        self.assert_refused(result, "SP_NO_LEVEL")

    def test_unknown_classification_is_refused(self) -> None:
        config = load_config()
        config["specifications"].append({
            "path": "docs/CI.md", "level": "L1-abstract-specification",
            "level_basis": "test-only", "exemptions": [],
        })
        result = self.run_guard("check", config)
        self.assert_refused(result, "SP_UNKNOWN_CLASSIFICATION")

    def test_exclusion_without_reason_is_refused(self) -> None:
        config = load_config()
        config["excluded"].append({"path": "docs/CI.md"})
        result = self.run_guard("check", config)
        self.assert_refused(result, "SP_EXCLUSION_UNJUSTIFIED")

    def test_duplicate_key_config_is_refused(self) -> None:
        path = self.directory / "duplicate.json"
        text = CONFIG.read_text(encoding="utf-8")
        text = text.replace('"item":', '"item": "duplicate",\n  "item":', 1)
        path.write_text(text, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(GUARD), "check", "--config", str(path),
             "--repo-root", str(REPO_ROOT)],
            capture_output=True, text=True, timeout=300,
        )
        self.assert_refused(result, "SP_JSON_DUPLICATE_KEY")


if __name__ == "__main__":
    unittest.main(verbosity=2)
