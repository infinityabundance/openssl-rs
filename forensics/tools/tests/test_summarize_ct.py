#!/usr/bin/env python3
"""Outcome-contract controls for courts/phase18/timing/summarize_ct.py (E5a).

An empty log, an unrelated log and a malformed log each used to print
``total contexts: 0`` and exit 0.  These controls require the summariser to
refuse each with its own stable code and a distinct exit status, and require the
accepted case to keep its recorded counts and output shape.

Run directly (`python3 forensics/tools/tests/test_summarize_ct.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
SCRIPT = REPO_ROOT / "courts" / "phase18" / "timing" / "summarize_ct.py"

FINDING = (
    "==1== Conditional jump or move depends on uninitialised value(s)\n"
    "==1==    at 0x1000: mont_mul_into (fixture.S:6)\n"
    "==1==    by 0x2000: caller (fixture.S:20)\n"
)
UNRELATED = (
    "==1== Memcheck, a memory error detector\n"
    "==1== Command: ./nothing-much\n"
    "==1==\n==1== HEAP SUMMARY:\n"
    "==1==   in use at exit: 0 bytes in 0 blocks\n"
)
MALFORMED = (
    "==1== Conditional jump or move depends on uninitialised value(s)\n"
    "==1== HEAP SUMMARY:\n"
)


class SummarizerContract(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ct-summary-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def write(self, name: str, text: str) -> Path:
        path = self.directory / name
        path.write_text(text, encoding="utf-8")
        return path

    def run_script(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
            timeout=120,
        )

    def test_a_finding_log_is_accepted_with_its_counts(self) -> None:
        result = self.run_script("0", str(self.write("finding.log", FINDING)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("total contexts: 1", result.stdout)
        self.assertIn("-- first 12 distinct stacks --", result.stdout)
        self.assertIn("mont_mul_into", result.stdout)

    def test_two_contexts_are_counted_and_not_deduplicated(self) -> None:
        log = self.write("two.log", FINDING + FINDING.replace("0x1000", "0x1100"))
        result = self.run_script("0", str(log))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("total contexts: 2", result.stdout)

    def test_an_empty_log_is_refused(self) -> None:
        result = self.run_script("0", str(self.write("empty.log", "")))
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("CT_SUMMARY_EMPTY_LOG", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_a_whitespace_only_log_is_empty(self) -> None:
        result = self.run_script("0", str(self.write("blank.log", "\n \n\t\n")))
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("CT_SUMMARY_EMPTY_LOG", result.stderr)

    def test_an_unrelated_log_is_refused(self) -> None:
        result = self.run_script("0", str(self.write("unrelated.log", UNRELATED)))
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn("CT_SUMMARY_UNRELATED_LOG", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_a_clean_zero_context_run_is_not_success(self) -> None:
        # A clean memcheck run and a run that never executed produce the same
        # bytes here; neither may be reported as a summarised result.
        result = self.run_script("0", str(self.write("clean.log", UNRELATED)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CT_SUMMARY_UNRELATED_LOG", result.stderr)

    def test_a_malformed_log_is_refused_distinctly(self) -> None:
        result = self.run_script("0", str(self.write("malformed.log", MALFORMED)))
        self.assertEqual(result.returncode, 5, result.stderr)
        self.assertIn("CT_SUMMARY_MALFORMED_LOG", result.stderr)
        self.assertNotIn("CT_SUMMARY_UNRELATED_LOG", result.stderr)

    def test_an_unreadable_log_is_refused_distinctly(self) -> None:
        missing = self.directory / "absent.log"
        result = self.run_script("0", str(missing))
        self.assertEqual(result.returncode, 6, result.stderr)
        self.assertIn("CT_SUMMARY_UNREADABLE_LOG", result.stderr)

    def test_the_three_refusals_have_distinct_codes_and_statuses(self) -> None:
        cases = {
            "empty": (self.write("e.log", ""), "CT_SUMMARY_EMPTY_LOG"),
            "unrelated": (self.write("u.log", UNRELATED), "CT_SUMMARY_UNRELATED_LOG"),
            "malformed": (self.write("m.log", MALFORMED), "CT_SUMMARY_MALFORMED_LOG"),
        }
        observed = {}
        for name, (path, code) in cases.items():
            result = self.run_script("0", str(path))
            self.assertIn(code, result.stderr)
            observed[name] = (code, result.returncode)
        self.assertEqual(len({status for _, status in observed.values()}), 3)
        self.assertEqual(len({code for code, _ in observed.values()}), 3)
        for name, (_, status) in observed.items():
            self.assertNotEqual(status, 0, f"{name} returned success")

    def test_a_bad_address_base_is_a_usage_refusal(self) -> None:
        result = self.run_script("not-hex", str(self.write("finding.log", FINDING)))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("CT_SUMMARY_USAGE", result.stderr)

    def test_the_contract_is_declared_in_the_source(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        for code in (
            "CT_SUMMARY_EMPTY_LOG",
            "CT_SUMMARY_UNRELATED_LOG",
            "CT_SUMMARY_MALFORMED_LOG",
            "CT_SUMMARY_UNREADABLE_LOG",
        ):
            self.assertIn(code, text)


if __name__ == "__main__":
    unittest.main()
