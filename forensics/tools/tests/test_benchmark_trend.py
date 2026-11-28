#!/usr/bin/env python3
"""Controls for `forensics/tools/benchmark_trend.py` (PFP-66).

The negative control is the exact comparison that motivated the item: PFP-11's
P-256 row (sign **and verify** inside the timed region) against M-A1's
`ecdsa256` row (sign only).  Both rows are labelled `ecdsa256`, so the refusal
must come from the `timed_operations` data, not from the name.

Run directly (`python3 forensics/tools/tests/test_benchmark_trend.py`) or with
`python3 -m unittest forensics.tools.tests.test_benchmark_trend`.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "forensics" / "tools"))

import benchmark_trend as bt  # noqa: E402

MA1 = ROOT / "evidence/performance-frontier/campaigns/M-A1/timing/raw/timing-summary.json"
PFP11 = ROOT / "evidence/performance-frontier/campaigns/PFP-11/raw/phase2-three-arm.json"


def row(path: Path, pointer: str) -> dict:
    return bt.resolve_pointer(json.loads(path.read_text(encoding="utf-8")), pointer)


class WorkloadIdentityControls(unittest.TestCase):
    def test_pfp11_sign_verify_vs_ma1_sign_only_is_refused(self):
        """The motivating comparison: same name, different timed operations."""
        with self.assertRaises(bt.Refusal) as caught:
            bt.compare(
                row(PFP11, "/p256/ecdsa256"),
                row(MA1, "/workloads/ecdsa256"),
            )
        self.assertEqual(caught.exception.code, bt.BENCH_TREND_IDENTITY_MISMATCH)
        self.assertIn("ECDSA_do_verify", caught.exception.detail)

    def test_the_two_rows_really_share_the_label(self):
        """The refusal is not an artefact of differing ids."""
        a = row(PFP11, "/p256/ecdsa256")["workload_identity"]
        b = row(MA1, "/workloads/ecdsa256")["workload_identity"]
        self.assertEqual(a["workload_id"], b["workload_id"])
        self.assertEqual(a["workload_id"], "ecdsa256")
        self.assertNotEqual(a["timed_operations"], b["timed_operations"])

    def test_same_identity_is_comparable(self):
        subject = row(MA1, "/workloads/ecdsa256")
        result = bt.compare(subject, subject)
        self.assertTrue(result["comparable"])
        self.assertEqual(result["timed_operations"], ["ECDSA_do_sign"])

    def test_different_names_are_distinct_even_with_equal_operations(self):
        """The id is part of the identity; the operations are never inferred from a name."""
        a = {"workload_identity": {"workload_id": "row-a", "timed_operations": ["ECDSA_do_sign"]}}
        b = {"workload_identity": {"workload_id": "row-b", "timed_operations": ["ECDSA_do_sign"]}}
        with self.assertRaises(bt.Refusal) as caught:
            bt.compare(a, b)
        # The id is part of the identity too, so unlike names still refuse; the
        # point of the control is that the *operations* are never inferred from
        # the name in either direction.
        self.assertEqual(caught.exception.code, bt.BENCH_TREND_IDENTITY_MISMATCH)

    def test_matching_name_different_operations_is_refused(self):
        a = {"workload_identity": {"workload_id": "ecdsa256", "timed_operations": ["ECDSA_do_sign"]}}
        b = {
            "workload_identity": {
                "workload_id": "ecdsa256",
                "timed_operations": ["ECDSA_do_sign", "ECDSA_do_verify"],
            }
        }
        with self.assertRaises(bt.Refusal) as caught:
            bt.compare(a, b)
        self.assertEqual(caught.exception.code, bt.BENCH_TREND_IDENTITY_MISMATCH)

    def test_absent_identity_is_refused(self):
        with self.assertRaises(bt.Refusal) as caught:
            bt.compare({}, {"workload_identity": {"workload_id": "x", "timed_operations": ["op"]}})
        self.assertEqual(caught.exception.code, bt.BENCH_TREND_IDENTITY_ABSENT)

    def test_malformed_identity_is_refused(self):
        with self.assertRaises(bt.Refusal) as caught:
            bt.compare(
                {"workload_identity": {"workload_id": "x", "timed_operations": []}},
                {"workload_identity": {"workload_id": "x", "timed_operations": ["op"]}},
            )
        self.assertEqual(caught.exception.code, bt.BENCH_TREND_IDENTITY_MALFORMED)

    def test_missing_pointer_is_refused(self):
        with self.assertRaises(bt.Refusal) as caught:
            bt.resolve_pointer({}, "/nope")
        self.assertEqual(caught.exception.code, bt.BENCH_TREND_ROW_ABSENT)

    def test_cli_returns_one_on_the_motivating_comparison(self):
        argv = [
            "--first", str(PFP11), "--first-row", "/p256/ecdsa256",
            "--second", str(MA1), "--second-row", "/workloads/ecdsa256",
        ]
        self.assertEqual(bt.main(argv), 1)

    def test_cli_returns_zero_for_the_same_row(self):
        argv = [
            "--first", str(MA1), "--first-row", "/workloads/ecdsa256",
            "--second", str(MA1), "--second-row", "/workloads/ecdsa256",
        ]
        self.assertEqual(bt.main(argv), 0)


if __name__ == "__main__":
    unittest.main()
