#!/usr/bin/env python3
"""Tests for the PFP-53 4-limb CIOS Montgomery multiply model.

These check the *transcribed algorithm* (the Python model in
`forensics/tools/pfp53_cios_model.py`) against its independent oracle, on the
enumerated edge cases, a bounded deterministic random sample, and a few
hand-checkable vectors. This is a finite-sample check of the model, not a proof,
and not a run of the compiled Rust binary.

Run:

    python3 -m unittest forensics.tools.tests.test_pfp53_cios_model
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import pfp53_cios_model as model  # noqa: E402


def _cios4_int(a: int, b: int, m: int) -> int:
    """Drive the model's CIOS transcription and return the integer result."""
    return model.from_limbs(
        model.cios4(
            model.to_limbs(a, 4),
            model.to_limbs(b, 4),
            model.to_limbs(m, 4),
            model.n0_of(m),
        )
    )


class Cios4Model(unittest.TestCase):
    def test_hand_checkable_vectors(self) -> None:
        # m = 3: 2^256 ≡ 1 (mod 3), so R^-1 ≡ 1.
        self.assertEqual(_cios4_int(1, 1, 3), 1)
        self.assertEqual(_cios4_int(2, 2, 3), 1)  # 4 * 1 ≡ 1 (mod 3)
        # m = 5: 2^256 ≡ 1 (mod 5), so R^-1 ≡ 1.
        self.assertEqual(_cios4_int(2, 3, 5), 1)  # 6 * 1 ≡ 1 (mod 5)
        self.assertEqual(_cios4_int(1, 0, 5), 0)
        self.assertEqual(_cios4_int(0, 0, 5), 0)

    def test_edge_cases_match_the_oracle(self) -> None:
        result = model.run_suite(seed=20261128, random_count=0)
        self.assertEqual(result["mismatches"], 0, result)
        self.assertEqual(result["range_violations"], 0, result)
        self.assertGreater(result["edge_cases"], 0)

    def test_bounded_random_sample_matches_the_oracle(self) -> None:
        result = model.run_suite(seed=20261128, random_count=5000)
        self.assertEqual(result["mismatches"], 0, result)
        self.assertEqual(result["range_violations"], 0, result)
        self.assertEqual(result["random_cases"], 5000)


if __name__ == "__main__":
    unittest.main()
