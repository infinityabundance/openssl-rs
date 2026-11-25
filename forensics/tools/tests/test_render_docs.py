#!/usr/bin/env python3
"""Controls for the generated README counter and its claim-record source.

A0-F10 is a summary that could not be reconstructed from the record it cited:
the README rendered `SAFE_COMPATIBLE 1/33` after `CAMPAIGN-STATUS.json` had been
reconciled to `0/33` with 1 risk-accepted family. These controls fail if the
generated counter stops matching `consumers` in the claim record, or if the
zero branch hides the risk-accepted family.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import render_docs  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]


class RenderedReadmeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = render_docs.Evidence(ROOT)
        cls.blocks = cls.evidence.blocks()
        cls.readme_names = [
            name for name, dest in render_docs.BLOCKS.items() if dest == render_docs.README
        ]

    def test_generated_readme_blocks_match_their_evidence(self) -> None:
        rendered = render_docs.replace_blocks(
            ROOT / render_docs.README, self.blocks, self.readme_names
        )
        actual = (ROOT / render_docs.README).read_text(encoding="utf-8")
        self.assertEqual(
            actual,
            rendered,
            "README generated blocks are stale; regenerate README from "
            "render_docs.Evidence.blocks() (do not rewrite the frozen "
            "STATUS-2026-10-20.md block)",
        )

    def test_counter_is_the_claim_record_value(self) -> None:
        consumers = self.evidence.consumers
        counter = f"{consumers['safe_compatible']} / {consumers['families_total']}"
        achievements = self.blocks["readme-achievements"]
        self.assertIn(counter, achievements)
        if consumers["safe_compatible"] == 0 and consumers.get("risk_accepted"):
            self.assertIn("risk-accepted", achievements)
            for family in consumers.get("risk_accepted_families") or []:
                self.assertIn(f"`{family}`", achievements)
            self.assertIn("not a graduation", achievements)


class CounterClauseControls(unittest.TestCase):
    def clause(self, consumers: dict, graduation: dict | None = None) -> str:
        fake = SimpleNamespace(consumers=consumers, status={})
        if graduation is not None:
            fake.status = {"safe_compatible_graduation": graduation}
        return render_docs.Evidence.safe_compatible_clause(fake)

    def test_zero_counter_names_the_risk_accepted_family(self) -> None:
        clause = self.clause(
            {
                "safe_compatible": 0,
                "families_total": 33,
                "risk_accepted": 1,
                "risk_accepted_families": ["openssh"],
            }
        )
        self.assertIn("`openssh`", clause)
        self.assertIn("not a graduation", clause)

    def test_zero_counter_without_risk_acceptance_invents_none(self) -> None:
        clause = self.clause(
            {
                "safe_compatible": 0,
                "families_total": 33,
                "risk_accepted": 0,
                "risk_accepted_families": [],
            }
        )
        self.assertEqual(clause, "no family has a proven dependency closure")

    def test_positive_counter_reports_the_graduation(self) -> None:
        clause = self.clause(
            {"safe_compatible": 1, "families_total": 33},
            {
                "admitted_family": "openssh",
                "families": ["ssh", "sshd"],
                "candidate_tag": "b85c",
            },
        )
        self.assertIn("`openssh`", clause)
        self.assertIn("`ssh`, `sshd`", clause)


if __name__ == "__main__":
    unittest.main()
