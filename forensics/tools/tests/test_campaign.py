#!/usr/bin/env python3
"""Controls for campaign accountability.

Each control exercises one rule of `docs/CAMPAIGN-ACCOUNTABILITY.md`: a campaign
is opened, amended and terminated; a closure may record a failure but may not
omit one; a success summary may not sit over a SKIP or a NOT_RUN; an abandonment
must say which required checks were not done; and a reconciliation refuses a
plan that silently narrowed against an independent plan.

A control mutates a synthetic campaign in memory.  It is not a source change and
not a defect report: a control that fires proves the refusal works, not that the
substituted form occurs anywhere in the tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import campaign as ac  # noqa: E402
import completeness as a5  # noqa: E402

EVIDENCE = REPO_ROOT / "evidence" / "b3"
CAMPAIGNS = EVIDENCE / "CAMPAIGNS.json"
RECONCILIATION = EVIDENCE / "RECONCILIATION.json"
CONTROLS = EVIDENCE / "CONTROLS.json"
PRODUCER = EVIDENCE / "build_evidence.py"
DOCUMENT = REPO_ROOT / "docs" / "CAMPAIGN-ACCOUNTABILITY.md"
TOOL = TOOLS / "campaign.py"


def base_campaign() -> dict:
    return {
        "schema": ac.CAMPAIGN_SCHEMA,
        "campaignId": "test-campaign",
        "opening": {
            "campaignId": "test-campaign",
            "openedAt": "2026-01-01T00:00:00Z",
            "plan": copy.deepcopy(ac.BASE_PLAN),
        },
        "amendments": [],
        "closureHistory": [],
        "closure": closure(
            [("C1", ac.R_PASS), ("C2", ac.R_PASS), ("C3", ac.R_PASS)],
            claims_success=True,
        ),
        "abandonment": None,
    }


def outcome(check_id: str, result: str) -> dict:
    if result in (ac.R_PASS, ac.R_FAIL):
        return {
            "checkId": check_id,
            "result": result,
            "evidence": f"test-only:evidence/{check_id}",
            "reason": "",
        }
    return {
        "checkId": check_id,
        "result": result,
        "evidence": "",
        "reason": f"test-only:{result.lower()}",
    }


def closure(rows, claims_success: bool, at: str = "2026-01-02T00:00:00Z") -> dict:
    outcomes = [outcome(check_id, result) for check_id, result in rows]
    tally = {result: 0 for result in ac.RESULTS}
    for _, result in rows:
        tally[result] += 1
    return {
        "at": at,
        "outcomes": outcomes,
        "summary": {
            "text": "test-only summary",
            "claimsSuccess": claims_success,
            "counts": {
                "pass": tally[ac.R_PASS],
                "fail": tally[ac.R_FAIL],
                "skip": tally[ac.R_SKIP],
                "notRun": tally[ac.R_NOT_RUN],
                "planned": len(rows),
                "accounted": len(rows),
            },
        },
    }


def amendment(**overrides) -> dict:
    value = {
        "at": "2026-01-01T12:00:00Z",
        "reason": "test-only amendment",
        "adds": [],
        "removes": [],
        "supersedes": [],
        "by": "test-only:author",
    }
    value.update(overrides)
    return value


def refusal_of(campaign: dict, **kwargs) -> str:
    try:
        ac.validate(campaign, **kwargs)
    except ac.Refusal as refusal:
        return refusal.code
    raise AssertionError("the record was not refused")


def run_tool(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), *arguments],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO_ROOT),
    )


def load_real_campaigns() -> dict[str, dict]:
    document = json.loads(CAMPAIGNS.read_text(encoding="utf-8"))
    return {campaign["campaignId"]: campaign for campaign in document["campaigns"]}


class Vocabulary(unittest.TestCase):
    def test_every_refusal_starts_with_ac_refused(self) -> None:
        for code in ac.REFUSALS:
            self.assertTrue(code.startswith("AC_REFUSED_"), code)
        for code in (
            ac.AC_OK,
            ac.AC_USAGE,
            ac.AC_INVALID,
            ac.AC_OPEN,
            ac.AC_CLOSED_CLEAN,
            ac.AC_CLOSED_WITH_FAILURES,
            ac.AC_ABANDONED,
        ):
            self.assertTrue(code.startswith("AC_"), code)
            self.assertFalse(code.startswith("AC_REFUSED_"), code)

    def test_the_two_modules_do_not_share_a_code(self) -> None:
        """B3 uses AC_; A5's completeness admission uses CA_.  No overlap."""
        a5_codes = {
            value
            for value in vars(a5).values()
            if isinstance(value, str) and value.startswith(("CA_REFUSED_", "CA_"))
        }
        b3_codes = set(ac.REFUSALS) | {
            ac.AC_OK,
            ac.AC_USAGE,
            ac.AC_INVALID,
            ac.AC_OPEN,
            ac.AC_CLOSED_CLEAN,
            ac.AC_CLOSED_WITH_FAILURES,
            ac.AC_ABANDONED,
        }
        self.assertTrue(a5_codes, "A5 exposes no CA_ code; the collision test would be vacuous")
        self.assertGreaterEqual(len(a5_codes), 10)
        self.assertEqual(a5_codes & b3_codes, set())
        for code in a5_codes:
            self.assertFalse(code.startswith("AC_"), code)
        for code in b3_codes:
            self.assertFalse(code.startswith("CA_"), code)

    def test_states_and_results_are_the_declared_vocabularies(self) -> None:
        self.assertEqual(
            set(ac.STATES),
            {"OPEN", "CLOSED_CLEAN", "CLOSED_WITH_FAILURES", "ABANDONED", "INVALID"},
        )
        self.assertEqual(set(ac.RESULTS), {"PASS", "FAIL", "SKIP", "NOT_RUN"})


class Controls(unittest.TestCase):
    def test_one_control_per_refusal_code_and_none_missed(self) -> None:
        controls = ac.build_controls()
        self.assertTrue(controls["coversEveryCode"])
        observed = {
            control["code"]
            for control in controls["controls"]
            if control["kind"] == "refusal"
        }
        self.assertEqual(observed, set(ac.REFUSALS))
        for control in controls["controls"]:
            self.assertTrue(control["controlOnly"])
            self.assertTrue(control["established"], control["name"])
            self.assertEqual(control["observed"], control["code"], control["name"])

    def test_the_required_controls_are_present_and_named(self) -> None:
        names = {control["name"] for control in ac.build_controls()["controls"]}
        required = {
            "omitted-check",
            "failure-omitted",
            "skip-as-pass",
            "not-run-as-pass",
            "retroactive-amendment",
            "double-terminator",
            "unplanned-outcome",
            "duplicate-outcome",
            "abandonment-silent",
            "order-terminator",
            "plan-narrowed",
        }
        self.assertTrue(required <= names, sorted(required - names))

    def test_the_positive_controls_reach_the_states_they_name(self) -> None:
        controls = ac.build_controls()
        self.assertEqual(
            sorted(controls["positiveControls"]),
            ["positive-closed-clean", "positive-closed-with-failures"],
        )


class ClosureRules(unittest.TestCase):
    def test_a_recorded_failure_is_accepted(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = closure(
            [("C1", ac.R_PASS), ("C2", ac.R_FAIL), ("C3", ac.R_PASS)],
            claims_success=False,
        )
        report = ac.validate(campaign)
        self.assertEqual(report["state"], ac.S_CLOSED_WITH_FAILURES)
        self.assertEqual(report["code"], ac.AC_CLOSED_WITH_FAILURES)
        self.assertEqual(report["outcomes"]["fail"], 1)
        self.assertEqual(report["outcomes"]["pass"], 2)

    def test_a_closure_that_omits_the_failed_check_is_refused(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = closure(
            [("C1", ac.R_PASS), ("C2", ac.R_PASS)], claims_success=False
        )
        self.assertEqual(refusal_of(campaign), ac.R_OMITTED_CHECK)

    def test_skip_in_a_success_summary_is_refused(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = closure(
            [("C1", ac.R_PASS), ("C2", ac.R_SKIP), ("C3", ac.R_PASS)],
            claims_success=True,
        )
        self.assertEqual(refusal_of(campaign), ac.R_SKIP_AS_PASS)

    def test_not_run_in_a_success_summary_is_refused(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = closure(
            [("C1", ac.R_PASS), ("C2", ac.R_NOT_RUN), ("C3", ac.R_PASS)],
            claims_success=True,
        )
        self.assertEqual(refusal_of(campaign), ac.R_NOT_RUN_AS_PASS)

    def test_a_skip_recorded_without_a_success_claim_is_accepted(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = closure(
            [("C1", ac.R_PASS), ("C2", ac.R_SKIP), ("C3", ac.R_PASS)],
            claims_success=False,
        )
        report = ac.validate(campaign)
        self.assertEqual(report["state"], ac.S_CLOSED_WITH_FAILURES)
        self.assertEqual(report["outcomes"]["skip"], 1)

    def test_a_not_run_recorded_without_a_success_claim_is_accepted(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = closure(
            [("C1", ac.R_PASS), ("C2", ac.R_NOT_RUN), ("C3", ac.R_PASS)],
            claims_success=False,
        )
        report = ac.validate(campaign)
        self.assertEqual(report["state"], ac.S_CLOSED_WITH_FAILURES)
        self.assertEqual(report["outcomes"]["notRun"], 1)

    def test_counts_that_do_not_reconcile_are_refused(self) -> None:
        campaign = base_campaign()
        campaign["closure"]["summary"]["counts"]["pass"] = 2
        self.assertEqual(refusal_of(campaign), ac.R_COUNT_MISMATCH)

    def test_passed_and_accounted_must_equal_the_outcomes(self) -> None:
        campaign = base_campaign()
        campaign["closure"]["summary"]["counts"]["accounted"] = 2
        self.assertEqual(refusal_of(campaign), ac.R_COUNT_MISMATCH)

    def test_a_pass_without_evidence_is_not_an_outcome(self) -> None:
        campaign = base_campaign()
        campaign["closure"]["outcomes"][0]["evidence"] = ""
        self.assertEqual(refusal_of(campaign), ac.R_MANIFEST_INVALID)

    def test_a_skip_without_a_reason_is_not_an_outcome(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = closure(
            [("C1", ac.R_PASS), ("C2", ac.R_SKIP), ("C3", ac.R_PASS)],
            claims_success=False,
        )
        campaign["closure"]["outcomes"][1]["reason"] = ""
        self.assertEqual(refusal_of(campaign), ac.R_MANIFEST_INVALID)


class AmendmentRules(unittest.TestCase):
    def test_an_amendment_that_supersedes_an_outcome_is_retroactive(self) -> None:
        campaign = base_campaign()
        campaign["amendments"] = [amendment(supersedes=["C1"])]
        self.assertEqual(refusal_of(campaign), ac.R_RETROACTIVE_AMENDMENT)

    def test_an_amendment_that_removes_a_closed_check_is_retroactive(self) -> None:
        campaign = base_campaign()
        campaign["amendments"] = [amendment(removes=["C3"])]
        self.assertEqual(refusal_of(campaign), ac.R_RETROACTIVE_AMENDMENT)

    def test_an_amendment_that_edits_an_outcome_is_retroactive(self) -> None:
        campaign = base_campaign()
        campaign["amendments"] = [amendment(outcomeEdits=["C1"])]
        self.assertEqual(refusal_of(campaign), ac.R_RETROACTIVE_AMENDMENT)

    def test_an_amendment_that_binds_to_nothing_is_refused(self) -> None:
        campaign = base_campaign()
        campaign["amendments"] = [amendment()]
        self.assertEqual(refusal_of(campaign), ac.R_UNBOUND_AMENDMENT)

    def test_an_amendment_that_names_an_unplanned_check_is_refused(self) -> None:
        campaign = base_campaign()
        campaign["amendments"] = [amendment(removes=["C9"])]
        self.assertEqual(refusal_of(campaign), ac.R_UNBOUND_AMENDMENT)

    def test_a_prospective_removal_is_allowed_and_shrinks_the_effective_plan(self) -> None:
        campaign = base_campaign()
        campaign["amendments"] = [amendment(removes=["C3"])]
        campaign["closure"] = closure(
            [("C1", ac.R_PASS), ("C2", ac.R_PASS)], claims_success=True
        )
        report = ac.validate(campaign)
        self.assertEqual(report["planned"], 2)
        self.assertEqual(report["removed"], ["C3"])
        self.assertEqual(report["state"], ac.S_CLOSED_CLEAN)

    def test_a_prospective_addition_is_allowed_and_must_be_answered(self) -> None:
        campaign = base_campaign()
        campaign["amendments"] = [
            amendment(adds=[{"checkId": "C4", "description": "added", "required": True}])
        ]
        campaign["closure"] = closure(
            [("C1", ac.R_PASS), ("C2", ac.R_PASS), ("C3", ac.R_PASS)],
            claims_success=True,
        )
        self.assertEqual(refusal_of(campaign), ac.R_OMITTED_CHECK)
        campaign["closure"] = closure(
            [
                ("C1", ac.R_PASS),
                ("C2", ac.R_PASS),
                ("C3", ac.R_PASS),
                ("C4", ac.R_PASS),
            ],
            claims_success=True,
        )
        self.assertEqual(ac.validate(campaign)["planned"], 4)

    def test_an_amendment_before_the_opening_is_out_of_order(self) -> None:
        campaign = base_campaign()
        campaign["amendments"] = [
            amendment(at="2025-12-31T00:00:00Z", supersedes=["C1"])
        ]
        self.assertEqual(refusal_of(campaign), ac.R_ORDER)

    def test_an_amendment_after_the_terminator_is_out_of_order(self) -> None:
        campaign = base_campaign()
        campaign["amendments"] = [
            amendment(at="2026-01-03T00:00:00Z", supersedes=["C1"])
        ]
        self.assertEqual(refusal_of(campaign), ac.R_ORDER)


class OpeningAndTerminatorRules(unittest.TestCase):
    def test_no_opening_is_refused(self) -> None:
        campaign = base_campaign()
        del campaign["opening"]
        self.assertEqual(refusal_of(campaign), ac.R_NO_OPENING)

    def test_two_openings_are_refused(self) -> None:
        campaign = base_campaign()
        campaign["opening"] = [campaign["opening"], copy.deepcopy(campaign["opening"])]
        self.assertEqual(refusal_of(campaign), ac.R_DOUBLE_OPENING)

    def test_two_closures_are_refused(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = [campaign["closure"], copy.deepcopy(campaign["closure"])]
        self.assertEqual(refusal_of(campaign), ac.R_DOUBLE_TERMINATOR)

    def test_a_closure_and_an_abandonment_are_two_terminators(self) -> None:
        campaign = base_campaign()
        campaign["abandonment"] = {
            "at": "2026-01-02T00:00:00Z",
            "reason": "test-only",
            "notDone": [
                {"checkId": check_id, "why": "test-only"} for check_id in ("C1", "C2", "C3")
            ],
        }
        self.assertEqual(refusal_of(campaign), ac.R_DOUBLE_TERMINATOR)

    def test_a_campaign_with_no_terminator_is_open_and_refused_only_when_required(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = None
        report = ac.validate(campaign)
        self.assertEqual(report["state"], ac.S_OPEN)
        self.assertEqual(report["code"], ac.AC_OPEN)
        self.assertEqual(
            refusal_of(campaign, require_terminator=True), ac.R_NO_TERMINATOR
        )

    def test_a_record_claiming_a_closure_without_one_is_refused(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = None
        campaign["state"] = ac.S_CLOSED_CLEAN
        self.assertEqual(refusal_of(campaign), ac.R_NO_TERMINATOR)

    def test_a_terminator_before_its_opening_is_out_of_order(self) -> None:
        campaign = base_campaign()
        campaign["closure"]["at"] = "2025-12-31T00:00:00Z"
        self.assertEqual(refusal_of(campaign), ac.R_ORDER)

    def test_a_record_that_misnames_its_own_state_is_refused(self) -> None:
        campaign = base_campaign()
        campaign["state"] = ac.S_OPEN
        self.assertEqual(refusal_of(campaign), ac.R_MANIFEST_INVALID)


class OutcomeRules(unittest.TestCase):
    def test_an_outcome_for_an_unplanned_check_is_refused(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = closure(
            [
                ("C1", ac.R_PASS),
                ("C2", ac.R_PASS),
                ("C3", ac.R_PASS),
                ("C9", ac.R_PASS),
            ],
            claims_success=True,
        )
        self.assertEqual(refusal_of(campaign), ac.R_UNPLANNED_OUTCOME)

    def test_a_duplicate_outcome_is_refused(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = closure(
            [
                ("C1", ac.R_PASS),
                ("C1", ac.R_PASS),
                ("C2", ac.R_PASS),
                ("C3", ac.R_PASS),
            ],
            claims_success=True,
        )
        self.assertEqual(refusal_of(campaign), ac.R_DUPLICATE_OUTCOME)

    def test_an_unknown_result_is_refused(self) -> None:
        campaign = base_campaign()
        campaign["closure"]["outcomes"][0]["result"] = "PARTIAL"
        self.assertEqual(refusal_of(campaign), ac.R_MANIFEST_INVALID)


class AbandonmentRules(unittest.TestCase):
    def _abandonment(self, checks) -> dict:
        return {
            "at": "2026-01-02T00:00:00Z",
            "reason": "test-only abandonment",
            "notDone": [{"checkId": check_id, "why": f"test-only: {check_id}"} for check_id in checks],
        }

    def test_an_abandonment_that_names_every_required_check_is_accepted(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = None
        campaign["abandonment"] = self._abandonment(("C1", "C2", "C3"))
        report = ac.validate(campaign)
        self.assertEqual(report["state"], ac.S_ABANDONED)
        self.assertEqual(report["code"], ac.AC_ABANDONED)
        self.assertEqual(report["notDone"], 3)

    def test_an_abandonment_that_omits_a_required_check_is_refused(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = None
        campaign["abandonment"] = self._abandonment(("C1", "C2"))
        self.assertEqual(refusal_of(campaign), ac.R_ABANDONMENT_SILENT)

    def test_an_abandonment_names_an_unplanned_check(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = None
        campaign["abandonment"] = self._abandonment(("C1", "C2", "C9"))
        self.assertEqual(refusal_of(campaign), ac.R_MANIFEST_INVALID)

    def test_an_abandonment_is_not_a_closure(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = None
        campaign["abandonment"] = self._abandonment(("C1", "C2", "C3"))
        report = ac.validate(campaign)
        self.assertNotIn(report["state"], (ac.S_CLOSED_CLEAN, ac.S_CLOSED_WITH_FAILURES))
        self.assertEqual(report["state"], ac.S_ABANDONED)


class ReconciliationRules(unittest.TestCase):
    def test_a_narrowed_plan_is_refused(self) -> None:
        campaign = base_campaign()
        campaign["opening"]["plan"] = copy.deepcopy(ac.BASE_PLAN[:2])
        campaign["closure"] = closure(
            [("C1", ac.R_PASS), ("C2", ac.R_PASS)], claims_success=True
        )
        with self.assertRaises(ac.Refusal) as raised:
            ac.reconcile(campaign, copy.deepcopy(ac.BASE_PLAN))
        self.assertEqual(raised.exception.code, ac.R_PLAN_NARROWED)

    def test_a_superset_plan_is_not_narrowed(self) -> None:
        campaign = base_campaign()
        campaign["amendments"] = [
            amendment(adds=[{"checkId": "C4", "description": "extra", "required": True}])
        ]
        campaign["closure"] = closure(
            [
                ("C1", ac.R_PASS),
                ("C2", ac.R_PASS),
                ("C3", ac.R_PASS),
                ("C4", ac.R_PASS),
            ],
            claims_success=True,
        )
        report = ac.reconcile(campaign, copy.deepcopy(ac.BASE_PLAN))
        self.assertFalse(report["narrowed"])
        self.assertEqual(report["omitted"], [])
        self.assertEqual(report["campaignOnly"], ["C4"])

    def test_produced_and_missing_are_read_from_the_declared_paths(self) -> None:
        campaign = base_campaign()
        campaign["opening"]["plan"] = copy.deepcopy(ac.BASE_PLAN[:2])
        campaign["closure"] = closure(
            [("C1", ac.R_PASS), ("C2", ac.R_PASS)], claims_success=True
        )
        external = [
            {"checkId": "C1", "path": "present.json", "required": True},
            {"checkId": "C2", "path": "absent.json", "required": True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "present.json").write_text("{}", encoding="utf-8")
            report = ac.reconcile(campaign, external, root=directory)
        self.assertEqual(report["produced"], ["C1"])
        self.assertEqual(report["missing"], ["C2"])
        self.assertFalse(report["narrowed"])
        self.assertTrue(report["liveView"])
        self.assertIsNone(report["asOfCommit"])

    def test_a_frozen_view_reads_the_declared_tree_not_the_working_tree(self) -> None:
        campaign = base_campaign()
        campaign["opening"]["plan"] = copy.deepcopy(ac.BASE_PLAN[:2])
        campaign["closure"] = closure(
            [("C1", ac.R_PASS), ("C2", ac.R_PASS)], claims_success=True
        )
        external = [
            {"checkId": "C1", "path": "present.json", "required": True},
            {"checkId": "C2", "path": "absent.json", "required": True},
        ]
        commit = "not-a-real-commit"
        with tempfile.TemporaryDirectory() as directory:
            # The working tree has only present.json; the declared tree only absent.json.
            (Path(directory) / "present.json").write_text("{}", encoding="utf-8")
            live = ac.reconcile(campaign, external, root=directory)
            frozen = ac.reconcile(
                campaign, external, root=directory, as_of=commit, tree={"absent.json"}
            )
        self.assertTrue(live["liveView"])
        self.assertEqual(live["produced"], ["C1"])
        self.assertEqual(live["missing"], ["C2"])
        self.assertFalse(frozen["liveView"])
        self.assertEqual(frozen["asOfCommit"], commit)
        self.assertEqual(frozen["produced"], ["C2"])
        self.assertEqual(frozen["missing"], ["C1"])
        self.assertIn("frozen at asOfCommit", frozen["record"])

    def test_a_frozen_view_without_a_tree_is_not_a_view(self) -> None:
        with self.assertRaises(ValueError):
            ac.reconcile(
                base_campaign(), copy.deepcopy(ac.BASE_PLAN), as_of="f" * 40
            )

    def test_a_tree_without_a_commit_is_not_a_declared_view(self) -> None:
        with self.assertRaises(ValueError):
            ac.reconcile(
                base_campaign(), copy.deepcopy(ac.BASE_PLAN), tree={"present.json"}
            )

    def test_a_closed_campaign_reports_checks_it_did_not_pass(self) -> None:
        campaign = base_campaign()
        campaign["closure"] = closure(
            [("C1", ac.R_PASS), ("C2", ac.R_FAIL), ("C3", ac.R_PASS)],
            claims_success=False,
        )
        report = ac.reconcile(campaign, copy.deepcopy(ac.BASE_PLAN))
        self.assertEqual(report["notPassed"], ["C2"])
        self.assertFalse(report["narrowed"])


class ReconciliationFreeze(unittest.TestCase):
    """A record is about a commit; a later member must not move it."""

    def _programme(self) -> tuple[dict, dict]:
        campaign = load_real_campaigns()["etp-programme"]
        freeze = json.loads(
            (REPO_ROOT / "evidence/a17/FREEZE-forward.json").read_text(
                encoding="utf-8"
            )
        )
        return campaign, freeze

    def test_the_committed_record_is_unchanged_when_a_later_member_lands(self) -> None:
        reconciliation = json.loads(RECONCILIATION.read_text(encoding="utf-8"))
        as_of = reconciliation["asOfCommit"]
        committed = next(
            record
            for record in reconciliation["records"]
            if record["campaignId"] == "etp-programme"
        )
        self.assertFalse(committed["liveView"])
        self.assertEqual(committed["asOfCommit"], as_of)
        campaign, freeze = self._programme()
        tree = ac.commit_paths(as_of)
        before = RECONCILIATION.read_bytes()

        with tempfile.TemporaryDirectory() as mirror:
            for member in freeze["members"]:
                target = Path(mirror) / member["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("", encoding="utf-8")
            synthetic = Path(mirror) / "evidence/zz/RECEIPT.md"
            synthetic.parent.mkdir(parents=True, exist_ok=True)
            synthetic.write_text("", encoding="utf-8")

            grew = copy.deepcopy(freeze)
            grew["members"].append(
                {
                    "id": "zz-later",
                    "path": "evidence/zz/RECEIPT.md",
                    "phase": "ZZ",
                    "predicate": "test-only synthetic member",
                    # Not required: this control exercises the binding, not a
                    # narrowed plan (which must still be refused).
                    "required": False,
                }
            )
            recomputed = ac.reconcile(
                campaign, freeze, root=mirror, as_of=as_of, tree=tree
            )
            frozen = ac.reconcile(
                campaign, grew, root=mirror, as_of=as_of, tree=tree
            )
            live = ac.reconcile(campaign, grew, root=mirror)

        # The frozen view reproduces the committed record exactly.
        self.assertEqual(recomputed, committed)
        # The later member is absent from the declared tree, so the record says
        # missing -- not produced, and not that the committed record drifted.
        self.assertEqual(frozen["produced"], committed["produced"])
        self.assertEqual(
            frozen["missing"], sorted(committed["missing"] + ["zz-later"])
        )
        # The live view sees the member the working tree now carries.
        self.assertTrue(live["liveView"])
        self.assertIn("zz-later", live["produced"])
        self.assertEqual(RECONCILIATION.read_bytes(), before)

    def test_a_later_commit_tree_reports_members_the_record_does_not(self) -> None:
        reconciliation = json.loads(RECONCILIATION.read_text(encoding="utf-8"))
        as_of = reconciliation["asOfCommit"]
        campaign, freeze = self._programme()
        recorded_tree = ac.commit_paths(as_of)
        later = ac.resolve_commit("HEAD")
        later_tree = ac.commit_paths(later)
        self.assertIn("evidence/b4/RECEIPT.md", later_tree)
        self.assertNotIn("evidence/b4/RECEIPT.md", recorded_tree)
        recorded = ac.reconcile(
            campaign, freeze, as_of=as_of, tree=recorded_tree
        )
        advanced = ac.reconcile(
            campaign, freeze, as_of=later, tree=later_tree
        )
        self.assertNotIn("b4-receipt", recorded["produced"])
        self.assertIn("b4-receipt", advanced["produced"])


class RealCampaigns(unittest.TestCase):
    def test_both_campaigns_are_present_and_validate_to_their_recorded_state(self) -> None:
        campaigns = load_real_campaigns()
        self.assertEqual(
            set(campaigns), {"etp-programme", "a22-adversarial-qualification"}
        )
        for campaign in campaigns.values():
            report = ac.validate(campaign)
            self.assertEqual(report["state"], campaign["state"])

    def test_the_programme_campaign_is_open_and_has_no_terminator(self) -> None:
        campaign = load_real_campaigns()["etp-programme"]
        report = ac.validate(campaign)
        self.assertEqual(report["state"], ac.S_OPEN)
        self.assertEqual(report["code"], ac.AC_OPEN)
        self.assertIsNone(campaign["closure"])
        self.assertIsNone(campaign["abandonment"])
        self.assertGreater(len(campaign["opening"]["plan"]), 80)
        self.assertGreater(len(campaign["amendments"]), 0)
        self.assertFalse(campaign["source"]["reconstructed"])
        self.assertIn("not closed", campaign["note"])

    def test_the_a22_campaign_closed_with_eight_passes(self) -> None:
        campaign = load_real_campaigns()["a22-adversarial-qualification"]
        report = ac.validate(campaign)
        self.assertEqual(report["state"], ac.S_CLOSED_CLEAN)
        self.assertEqual(report["outcomes"]["pass"], 8)
        self.assertEqual(report["outcomes"]["fail"], 0)
        self.assertEqual(report["outcomes"]["skip"], 0)
        self.assertEqual(report["outcomes"]["notRun"], 0)
        self.assertEqual(len(campaign["opening"]["plan"]), 8)
        self.assertTrue(campaign["source"]["reconstructed"])

    def test_the_earlier_defect_and_partial_are_preserved(self) -> None:
        campaign = load_real_campaigns()["a22-adversarial-qualification"]
        history = campaign["closureHistory"][0]
        self.assertFalse(history["summary"]["claimsSuccess"])
        self.assertEqual(history["summary"]["counts"]["fail"], 1)
        self.assertEqual(history["summary"]["counts"]["skip"], 1)
        by_id = {entry["checkId"]: entry for entry in history["outcomes"]}
        self.assertEqual(by_id["E5"]["result"], ac.R_FAIL)
        self.assertEqual(by_id["E6"]["result"], ac.R_SKIP)
        final = {entry["checkId"]: entry for entry in campaign["closure"]["outcomes"]}
        self.assertEqual(final["E5"]["history"][0]["result"], ac.R_FAIL)
        self.assertEqual(final["E6"]["history"][0]["result"], ac.R_SKIP)
        self.assertEqual(final["E5"]["result"], ac.R_PASS)

    def test_neither_real_campaign_invented_an_outcome(self) -> None:
        campaign = load_real_campaigns()["a22-adversarial-qualification"]
        results = json.loads(
            (REPO_ROOT / "evidence/a22/RESULTS.json").read_text(encoding="utf-8")
        )
        expected = {
            experiment["id"]: {
                "QUALIFIED": ac.R_PASS,
                "DEFECT": ac.R_FAIL,
                "PARTIAL": ac.R_SKIP,
                "NOT_RUN": ac.R_NOT_RUN,
            }[experiment["verdict"]]
            for experiment in results["experiments"]
        }
        observed = {
            entry["checkId"]: entry["result"]
            for entry in campaign["closure"]["outcomes"]
        }
        self.assertEqual(observed, expected)


class Determinism(unittest.TestCase):
    def test_the_producer_writes_the_same_bytes_twice(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for directory in (first, second):
                completed = subprocess.run(
                    [sys.executable, str(PRODUCER), "--out", directory],
                    capture_output=True,
                    text=True,
                    check=False,
                    cwd=str(REPO_ROOT),
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            for name in ("CAMPAIGNS.json", "RECONCILIATION.json", "CONTROLS.json"):
                self.assertEqual(
                    (Path(first) / name).read_bytes(),
                    (Path(second) / name).read_bytes(),
                    name,
                )

    def test_the_committed_records_equal_a_fresh_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [sys.executable, str(PRODUCER), "--out", directory],
                capture_output=True,
                text=True,
                check=False,
                cwd=str(REPO_ROOT),
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            for name in ("CAMPAIGNS.json", "RECONCILIATION.json", "CONTROLS.json"):
                self.assertEqual(
                    (Path(directory) / name).read_bytes(),
                    (EVIDENCE / name).read_bytes(),
                    name,
                )

    def test_the_producer_check_mode_accepts_the_committed_bytes(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(PRODUCER), "--check"],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(REPO_ROOT),
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("code=AC_OK", completed.stdout)

    def test_the_recorded_as_of_reproduces_the_committed_bytes(self) -> None:
        reconciliation = json.loads(RECONCILIATION.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PRODUCER),
                    "--out",
                    directory,
                    "--as-of",
                    reconciliation["asOfCommit"],
                ],
                capture_output=True,
                text=True,
                check=False,
                cwd=str(REPO_ROOT),
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(
                (Path(directory) / "RECONCILIATION.json").read_bytes(),
                RECONCILIATION.read_bytes(),
            )

    def test_a_later_as_of_moves_the_temporary_view_not_the_record(self) -> None:
        committed = RECONCILIATION.read_bytes()
        recorded = json.loads(committed)["asOfCommit"]
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PRODUCER),
                    "--out",
                    directory,
                    "--as-of",
                    "HEAD",
                ],
                capture_output=True,
                text=True,
                check=False,
                cwd=str(REPO_ROOT),
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            later = json.loads(
                (Path(directory) / "RECONCILIATION.json").read_text(encoding="utf-8")
            )
        self.assertNotEqual(later["asOfCommit"], recorded)
        programme = next(
            record
            for record in later["records"]
            if record["campaignId"] == "etp-programme"
        )
        self.assertIn("b4-receipt", programme["produced"])
        self.assertEqual(RECONCILIATION.read_bytes(), committed)

    def test_neither_producer_reads_a_clock(self) -> None:
        for path in (PRODUCER, TOOL):
            text = path.read_text(encoding="utf-8")
            for forbidden in ("datetime.now", "utcnow", "time.time", "time.monotonic"):
                self.assertNotIn(forbidden, text, path.name)


class CommandLine(unittest.TestCase):
    def test_status_reports_both_real_campaigns(self) -> None:
        completed = run_tool("status")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("campaign=etp-programme state=OPEN code=AC_OPEN", completed.stdout)
        self.assertIn(
            "campaign=a22-adversarial-qualification state=CLOSED_CLEAN code=AC_CLOSED_CLEAN",
            completed.stdout,
        )

    def test_a_closure_that_omits_a_check_exits_one_with_the_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign_path = Path(directory) / "campaign.json"
            closure_path = Path(directory) / "closure.json"
            campaign_path.write_text(json.dumps(base_campaign()), encoding="utf-8")
            omitting = closure(
                [("C1", ac.R_PASS), ("C2", ac.R_PASS)], claims_success=False
            )
            omitting["summary"]["counts"]["planned"] = 3
            closure_path.write_text(json.dumps(omitting), encoding="utf-8")
            completed = run_tool(
                "close", "--campaign", str(campaign_path), "--closure", str(closure_path)
            )
        self.assertEqual(completed.returncode, 1)
        self.assertIn(f"code={ac.R_OMITTED_CHECK}", completed.stdout)

    def test_a_narrowed_reconciliation_exits_one_with_the_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = base_campaign()
            campaign["opening"]["plan"] = copy.deepcopy(ac.BASE_PLAN[:2])
            campaign["closure"] = closure(
                [("C1", ac.R_PASS), ("C2", ac.R_PASS)], claims_success=True
            )
            campaign_path = Path(directory) / "campaign.json"
            plan_path = Path(directory) / "plan.json"
            campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
            plan_path.write_text(json.dumps(ac.BASE_PLAN), encoding="utf-8")
            completed = run_tool(
                "reconcile",
                "--campaign",
                str(campaign_path),
                "--plan",
                str(plan_path),
                "--root",
                directory,
                "--live",
            )
        self.assertEqual(completed.returncode, 1)
        self.assertIn(f"code={ac.R_PLAN_NARROWED}", completed.stdout)

    def test_a_usage_error_exits_two_with_the_code(self) -> None:
        completed = run_tool("status", "--no-such-flag")
        self.assertEqual(completed.returncode, 2)
        self.assertIn(f"code={ac.AC_USAGE}", completed.stdout)

    def test_live_reconcile_reports_state_live_and_writes_nothing(self) -> None:
        plan = str(REPO_ROOT / "evidence/a17/FREEZE-forward.json")
        campaign = load_real_campaigns()["etp-programme"]
        with tempfile.TemporaryDirectory() as directory:
            campaign_path = Path(directory) / "campaign.json"
            campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
            completed = run_tool(
                "reconcile",
                "--campaign",
                str(campaign_path),
                "--plan",
                plan,
                "--live",
            )
            entries = sorted(path.name for path in Path(directory).iterdir())
            refused = run_tool(
                "reconcile",
                "--campaign",
                str(campaign_path),
                "--plan",
                plan,
                "--live",
                "--out",
                str(Path(directory) / "out.json"),
            )
            wrote = (Path(directory) / "out.json").exists()
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("state=LIVE", completed.stdout)
        self.assertIn("campaignState=OPEN", completed.stdout)
        self.assertIn("view=working-tree", completed.stdout)
        self.assertNotIn("missing=b4-receipt", completed.stdout)
        self.assertEqual(entries, ["campaign.json"])
        self.assertEqual(refused.returncode, 2)
        self.assertIn(f"code={ac.AC_USAGE}", refused.stdout)
        self.assertFalse(wrote)

    def test_a_frozen_reconcile_records_its_commit(self) -> None:
        reconciliation = json.loads(RECONCILIATION.read_text(encoding="utf-8"))
        campaign = load_real_campaigns()["etp-programme"]
        plan = str(REPO_ROOT / "evidence/a17/FREEZE-forward.json")
        with tempfile.TemporaryDirectory() as directory:
            campaign_path = Path(directory) / "campaign.json"
            out_path = Path(directory) / "record.json"
            campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
            completed = run_tool(
                "reconcile",
                "--campaign",
                str(campaign_path),
                "--plan",
                plan,
                "--as-of",
                reconciliation["asOfCommit"],
                "--out",
                str(out_path),
            )
            written = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("view=frozen", completed.stdout)
        self.assertFalse(written["liveView"])
        self.assertEqual(written["asOfCommit"], reconciliation["asOfCommit"])
        self.assertEqual(
            written["produced"],
            next(
                record["produced"]
                for record in reconciliation["records"]
                if record["campaignId"] == "etp-programme"
            ),
        )

    def test_reconcile_without_a_declared_view_is_a_usage_error(self) -> None:
        campaign = load_real_campaigns()["etp-programme"]
        with tempfile.TemporaryDirectory() as directory:
            campaign_path = Path(directory) / "campaign.json"
            campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
            completed = run_tool(
                "reconcile",
                "--campaign",
                str(campaign_path),
                "--plan",
                str(REPO_ROOT / "evidence/a17/FREEZE-forward.json"),
            )
        self.assertEqual(completed.returncode, 2)
        self.assertIn(f"code={ac.AC_USAGE}", completed.stdout)

    def test_open_amend_close_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "plan.json"
            campaign_path = Path(directory) / "campaign.json"
            closure_path = Path(directory) / "closure.json"
            amendment_path = Path(directory) / "amendment.json"
            plan_path.write_text(json.dumps(ac.BASE_PLAN), encoding="utf-8")
            opened = run_tool(
                "open",
                "--out",
                str(campaign_path),
                "--id",
                "test-campaign",
                "--at",
                "2026-01-01T00:00:00Z",
                "--plan",
                str(plan_path),
            )
            self.assertEqual(opened.returncode, 0, opened.stdout + opened.stderr)
            self.assertIn(f"code={ac.AC_OPEN}", opened.stdout)

            amendment_path.write_text(
                json.dumps(amendment(supersedes=["C1"])), encoding="utf-8"
            )
            amended = run_tool(
                "amend",
                "--campaign",
                str(campaign_path),
                "--amendment",
                str(amendment_path),
            )
            self.assertEqual(amended.returncode, 0, amended.stdout + amended.stderr)
            self.assertIn("amendments=1", amended.stdout)

            closure_path.write_text(
                json.dumps(
                    closure(
                        [("C1", ac.R_PASS), ("C2", ac.R_PASS), ("C3", ac.R_PASS)],
                        claims_success=True,
                    )
                ),
                encoding="utf-8",
            )
            closed = run_tool(
                "close", "--campaign", str(campaign_path), "--closure", str(closure_path)
            )
            self.assertEqual(closed.returncode, 1)
            self.assertIn(f"code={ac.R_RETROACTIVE_AMENDMENT}", closed.stdout)


class EvidenceRecords(unittest.TestCase):
    def test_the_records_are_json_and_carry_their_schema(self) -> None:
        campaigns = json.loads(CAMPAIGNS.read_text(encoding="utf-8"))
        controls = json.loads(CONTROLS.read_text(encoding="utf-8"))
        reconciliation = json.loads(RECONCILIATION.read_text(encoding="utf-8"))
        self.assertEqual(campaigns["schema"], ac.CAMPAIGNS_SCHEMA)
        self.assertEqual(controls["schema"], ac.CONTROLS_SCHEMA)
        self.assertEqual(reconciliation["schema"], ac.RECONCILIATION_SCHEMA)
        self.assertIn("asOfCommit", reconciliation)
        self.assertNotIn("asOf", reconciliation)
        self.assertEqual(reconciliation["resolvedFrom"], "git ls-tree -r --name-only")
        self.assertEqual(len(campaigns["campaigns"]), 2)
        self.assertEqual(len(reconciliation["records"]), 2)
        self.assertTrue(controls["coversEveryCode"])

    def test_the_tool_digest_is_the_tool(self) -> None:
        campaigns = json.loads(CAMPAIGNS.read_text(encoding="utf-8"))
        self.assertEqual(campaigns["tool"]["sha256"], ac.sha256_file(TOOL))

    def test_each_campaign_reconciles_against_its_independent_plan(self) -> None:
        reconciliation = json.loads(RECONCILIATION.read_text(encoding="utf-8"))
        by_id = {
            record["campaignId"]: record for record in reconciliation["records"]
        }
        programme = by_id["etp-programme"]
        self.assertFalse(programme["narrowed"])
        self.assertEqual(programme["omitted"], [])
        self.assertFalse(programme["liveView"])
        self.assertEqual(programme["asOfCommit"], reconciliation["asOfCommit"])
        self.assertEqual(
            len(programme["produced"]) + len(programme["missing"]), 20
        )
        self.assertEqual(programme["campaignState"], ac.S_OPEN)
        a22 = by_id["a22-adversarial-qualification"]
        self.assertFalse(a22["narrowed"])
        self.assertFalse(a22["liveView"])
        self.assertEqual(a22["omitted"], [])
        self.assertEqual(a22["missing"], [])
        self.assertEqual(len(a22["produced"]), 8)

    def test_no_real_reconciliation_is_narrowed(self) -> None:
        reconciliation = json.loads(RECONCILIATION.read_text(encoding="utf-8"))
        for record in reconciliation["records"]:
            self.assertFalse(record["narrowed"], record["campaignId"])
            self.assertEqual(record["omitted"], [], record["campaignId"])


class Documentation(unittest.TestCase):
    def test_the_document_names_every_refusal_code_exactly_once_in_the_table(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        for code in ac.REFUSALS:
            self.assertIn(f"| `{code}` |", text, code)

    def test_the_document_does_not_name_a_code_the_tool_does_not_emit(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        documented = set(re.findall(r"AC_REFUSED_[A-Z_]+", text))
        self.assertEqual(documented, set(ac.REFUSALS))

    def test_the_document_names_the_state_and_outcome_vocabulary(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        for value in ac.STATES:
            self.assertIn(value, text)
        for value in ac.RESULTS:
            self.assertIn(value, text)

    def test_the_document_states_the_omission_rule_and_the_non_claims(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8").lower()
        self.assertIn("may be recorded", text)
        self.assertIn("may not be omitted", text)
        self.assertIn("not a success claim", text)
        self.assertIn("an abandonment is not a closure", text)

    def test_the_document_has_a_not_run_section(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^#+ `?NOT_RUN`?")

    def test_the_document_names_both_campaigns_and_their_states(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        self.assertIn("etp-programme", text)
        self.assertIn("a22-adversarial-qualification", text)
        self.assertIn("CLOSED_CLEAN", text)
        self.assertIn("OPEN", text)

    def test_the_document_names_the_prefix_disjointness(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        self.assertIn("CA_", text)
        self.assertIn("AC_", text)


if __name__ == "__main__":
    unittest.main()
