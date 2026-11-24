#!/usr/bin/env python3
"""Controls for baseline disposition.

Each control exercises one rule of `docs/BASELINE-DISPOSITION.md`: a baseline is
a finding population at a recorded identity; a delta must say why a member is
absent; only a COMPLETE later population, an unchanged recorded tool, an absent
identity, no exclusion or suppression, and a later recorded candidate together
license `RESOLVED`; and every weaker reason has its own stable code.

A control mutates a baseline in memory. It is not a source change and not a defect
report: a control that fires proves the refusal works, not that the substituted
form occurs anywhere in the tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import baseline as bl  # noqa: E402

A7 = REPO_ROOT / "evidence" / "a7"
BASELINES = A7 / "BASELINES.json"
DELTA = A7 / "DELTA.json"
CONTROLS = A7 / "CONTROLS.json"
PRODUCER = A7 / "build_evidence.py"
DOCUMENT = REPO_ROOT / "docs" / "BASELINE-DISPOSITION.md"
TOOL = TOOLS / "baseline.py"

REQUIRED_CODES = {
    "BL_REFUSED_ABSENCE_AS_RESOLUTION",
    "BL_REFUSED_POPULATION_SHRINK",
    "BL_REFUSED_TOOL_CHANGE",
    "BL_REFUSED_EXCLUSION_AS_RESOLUTION",
    "BL_REFUSED_SUPPRESSION_AS_RESOLUTION",
    "BL_REFUSED_PARTIAL_SCAN",
    "BL_REFUSED_MOVED_AS_RESOLVED",
    "BL_REFUSED_CANDIDATE_UNRECORDED",
    "BL_REFUSED_AGGREGATE_AS_MEMBERS",
    "BL_REFUSED_NO_BASELINE",
    "BL_REFUSED_IDENTITY_UNSTABLE",
}

REQUIRED_DISPOSITIONS = {
    "STILL_PRESENT",
    "RESOLVED",
    "MOVED",
    "NEW",
    "SUPPRESSED_ABSENT",
    "EXCLUDED_ABSENT",
    "UNSCANNED_ABSENT",
    "TOOL_CHANGED_ABSENT",
    "POPULATION_SHRUNK_ABSENT",
    "UNKNOWN",
}


def _fingerprint(tag: str) -> str:
    return hashlib.sha256(tag.encode("utf-8")).hexdigest()


def member(tag: str) -> bl.Member:
    return bl.Member(
        logical=_fingerprint(tag + ":logical"),
        exact=_fingerprint(tag + ":exact"),
        rule=_fingerprint(tag + ":rule"),
        label=tag,
    )


def moved(member_value: bl.Member, tag: str) -> bl.Member:
    return bl.Member(
        logical=member_value.logical,
        exact=_fingerprint(tag + ":exact"),
        rule=member_value.rule,
        label=tag,
    )


CANDIDATE_A = bl.Candidate(commit="a" * 40, recorded=True)
CANDIDATE_B = bl.Candidate(commit="b" * 40, recorded=True)
CANDIDATE_MISSING = bl.Candidate(recorded=False)
TOOL_A = bl.ToolIdentity(path="control/tool", digest="1" * 64, recorded=True)
TOOL_B = bl.ToolIdentity(path="control/tool", digest="2" * 64, recorded=True)


def scope(expected: int | None, completeness: str = bl.S_COMPLETE) -> bl.Scope:
    return bl.Scope(
        id="control-scope",
        expected=expected,
        examined=expected,
        completeness=completeness,
        basis="in-memory control scope",
        locator="/controls",
    )


def baseline(
    baseline_id: str,
    members: tuple[bl.Member, ...],
    *,
    candidate: bl.Candidate = CANDIDATE_A,
    tool: bl.ToolIdentity = TOOL_A,
    control_scope: bl.Scope | None = None,
    aggregate: bool = False,
    member_count: int | None = None,
) -> bl.Baseline:
    return bl.Baseline(
        id=baseline_id,
        candidate=candidate,
        tool=tool,
        scope=control_scope or scope(len(members) if not aggregate else 0),
        members=members,
        aggregate=aggregate,
        member_count=member_count,
        suppressions=(),
        taken_at="2026-11-24",
        record=bl.RecordRef(path="control", locator="/controls"),
        note="in-memory control",
    )


def run_delta(
    before_members: tuple[bl.Member, ...],
    after_members: tuple[bl.Member, ...],
    *,
    before_expected: int | None = None,
    after_expected: int | None = None,
    before_candidate: bl.Candidate = CANDIDATE_A,
    after_candidate: bl.Candidate = CANDIDATE_B,
    before_tool: bl.ToolIdentity = TOOL_A,
    after_tool: bl.ToolIdentity = TOOL_A,
    after_completeness: str = bl.S_COMPLETE,
    exclusions: tuple[bl.Exclusion, ...] = (),
    suppressions: tuple[bl.SuppressionDisposition, ...] = (),
) -> bl.DeltaResult:
    return bl.delta(
        baseline(
            "control-before",
            before_members,
            candidate=before_candidate,
            tool=before_tool,
            control_scope=scope(
                before_expected if before_expected is not None else len(before_members)
            ),
        ),
        baseline(
            "control-after",
            after_members,
            candidate=after_candidate,
            tool=after_tool,
            control_scope=scope(
                after_expected if after_expected is not None else len(after_members),
                after_completeness,
            ),
        ),
        exclusions=exclusions,
        suppressions=suppressions,
        delta_id="control",
    )


def disposition_for(result: bl.DeltaResult, member_value: bl.Member) -> str:
    for record in result.records:
        if record.exact == member_value.exact:
            return record.disposition
    raise AssertionError(f"no disposition for {member_value.exact}")


class RealEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baselines, cls.not_baselines = bl.build_baselines(REPO_ROOT)
        cls.by_id = {item.id: item for item in cls.baselines}
        cls.deltas, cls.no_baseline = bl.build_deltas(cls.baselines, REPO_ROOT)
        cls.delta_by_id = {item.id: item for item in cls.deltas}

    def test_the_registry_reads_every_expected_code(self) -> None:
        self.assertEqual(set(bl.REFUSALS), REQUIRED_CODES)
        self.assertEqual(set(bl.DISPOSITIONS), REQUIRED_DISPOSITIONS)

    def test_every_baseline_states_a_candidate_and_a_scope(self) -> None:
        for item in self.baselines:
            self.assertTrue(
                item.candidate.recorded or item.candidate.mixed or item.candidate.note,
                item.id,
            )
            self.assertIn(item.scope.completeness, bl.COMPLETENESS_STATES)
            self.assertTrue(item.record.path.endswith(".json"))
            self.assertTrue(item.record.locator)

    def test_a1_records_six_per_run_candidates_and_is_not_relabelled(self) -> None:
        a1 = self.by_id["a1-sarif-results"]
        self.assertTrue(a1.candidate.mixed)
        self.assertEqual(len(a1.candidate.per_run), 6)
        self.assertIsNone(a1.candidate.token())

    def test_the_claims_delta_preserves_every_logical_claim(self) -> None:
        result = self.delta_by_id["claims-reconciliation"]
        self.assertEqual(result.counts()[bl.D_STILL_PRESENT], 31)
        self.assertEqual(result.counts()[bl.D_MOVED], 4)
        self.assertEqual(result.counts()[bl.D_RESOLVED], 0)
        self.assertIn(bl.R_ABSENCE_AS_RESOLUTION, result.codes)
        self.assertIn(bl.R_MOVED_AS_RESOLVED, result.codes)
        self.assertIn(bl.R_TOOL_CHANGE, result.codes)

    def test_the_closure_delta_moves_eleven_obligations_and_resolves_none(self) -> None:
        result = self.delta_by_id["closure-ssh-b50-status"]
        self.assertEqual(result.counts()[bl.D_STILL_PRESENT], 301)
        self.assertEqual(result.counts()[bl.D_MOVED], 11)
        self.assertEqual(result.counts()[bl.D_RESOLVED], 0)

    def test_the_haz15_delta_does_not_call_the_repair_resolved(self) -> None:
        result = self.delta_by_id["haz15-padding-observation"]
        self.assertEqual(result.counts()[bl.D_UNSCANNED_ABSENT], 2)
        self.assertEqual(result.counts()[bl.D_NEW], 2)
        self.assertEqual(result.counts()[bl.D_RESOLVED], 0)
        self.assertIn(bl.R_PARTIAL_SCAN, result.codes)
        self.assertIn(bl.R_TOOL_CHANGE, result.codes)

    def test_the_fingerprint_migration_changes_the_tool_and_loses_nothing(self) -> None:
        result = self.delta_by_id["a3-fingerprint-migration"]
        self.assertEqual(result.counts()[bl.D_STILL_PRESENT], 4245)
        self.assertEqual(result.counts()[bl.D_RESOLVED], 0)
        self.assertEqual(result.codes, ())
        self.assertTrue(result.admitted)

    def test_no_real_delta_reaches_resolved(self) -> None:
        for result in self.deltas:
            self.assertEqual(result.counts()[bl.D_RESOLVED], 0, result.id)

    def test_every_before_member_appears_in_its_delta(self) -> None:
        for result in self.deltas:
            before = self.by_id[result.before]
            expected = Counter(
                item.exact for item in before.members if item.exact is not None
            )
            observed = Counter(
                record.exact
                for record in result.records
                if record.exact is not None and record.exact in expected
            )
            self.assertEqual(expected, observed, result.id)

    def test_every_area_without_a_second_population_is_named(self) -> None:
        self.assertEqual(len(self.no_baseline), 7)
        for item in self.no_baseline:
            self.assertEqual(item["code"], bl.R_NO_BASELINE)


class RefusalCodeTests(unittest.TestCase):
    """One control per refusal code."""

    def test_the_controls_cover_every_code_once(self) -> None:
        baselines, _ = bl.build_baselines(REPO_ROOT)
        outcomes = bl.build_controls(baselines)
        self.assertEqual({item["code"] for item in outcomes}, REQUIRED_CODES)
        self.assertEqual(len(outcomes), len(REQUIRED_CODES))

    def test_absence_as_resolution(self) -> None:
        a, b, c = member("a"), member("b"), member("c")
        result = run_delta(
            (a, b),
            (b, c),
            before_candidate=CANDIDATE_A,
            after_candidate=CANDIDATE_A,
        )
        self.assertEqual(disposition_for(result, a), bl.D_UNKNOWN)
        self.assertIn(bl.R_ABSENCE_AS_RESOLUTION, result.codes)
        self.assertNotIn(bl.D_RESOLVED, {r.disposition for r in result.records})

    def test_population_shrink(self) -> None:
        a, b = member("a"), member("b")
        result = run_delta((a, b), (b,), before_expected=2, after_expected=1)
        self.assertEqual(disposition_for(result, a), bl.D_POPULATION_SHRUNK_ABSENT)
        self.assertIn(bl.R_POPULATION_SHRINK, result.codes)

    def test_tool_change(self) -> None:
        a, b, c = member("a"), member("b"), member("c")
        result = run_delta((a, b), (b, c), after_tool=TOOL_B)
        self.assertEqual(disposition_for(result, a), bl.D_TOOL_CHANGED_ABSENT)
        self.assertIn(bl.R_TOOL_CHANGE, result.codes)

    def test_exclusion_as_resolution(self) -> None:
        a, b, c = member("a"), member("b"), member("c")
        result = run_delta(
            (a, b),
            (b, c),
            exclusions=(bl.Exclusion(id="ex", covers=a.exact),),
        )
        self.assertEqual(disposition_for(result, a), bl.D_EXCLUDED_ABSENT)
        self.assertIn(bl.R_EXCLUSION_AS_RESOLUTION, result.codes)

    def test_suppression_as_resolution(self) -> None:
        a, b, c = member("a"), member("b"), member("c")
        result = run_delta(
            (a, b),
            (b, c),
            suppressions=(
                bl.SuppressionDisposition(
                    id="sup", covers=a.exact, disposition="ACTIVE", actionable=True
                ),
            ),
        )
        self.assertEqual(disposition_for(result, a), bl.D_SUPPRESSED_ABSENT)
        self.assertIn(bl.R_SUPPRESSION_AS_RESOLUTION, result.codes)

    def test_partial_scan(self) -> None:
        a, b, c = member("a"), member("b"), member("c")
        result = run_delta(
            (a, b), (b, c), after_completeness=bl.S_TRUNCATED_BOUNDED
        )
        self.assertEqual(disposition_for(result, a), bl.D_UNSCANNED_ABSENT)
        self.assertIn(bl.R_PARTIAL_SCAN, result.codes)

    def test_moved_as_resolved(self) -> None:
        a, b = member("a"), moved(member("a"), "a-moved")
        result = run_delta((a,), (b,))
        self.assertEqual(disposition_for(result, a), bl.D_MOVED)
        self.assertIn(bl.R_MOVED_AS_RESOLVED, result.codes)

    def test_candidate_unrecorded(self) -> None:
        a, b, c = member("a"), member("b"), member("c")
        result = run_delta((a, b), (b, c), after_candidate=CANDIDATE_MISSING)
        self.assertEqual(disposition_for(result, a), bl.D_UNKNOWN)
        self.assertIn(bl.R_CANDIDATE_UNRECORDED, result.codes)

    def test_aggregate_as_members(self) -> None:
        aggregate = baseline(
            "aggregate",
            (),
            candidate=CANDIDATE_B,
            aggregate=True,
            member_count=1,
            control_scope=scope(1),
        )
        with self.assertRaises(bl.Refusal) as raised:
            bl.delta(
                baseline("before", (member("a"),), control_scope=scope(1)),
                aggregate,
            )
        self.assertEqual(raised.exception.code, bl.R_AGGREGATE_AS_MEMBERS)

    def test_no_baseline(self) -> None:
        with self.assertRaises(bl.Refusal) as raised:
            bl.delta(
                baseline("before", (member("a"),), control_scope=scope(1)), None
            )
        self.assertEqual(raised.exception.code, bl.R_NO_BASELINE)

    def test_identity_unstable(self) -> None:
        unstable = bl.Member(logical=None, exact=None, label="unstable")
        result = run_delta((unstable,), ())
        self.assertEqual(result.records[0].disposition, bl.D_UNKNOWN)
        self.assertIn(bl.R_IDENTITY_UNSTABLE, result.codes)


class DispositionTests(unittest.TestCase):
    """One control per disposition."""

    def test_still_present(self) -> None:
        a = member("a")
        result = run_delta((a,), (a,))
        self.assertEqual(disposition_for(result, a), bl.D_STILL_PRESENT)

    def test_resolved(self) -> None:
        a, b, c = member("a"), member("b"), member("c")
        result = run_delta((a, b), (b, c))
        self.assertEqual(disposition_for(result, a), bl.D_RESOLVED)
        self.assertEqual(disposition_for(result, c), bl.D_NEW)
        self.assertEqual(result.codes, ())
        self.assertTrue(result.admitted)

    def test_moved(self) -> None:
        a, b = member("a"), moved(member("a"), "a-moved")
        result = run_delta((a,), (b,))
        self.assertEqual(disposition_for(result, a), bl.D_MOVED)

    def test_new(self) -> None:
        a, b = member("a"), member("b")
        result = run_delta((a,), (a, b))
        self.assertEqual(disposition_for(result, b), bl.D_NEW)

    def test_suppressed_absent(self) -> None:
        a, b, c = member("a"), member("b"), member("c")
        result = run_delta(
            (a, b),
            (b, c),
            suppressions=(
                bl.SuppressionDisposition(
                    id="sup", covers=a.logical, disposition="ACTIVE"
                ),
            ),
        )
        self.assertEqual(disposition_for(result, a), bl.D_SUPPRESSED_ABSENT)

    def test_excluded_absent(self) -> None:
        a, b, c = member("a"), member("b"), member("c")
        result = run_delta(
            (a, b),
            (b, c),
            exclusions=(bl.Exclusion(id="ex", covers=a.logical),),
        )
        self.assertEqual(disposition_for(result, a), bl.D_EXCLUDED_ABSENT)

    def test_unscanned_absent(self) -> None:
        a, b, c = member("a"), member("b"), member("c")
        result = run_delta((a, b), (b, c), after_completeness=bl.S_SAMPLED)
        self.assertEqual(disposition_for(result, a), bl.D_UNSCANNED_ABSENT)

    def test_tool_changed_absent(self) -> None:
        a, b, c = member("a"), member("b"), member("c")
        result = run_delta((a, b), (b, c), after_tool=TOOL_B)
        self.assertEqual(disposition_for(result, a), bl.D_TOOL_CHANGED_ABSENT)

    def test_population_shrunk_absent(self) -> None:
        a, b = member("a"), member("b")
        result = run_delta((a, b), (b,), before_expected=2, after_expected=1)
        self.assertEqual(disposition_for(result, a), bl.D_POPULATION_SHRUNK_ABSENT)

    def test_unknown(self) -> None:
        a, b, c = member("a"), member("b"), member("c")
        result = run_delta((a, b), (b, c), after_candidate=CANDIDATE_MISSING)
        self.assertEqual(disposition_for(result, a), bl.D_UNKNOWN)


class FiveConditionTests(unittest.TestCase):
    """The RESOLVED rule, with each condition individually violated."""

    def setUp(self) -> None:
        self.a, self.b, self.c = member("a"), member("b"), member("c")

    def test_the_positive_path_reaches_resolved(self) -> None:
        result = run_delta((self.a, self.b), (self.b, self.c))
        self.assertEqual(disposition_for(result, self.a), bl.D_RESOLVED)
        self.assertTrue(result.admitted)

    def test_condition_a_later_population_must_be_complete(self) -> None:
        for state in (
            bl.S_SAMPLED,
            bl.S_TRUNCATED_BOUNDED,
            bl.S_UNKNOWN,
            bl.S_AGGREGATE_ONLY,
            bl.S_DEFERRED,
            bl.S_ABSENT,
        ):
            with self.subTest(state=state):
                result = run_delta(
                    (self.a, self.b), (self.b, self.c), after_completeness=state
                )
                self.assertNotEqual(disposition_for(result, self.a), bl.D_RESOLVED)
                self.assertIn(bl.R_PARTIAL_SCAN, result.codes)

    def test_condition_b_tool_identity_must_be_unchanged_and_recorded(self) -> None:
        result = run_delta((self.a, self.b), (self.b, self.c), after_tool=TOOL_B)
        self.assertEqual(disposition_for(result, self.a), bl.D_TOOL_CHANGED_ABSENT)
        unrecorded = bl.ToolIdentity(path="control/tool", digest=None, recorded=False)
        result = run_delta(
            (self.a, self.b), (self.b, self.c), after_tool=unrecorded
        )
        self.assertEqual(disposition_for(result, self.a), bl.D_TOOL_CHANGED_ABSENT)

    def test_condition_c_identity_must_be_absent(self) -> None:
        result = run_delta((self.a, self.b), (self.a, self.b))
        self.assertEqual(disposition_for(result, self.a), bl.D_STILL_PRESENT)
        self.assertNotEqual(disposition_for(result, self.a), bl.D_RESOLVED)

    def test_condition_d_no_exclusion_or_suppression(self) -> None:
        excluded = run_delta(
            (self.a, self.b),
            (self.b, self.c),
            exclusions=(bl.Exclusion(id="ex", covers=self.a.exact),),
        )
        self.assertEqual(disposition_for(excluded, self.a), bl.D_EXCLUDED_ABSENT)
        suppressed = run_delta(
            (self.a, self.b),
            (self.b, self.c),
            suppressions=(
                bl.SuppressionDisposition(
                    id="sup", covers=self.a.exact, disposition="ACTIVE"
                ),
            ),
        )
        self.assertEqual(disposition_for(suppressed, self.a), bl.D_SUPPRESSED_ABSENT)

    def test_condition_e_candidate_must_be_recorded_and_later(self) -> None:
        unrecorded = run_delta(
            (self.a, self.b),
            (self.b, self.c),
            after_candidate=CANDIDATE_MISSING,
        )
        self.assertEqual(disposition_for(unrecorded, self.a), bl.D_UNKNOWN)
        self.assertIn(bl.R_CANDIDATE_UNRECORDED, unrecorded.codes)

        same = run_delta(
            (self.a, self.b),
            (self.b, self.c),
            before_candidate=CANDIDATE_A,
            after_candidate=CANDIDATE_A,
        )
        self.assertEqual(disposition_for(same, self.a), bl.D_UNKNOWN)
        self.assertIn(bl.R_ABSENCE_AS_RESOLUTION, same.codes)

    def test_a_population_shrink_is_not_a_resolution(self) -> None:
        result = run_delta(
            (self.a, self.b), (self.b,), before_expected=2, after_expected=1
        )
        self.assertEqual(disposition_for(result, self.a), bl.D_POPULATION_SHRUNK_ABSENT)
        self.assertIn(bl.R_POPULATION_SHRINK, result.codes)

    def test_a_moved_identity_is_not_a_resolution(self) -> None:
        result = run_delta((self.a,), (moved(self.a, "a-moved"),))
        self.assertEqual(disposition_for(result, self.a), bl.D_MOVED)
        self.assertIn(bl.R_MOVED_AS_RESOLVED, result.codes)


class AdmitTests(unittest.TestCase):
    def test_a_clean_delta_is_admitted(self) -> None:
        a, b, c = member("a"), member("b"), member("c")
        report = bl.admit(run_delta((a, b), (b, c)))
        self.assertTrue(report["admitted"])
        self.assertEqual(report["problems"], [])

    def test_a_resolved_record_with_a_code_is_refused(self) -> None:
        record = bl.DispositionRecord(
            identity="f" * 64,
            logical="e" * 64,
            exact="f" * 64,
            label="bad",
            disposition=bl.D_RESOLVED,
            reason="bad",
            codes=(bl.R_PARTIAL_SCAN,),
        )
        result = bl.DeltaResult(
            id="bad",
            before="before",
            after="after",
            records=(record,),
            codes=(),
            admitted=True,
        )
        report = bl.admit(result)
        self.assertFalse(report["admitted"])
        self.assertTrue(report["problems"])

    def test_a_weaker_disposition_without_a_code_is_refused(self) -> None:
        record = bl.DispositionRecord(
            identity="f" * 64,
            logical="e" * 64,
            exact="f" * 64,
            label="bad",
            disposition=bl.D_MOVED,
            reason="bad",
        )
        result = bl.DeltaResult(
            id="bad",
            before="before",
            after="after",
            records=(record,),
            codes=(),
            admitted=True,
        )
        report = bl.admit(result)
        self.assertFalse(report["admitted"])
        self.assertTrue(report["problems"])


def _recorded_identity() -> dict:
    return json.loads(BASELINES.read_text(encoding="utf-8"))["sourceIdentity"]


class ProducerTests(unittest.TestCase):
    def test_the_producer_is_deterministic(self) -> None:
        commit = _recorded_identity()["commit"]
        with tempfile.TemporaryDirectory() as first:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PRODUCER),
                    "--out",
                    first,
                    "--source-commit",
                    commit,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            first_bytes = {
                name: (Path(first) / name).read_bytes()
                for name in ("BASELINES.json", "DELTA.json", "CONTROLS.json")
            }
        with tempfile.TemporaryDirectory() as second:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PRODUCER),
                    "--out",
                    second,
                    "--source-commit",
                    commit,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            for name, value in first_bytes.items():
                self.assertEqual(value, (Path(second) / name).read_bytes(), name)

    def test_the_committed_records_match_a_fresh_build(self) -> None:
        # The verifier supplies the identity the record states. It must not be the
        # live HEAD, or a record carried by commit E could never be reproduced at E.
        commit = _recorded_identity()["commit"]
        with tempfile.TemporaryDirectory() as out:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PRODUCER),
                    "--out",
                    out,
                    "--source-commit",
                    commit,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            for name in ("BASELINES.json", "DELTA.json", "CONTROLS.json"):
                self.assertEqual(
                    (Path(out) / name).read_bytes(),
                    (A7 / name).read_bytes(),
                    name,
                )


class InputIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.identity = _recorded_identity()
        cls.inputs = cls.identity["inputs"]

    def test_the_identity_names_the_commit_and_every_input_digest(self) -> None:
        self.assertNotIn("branch", self.identity)
        self.assertTrue(self.inputs)
        for item in self.inputs:
            self.assertEqual(
                hashlib.sha256((REPO_ROOT / item["path"]).read_bytes()).hexdigest(),
                item["sha256"],
                item["path"],
            )
        # The population is read from records; the inventory must name them.
        self.assertTrue(
            any(item["path"].endswith("SARIF.json") for item in self.inputs)
        )

    def test_the_commit_token_is_the_argument_not_the_checkout(self) -> None:
        # Recording HEAD here would make the record irreproducible at the commit
        # that carries it; the identity is a function of its explicit argument.
        observed = bl.source_identity(
            REPO_ROOT,
            commit=self.identity["commit"],
            inputs={item["path"]: item["sha256"] for item in self.inputs},
        )
        self.assertEqual(observed, self.identity)

    def test_a_changed_input_stops_the_rebuild_with_a_named_code(self) -> None:
        changed = "evidence/a5/ADMISSION.json"
        self.assertIn(changed, {item["path"] for item in self.inputs})
        with tempfile.TemporaryDirectory() as root:
            mirror = Path(root)
            for item in self.inputs:
                destination = mirror / item["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((REPO_ROOT / item["path"]).read_bytes())
            record = mirror / "evidence" / "a7" / "BASELINES.json"
            record.parent.mkdir(parents=True, exist_ok=True)
            record.write_bytes(BASELINES.read_bytes())
            target = mirror / changed
            target.write_bytes(target.read_bytes() + b"\n")
            with tempfile.TemporaryDirectory() as out:
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(PRODUCER),
                        "--repo-root",
                        str(mirror),
                        "--out",
                        out,
                        "--source-commit",
                        self.identity["commit"],
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
        self.assertEqual(
            completed.returncode, 2, completed.stdout + completed.stderr
        )
        self.assertIn(bl.R_INPUT_DIGEST_MISMATCH, completed.stderr)
        self.assertIn(changed, completed.stderr)

    def test_the_verifier_refuses_a_stale_digest(self) -> None:
        recorded = [{"path": "evidence/x.json", "sha256": "a" * 64}]
        with self.assertRaises(bl.Refusal) as caught:
            bl.verify_input_digests(recorded, {"evidence/x.json": "b" * 64})
        self.assertEqual(caught.exception.code, bl.R_INPUT_DIGEST_MISMATCH)
        self.assertIn("recorded", str(caught.exception))

    def test_a_record_without_an_inventory_is_bootstrapped_not_verified(self) -> None:
        # The first run establishes the inventory; every later run verifies it.
        bl.verify_input_digests([], {"evidence/x.json": "b" * 64})


class CommandLineTests(unittest.TestCase):
    def test_delta_exits_one_and_prints_every_code(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(TOOL), "delta"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        for delta_id in (
            "a3-fingerprint-migration",
            "claims-reconciliation",
            "closure-ssh-b50-status",
            "haz15-padding-observation",
        ):
            self.assertIn(delta_id, completed.stdout)
        for code in (
            bl.R_ABSENCE_AS_RESOLUTION,
            bl.R_MOVED_AS_RESOLVED,
            bl.R_PARTIAL_SCAN,
            bl.R_TOOL_CHANGE,
        ):
            self.assertIn(code, completed.stdout)

    def test_admit_exit_codes_and_printed_codes(self) -> None:
        admitted = subprocess.run(
            [sys.executable, str(TOOL), "admit", "a3-fingerprint-migration"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(admitted.returncode, 0)
        self.assertIn("admitted=yes", admitted.stdout)
        self.assertIn("codes=none", admitted.stdout)

        refused = subprocess.run(
            [sys.executable, str(TOOL), "admit", "claims-reconciliation"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(refused.returncode, 1)
        self.assertIn("admitted=no", refused.stdout)
        self.assertIn(bl.R_MOVED_AS_RESOLVED, refused.stdout)

        unknown = subprocess.run(
            [sys.executable, str(TOOL), "admit", "no-such-delta"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(unknown.returncode, 2)
        self.assertIn(bl.R_NO_BASELINE, unknown.stderr)

    def test_explain_exit_codes(self) -> None:
        baselines, _ = bl.build_baselines(REPO_ROOT)
        claims = next(item for item in baselines if item.id == "etp-claims-after")
        identity = claims.members[0].exact
        found = subprocess.run(
            [sys.executable, str(TOOL), "explain", identity],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(found.returncode, 0)
        self.assertIn("claims-reconciliation", found.stdout)
        missing = subprocess.run(
            [sys.executable, str(TOOL), "explain", "0" * 64],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(missing.returncode, 2)
        self.assertIn(bl.R_NO_BASELINE, missing.stderr)


class DocumentSynchronisationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8")

    def test_every_refusal_code_is_in_the_document(self) -> None:
        for code in REQUIRED_CODES:
            self.assertIn(code, self.text)

    def test_every_disposition_is_in_the_document(self) -> None:
        for disposition in REQUIRED_DISPOSITIONS:
            self.assertIn(disposition, self.text)

    def test_the_document_names_the_implementation_and_controls(self) -> None:
        for name in (
            "forensics/tools/baseline.py",
            "forensics/tools/tests/test_baseline.py",
            "evidence/a7/BASELINES.json",
            "evidence/a7/DELTA.json",
            "evidence/a7/CONTROLS.json",
            "evidence/a7/build_evidence.py",
        ):
            self.assertIn(name, self.text)

    def test_the_document_names_every_control(self) -> None:
        controls = json.loads(CONTROLS.read_text(encoding="utf-8"))
        for control in controls["controls"]:
            self.assertIn(control["id"], self.text)


if __name__ == "__main__":
    unittest.main()
