#!/usr/bin/env python3
"""Controls for the A27 vertical slice.

One control per refusal code, the digest chain in both directions, the skipped
stage, every stage after the stop, the real stop at A12, the policy
counterfactual, determinism, the command line and the document synchronisation.

The tests read the committed records; they do not modify any record. Where a test
needs a mutant trace, it mutates a deep copy in memory or writes to a temporary
directory.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import vertical_slice as vs  # noqa: E402

A27 = REPO_ROOT / "evidence/a27"
DOC = REPO_ROOT / "docs/VERTICAL-SLICE.md"
ALL_CODES = set(vs.REFUSAL_CODES) | set(vs.INVOCATION_CODES) | set(vs.STOP_CODES)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _by_stage(trace: list[dict], stage: str) -> dict:
    for entry in trace:
        if entry["stage"] == stage:
            return entry
    raise AssertionError(f"no stage {stage}")


def _run_cli(argv: list[str]) -> tuple[int, str]:
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = vs.main(argv)
    except SystemExit as exc:  # the parser raises SystemExit(2) on a usage error
        code = int(exc.code or 0)
    return code, buffer.getvalue()


class VerticalSliceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.slice = vs.build_slice(REPO_ROOT)
        cls.trace = cls.slice["trace"]
        cls.controls = vs.build_controls(REPO_ROOT)
        cls.stops = vs.build_stops(cls.slice)
        cls.artefact = cls.slice["artefact"]

    # ------------------------------------------------------------------
    # The declaration and the trace shape
    # ------------------------------------------------------------------

    def test_the_chain_declares_seventeen_stages_in_order(self) -> None:
        self.assertEqual(
            vs.STAGE_ORDER,
            ("A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A12",
             "A14", "A15", "A16", "A18", "A19", "A17", "A20", "A21"),
        )
        self.assertEqual(len(vs.CHAIN), 17)

    def test_no_stage_is_omitted(self) -> None:
        self.assertEqual([entry["stage"] for entry in self.trace], list(vs.STAGE_ORDER))
        self.assertEqual(len({entry["stage"] for entry in self.trace}), 17)

    def test_run_returns_the_trace(self) -> None:
        self.assertEqual(vs.run(), self.trace)

    def test_each_stage_declares_the_tool_and_what_it_consumes(self) -> None:
        for entry in vs.CHAIN:
            self.assertTrue(entry["tool"].startswith("forensics/tools/"))
            self.assertTrue(entry["reads"])
            self.assertIn("consumes", entry)
            self.assertIn("produces", entry)
            self.assertIn("contract", entry)

    def test_the_binding_digest_is_the_first_input(self) -> None:
        self.assertEqual(self.trace[0]["inputDigest"], self.artefact["bindingDigest"])

    def test_a_stage_before_the_stop_has_an_output_and_a_later_stage_does_not(self) -> None:
        for entry in self.trace:
            if entry["status"] == vs.STATUS_NOT_REACHED:
                self.assertIsNone(entry["outputDigest"])
            else:
                self.assertRegex(entry["outputDigest"], vs.HEX64)

    # ------------------------------------------------------------------
    # The digest chain, in both directions
    # ------------------------------------------------------------------

    def test_digest_chain_links_every_consecutive_pair_forward(self) -> None:
        for left, right in zip(self.trace, self.trace[1:]):
            if right["status"] == vs.STATUS_NOT_REACHED:
                continue
            self.assertEqual(
                left["outputDigest"], right["inputDigest"],
                f"{left['stage']} output is not {right['stage']} input",
            )

    def test_digest_chain_links_every_consecutive_pair_backward(self) -> None:
        for right, left in zip(self.trace[1:], self.trace):
            if right["status"] == vs.STATUS_NOT_REACHED:
                continue
            self.assertEqual(
                right["inputDigest"], left["outputDigest"],
                f"{right['stage']} input is not {left['stage']} output",
            )

    def test_digest_chain_is_not_coincidental(self) -> None:
        produced = [
            entry["outputDigest"] for entry in self.trace
            if entry["outputDigest"] is not None
        ]
        self.assertEqual(len(produced), len(set(produced)))
        consumed = [
            entry["inputDigest"] for entry in self.trace
            if entry["status"] != vs.STATUS_NOT_REACHED
        ]
        # Every consumed digest after the first was produced by the previous stage.
        for index in range(1, len(consumed)):
            self.assertEqual(consumed[index], produced[index - 1])

    def test_a_broken_output_digest_is_detected(self) -> None:
        trace = copy.deepcopy(self.trace)
        _by_stage(trace, "A5")["outputDigest"] = "f" * 64
        self.assertEqual(vs.validate_trace(trace, root=REPO_ROOT), [vs.VS_REFUSED_TRACE_BROKEN])

    def test_a_broken_input_digest_is_detected(self) -> None:
        trace = copy.deepcopy(self.trace)
        _by_stage(trace, "A5")["inputDigest"] = "f" * 64
        self.assertEqual(vs.validate_trace(trace, root=REPO_ROOT), [vs.VS_REFUSED_TRACE_BROKEN])

    # ------------------------------------------------------------------
    # Skipping, omission and stages after the stop
    # ------------------------------------------------------------------

    def test_a_skipped_stage_is_detected(self) -> None:
        trace = [entry for entry in copy.deepcopy(self.trace) if entry["stage"] != "A5"]
        self.assertEqual(vs.validate_trace(trace, root=REPO_ROOT), [vs.VS_REFUSED_STAGE_SKIPPED])

    def test_a_stage_after_the_stop_is_never_reached(self) -> None:
        stop_index = next(
            index for index, entry in enumerate(self.trace)
            if entry["status"] == vs.STATUS_STOP
        )
        for entry in self.trace[stop_index + 1:]:
            self.assertEqual(entry["status"], vs.STATUS_NOT_REACHED)
            self.assertEqual(entry["detail"]["after"], "A12")
            self.assertEqual(
                entry["detail"]["afterCode"], vs.VS_STOP_NO_INDEPENDENT_VERIFICATION
            )

    def test_every_stage_after_the_stop_has_a_reason(self) -> None:
        after = [entry for entry in self.trace if entry["status"] == vs.STATUS_NOT_REACHED]
        self.assertEqual(len(after), 8)
        for entry in after:
            self.assertTrue(entry["detail"]["reason"])
            self.assertIn("A12", entry["detail"]["reason"])

    def test_a_reached_stage_after_a_stop_breaks_the_trace(self) -> None:
        trace = copy.deepcopy(self.trace)
        _by_stage(trace, "A14")["status"] = vs.STATUS_PASS
        _by_stage(trace, "A14")["outputDigest"] = "a" * 64
        self.assertEqual(vs.validate_trace(trace, root=REPO_ROOT), [vs.VS_REFUSED_TRACE_BROKEN])

    # ------------------------------------------------------------------
    # The real stop
    # ------------------------------------------------------------------

    def test_the_real_trace_stops_at_a12_with_self_issued(self) -> None:
        stop = vs.first_stop(self.trace)
        self.assertIsNotNone(stop)
        assert stop is not None
        self.assertEqual(stop["stage"], "A12")
        self.assertEqual(stop["code"], vs.VS_STOP_NO_INDEPENDENT_VERIFICATION)
        self.assertEqual(stop["outcome"], "SELF_ISSUED")
        self.assertEqual(stop["establishedBy"]["observed"]["independentlyVerifiedEnvelopes"], 0)
        self.assertFalse(stop["establishedBy"]["observed"]["independentlyVerified"])

    def test_the_stop_is_bound_to_its_record(self) -> None:
        self.assertEqual(vs.check_stop_binding(REPO_ROOT, self.trace), [])
        stop = vs.first_stop(self.trace)
        assert stop is not None
        record = stop["establishedBy"]["record"]
        self.assertEqual(stop["establishedBy"]["sha256"], _sha(REPO_ROOT / record))

    def test_a_stop_with_no_record_is_refused(self) -> None:
        trace = copy.deepcopy(self.trace)
        _by_stage(trace, "A12")["detail"].pop("establishedBy", None)
        self.assertEqual(
            vs.validate_trace(trace, root=REPO_ROOT), [vs.VS_REFUSED_STOP_NOT_RECORDED]
        )

    def test_the_stop_record_digest_must_match_the_file(self) -> None:
        trace = copy.deepcopy(self.trace)
        _by_stage(trace, "A12")["detail"]["establishedBy"]["sha256"] = "0" * 64
        self.assertEqual(
            vs.check_stop_binding(REPO_ROOT, trace), [vs.VS_REFUSED_STOP_NOT_RECORDED]
        )

    # ------------------------------------------------------------------
    # The policy counterfactual
    # ------------------------------------------------------------------

    def test_the_policy_would_deny(self) -> None:
        policy = self.slice["wouldBe"]["policy"]
        self.assertEqual(policy["decision"], "DENY")
        self.assertEqual(policy["default"], "deny")
        self.assertFalse(policy["evaluatedByThisSlice"])

    def test_the_policy_names_the_same_source_records(self) -> None:
        policy = self.slice["wouldBe"]["policy"]
        self.assertTrue(policy["sourceRecordsMatchCurrentTree"])
        self.assertEqual(policy["sourceRecordsMismatched"], [])
        self.assertEqual(policy["attestation"]["recordSha256"], _sha(
            REPO_ROOT / "evidence/a12/VERIFICATION.json"
        ))

    def test_the_policy_attestation_is_unmet_at_zero(self) -> None:
        attestation = self.slice["wouldBe"]["policy"]["attestation"]
        self.assertEqual(attestation["state"], "UNMET")
        self.assertEqual(attestation["observed"]["count"], 0)
        self.assertIn("A12.independent-attestation", self.slice["wouldBe"]["policy"]["unmet"])

    def test_the_slice_does_not_claim_a_release_pass(self) -> None:
        self.assertEqual(self.slice["counts"]["stopped"], 1)
        self.assertEqual(self.slice["counts"]["passed"], 8)
        self.assertEqual(self.slice["counts"]["refused"], 0)
        self.assertEqual(self.slice["counts"]["notReached"], 8)
        self.assertTrue(self.slice["nonClaims"])

    # ------------------------------------------------------------------
    # Controls: one per refusal code
    # ------------------------------------------------------------------

    def test_every_refusal_code_has_a_firing_control(self) -> None:
        self.assertTrue(self.controls["coversEveryCode"])
        self.assertEqual(self.controls["codesMissing"], [])
        self.assertEqual(self.controls["failing"], [])
        self.assertEqual(
            {row["code"] for row in self.controls["controls"]},
            set(vs.REFUSAL_CODES) | set(vs.INVOCATION_CODES),
        )

    def test_each_control_fires_its_own_code(self) -> None:
        for row in self.controls["controls"]:
            with self.subTest(control=row["id"]):
                self.assertTrue(row["controlOnly"])
                self.assertTrue(row["fired"], row)
                self.assertEqual(row["observedCodes"][0], row["code"])
                self.assertEqual(row["expectedCode"], row["code"])

    def test_the_controls_are_named_for_the_required_defect_classes(self) -> None:
        ids = {row["id"] for row in self.controls["controls"]}
        self.assertTrue({
            "trace-broken", "stage-skipped", "output-missing", "stage-overclaim",
            "admit-without-root", "summary-as-evidence", "stop-unrecorded",
            "artefact-unbound", "malformed-invocation",
        }.issubset(ids))

    def test_the_controls_do_not_change_the_committed_records(self) -> None:
        before = {path.name: _sha(path) for path in sorted(A27.glob("*.json"))}
        vs.build_controls(REPO_ROOT)
        after = {path.name: _sha(path) for path in sorted(A27.glob("*.json"))}
        self.assertEqual(before, after)

    def test_the_positive_controls_pass(self) -> None:
        for row in self.controls["positiveControls"]:
            with self.subTest(control=row["id"]):
                self.assertTrue(row["fired"], row)
                self.assertEqual(row["observedCodes"], [])

    # ------------------------------------------------------------------
    # Determinism and the committed bytes
    # ------------------------------------------------------------------

    def test_the_slice_is_deterministic(self) -> None:
        first = vs._serialise(vs.build_slice(REPO_ROOT))
        second = vs._serialise(vs.build_slice(REPO_ROOT))
        self.assertEqual(first, second)

    def test_the_controls_are_deterministic(self) -> None:
        first = vs._serialise(vs.build_controls(REPO_ROOT))
        second = vs._serialise(vs.build_controls(REPO_ROOT))
        self.assertEqual(first, second)

    def test_the_committed_slice_is_the_current_build(self) -> None:
        committed = json.loads((A27 / "SLICE.json").read_text(encoding="utf-8"))
        committed.pop("producedBy", None)
        self.assertEqual(committed, vs.build_slice(REPO_ROOT))

    def test_the_committed_stops_and_controls_are_the_current_build(self) -> None:
        committed_stops = json.loads((A27 / "STOPS.json").read_text(encoding="utf-8"))
        for key in ("producedBy", "sliceSha256"):
            committed_stops.pop(key, None)
        self.assertEqual(committed_stops, vs.build_stops(vs.build_slice(REPO_ROOT)))
        committed_controls = json.loads((A27 / "CONTROLS.json").read_text(encoding="utf-8"))
        for key in ("producedBy", "sliceSha256", "slice"):
            committed_controls.pop(key, None)
        self.assertEqual(committed_controls, vs.build_controls(REPO_ROOT))

    def test_the_stops_file_names_every_not_reached_stage(self) -> None:
        self.assertEqual(self.stops["notReachedCount"], 8)
        self.assertEqual(
            [row["stage"] for row in self.stops["notReached"]],
            ["A14", "A15", "A16", "A18", "A19", "A17", "A20", "A21"],
        )
        for row in self.stops["notReached"]:
            self.assertEqual(row["after"], "A12")
            self.assertTrue(row["reason"])

    def test_the_stop_and_controls_name_the_slice_digest(self) -> None:
        slice_sha = _sha(A27 / "SLICE.json")
        stops = json.loads((A27 / "STOPS.json").read_text(encoding="utf-8"))
        controls = json.loads((A27 / "CONTROLS.json").read_text(encoding="utf-8"))
        self.assertEqual(stops["sliceSha256"], slice_sha)
        self.assertEqual(controls["sliceSha256"], slice_sha)

    def test_the_producer_stamp_is_current(self) -> None:
        slice_document = json.loads((A27 / "SLICE.json").read_text(encoding="utf-8"))
        produced = slice_document["producedBy"]
        self.assertEqual(produced["sha256"], _sha(REPO_ROOT / "evidence/a27/build_evidence.py"))
        self.assertEqual(
            produced["tool"]["sha256"], _sha(REPO_ROOT / "forensics/tools/vertical_slice.py")
        )

    # ------------------------------------------------------------------
    # The source records the trace cites are the current bytes
    # ------------------------------------------------------------------

    def test_every_cited_source_record_is_the_current_file(self) -> None:
        cited = {
            "A3": ["evidence/a1/SARIF.json"],
            "A4": ["evidence/a4/INSTANCES.json"],
            "A5": ["evidence/a5/ADMISSION.json", "evidence/a5/POPULATIONS.json",
                   "evidence/a1/SARIF.json"],
            "A6": ["evidence/a6/SUPPRESSIONS.json"],
            "A7": ["evidence/a7/DELTA.json", "evidence/a7/BASELINES.json"],
            "A8": ["evidence/a8/MANIFEST.json"],
            "A9": ["evidence/a9/STATEMENTS.json"],
            "A10": ["evidence/a10/ENVELOPES.json"],
            "A12": ["evidence/a12/VERIFICATION.json"],
        }
        for stage, records in cited.items():
            detail = _by_stage(self.trace, stage)["detail"]
            recorded = {
                value for key, value in _walk(detail)
                if isinstance(value, str) and len(value) == 64 and re.fullmatch(r"[0-9a-f]{64}", value)
            }
            for record in records:
                with self.subTest(stage=stage, record=record):
                    self.assertIn(_sha(REPO_ROOT / record), recorded)

    def test_the_artefact_identity_is_recomputed_not_copied(self) -> None:
        detail = _by_stage(self.trace, "A3")["detail"]
        self.assertEqual(detail["fingerprints"]["a1Exact/v1"], self.artefact["exact"])
        self.assertEqual(detail["region"], "line=118")
        self.assertTrue(detail["provenance"]["rehashed"])

    # ------------------------------------------------------------------
    # The command line
    # ------------------------------------------------------------------

    def test_run_exits_zero_on_a_recorded_stop(self) -> None:
        code, output = _run_cli(["run"])
        self.assertEqual(code, 0)
        self.assertIn("stage=A12 status=STOP", output)
        self.assertIn("code=VS_STOP_NO_INDEPENDENT_VERIFICATION", output)
        self.assertIn("codes=NONE", output)

    def test_trace_exits_zero_and_prints_every_stage(self) -> None:
        code, output = _run_cli(["trace"])
        self.assertEqual(code, 0)
        for stage in vs.STAGE_ORDER:
            self.assertIn(f"stage={stage} status=", output)
        self.assertIn("codes=NONE", output)

    def test_stop_prints_the_stop_and_every_stage_not_reached(self) -> None:
        code, output = _run_cli(["stop"])
        self.assertEqual(code, 0)
        self.assertIn("stop=A12", output)
        self.assertIn("code=VS_STOP_NO_INDEPENDENT_VERIFICATION", output)
        self.assertIn("outcome=SELF_ISSUED", output)
        for stage in ("A14", "A15", "A16", "A18", "A19", "A17", "A20", "A21"):
            self.assertIn(f"not_reached={stage}", output)

    def test_a_malformed_invocation_exits_two_and_prints_the_code(self) -> None:
        code, output = _run_cli(["no-such-command"])
        self.assertEqual(code, 2)
        self.assertIn(vs.VS_REFUSED_USAGE, output)

    def test_trace_exits_one_on_a_broken_trace(self) -> None:
        broken = copy.deepcopy(self.slice)
        _by_stage(broken["trace"], "A9")["outputDigest"] = None
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SLICE.json"
            path.write_text(json.dumps(broken), encoding="utf-8")
            code, output = _run_cli(["trace", "--slice", str(path)])
        self.assertEqual(code, 1)
        self.assertIn(vs.VS_REFUSED_OUTPUT_MISSING, output)

    def test_trace_exits_one_when_the_slice_file_is_absent(self) -> None:
        code, output = _run_cli(["trace", "--slice", "/nonexistent/SLICE.json"])
        self.assertEqual(code, 1)
        self.assertIn(vs.VS_REFUSED_OUTPUT_MISSING, output)

    def test_run_writes_a_slice_that_reproduces_the_trace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SLICE.json"
            code, _ = _run_cli(["run", "--out", str(path)])
            self.assertEqual(code, 0)
            written = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            [entry["status"] for entry in written["trace"]],
            [entry["status"] for entry in self.trace],
        )

    # ------------------------------------------------------------------
    # Document synchronisation
    # ------------------------------------------------------------------

    def test_the_document_exists_and_is_not_empty(self) -> None:
        self.assertTrue(DOC.exists())
        self.assertGreater(len(DOC.read_text(encoding="utf-8")), 4000)

    def test_the_document_names_every_stage_in_a_table_row(self) -> None:
        rows = re.findall(r"^\| `(A\d+)` \|", DOC.read_text(encoding="utf-8"), re.M)
        self.assertEqual(rows, list(vs.STAGE_ORDER))

    def test_the_document_tabulates_every_code(self) -> None:
        rows = re.findall(r"^\| `(VS_[A-Z0-9_]+)` \|", DOC.read_text(encoding="utf-8"), re.M)
        self.assertEqual(set(rows), ALL_CODES)
        self.assertEqual(len(rows), len(ALL_CODES))

    def test_the_document_names_the_artefact_and_the_stop(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        self.assertIn(self.artefact["id"], text)
        self.assertIn(self.artefact["exact"], text)
        self.assertIn("SELF_ISSUED", text)
        self.assertIn(vs.VS_STOP_NO_INDEPENDENT_VERIFICATION, text)
        self.assertIn("A12", text)

    def test_the_document_states_what_is_not_run(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("NOT_RUN", text)
        self.assertIn("does not establish", text)

    def test_every_enforced_by_names_a_code_or_a_test(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        rows = re.findall(r"^\| `(VS_[A-Z0-9_]+)` \| ([^|]+) \| ([^|]+) \|", text, re.M)
        self.assertEqual(len(rows), len(ALL_CODES))
        for code, _condition, enforced in rows:
            with self.subTest(code=code):
                self.assertTrue(
                    ("VS_" in enforced) or ("test_" in enforced),
                    f"{code} is enforced by {enforced!r}",
                )

    def test_the_document_states_the_digest_rule_and_the_statuses(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        for status in (vs.STATUS_PASS, vs.STATUS_STOP, vs.STATUS_REFUSED, vs.STATUS_NOT_REACHED):
            self.assertIn(status, text)
        self.assertIn("outputDigest", text)
        self.assertIn("inputDigest", text)


def _walk(value):
    """Yield every (key, value) pair in a nested JSON value."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


if __name__ == "__main__":
    unittest.main()
