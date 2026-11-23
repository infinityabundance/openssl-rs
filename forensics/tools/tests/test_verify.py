#!/usr/bin/env python3
"""Controls for the ETP-T12 public verification interface.

The interface makes claims that need controls of their own:

* a missing tool is ``NOT_RUN`` and named, never skipped or passed;
* a non-zero exit is ``FAIL``, never ``PASS``;
* a resource bound is ``BLOCKED``, and a timeout is a resource bound;
* a step that needs the network is refused offline with that reason;
* an absent or drifted receipt is ``FAIL``, not a silent pass;
* a declared private path is reported when it is present, so a verdict taken
  with private state is visible rather than silently satisfied;
* ``all`` exits non-zero and names every non-passing step;
* ``--json`` is byte-identical across two runs over the same checkout.

Most controls drive the dispatcher with an injected executor, so they test the
decision logic without running a delegate.  Four controls run the real command
line in a throwaway tree whose delegates are stubs, so the exit contract, the
selection and the serialisation are exercised end to end.

Run inside the court:

    python3 forensics/tools/tests/test_verify.py
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import verify  # noqa: E402

REPO = TOOLS.parents[1]


def make_context(root: Path, *, network: bool = False, tmpdir: str | None = None) -> verify.Context:
    return verify.build_context(root, network, tmpdir or tempfile.mkdtemp())


class FakeExecutor:
    """An executor that returns scripted results and records the requests."""

    def __init__(self, *results, default=None):
        self.results = list(results)
        self.default = default or verify.ExecResult(exit=0, stdout="ok\n")
        self.requests: list[verify.ExecRequest] = []

    def __call__(self, request: verify.ExecRequest) -> verify.ExecResult:
        self.requests.append(request)
        return self.results.pop(0) if self.results else self.default


class Fixture:
    """A throwaway checkout with one stub per delegate the interface names."""

    def __init__(self, *, failing: str | None = None):
        self.root = Path(tempfile.mkdtemp(prefix="verify-fixture-"))
        (self.root / "forensics" / "tools").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(TOOLS / "verify.py", self.root / "forensics" / "tools" / "verify.py")
        (self.root / "forensics" / "tools" / "verify.py").chmod(0o755)
        self.failing = failing
        table = verify.steps_for(self.root)
        for step in table.values():
            for tool in step.tools:
                target = self.root / tool
                if tool == "forensics/tools/tests":
                    target.mkdir(parents=True, exist_ok=True)
                    (target / "test_stub.py").write_text(
                        "import unittest\n"
                        "class Stub(unittest.TestCase):\n"
                        "    def test_ok(self):\n"
                        "        self.assertTrue(True)\n",
                        encoding="utf-8")
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if tool.endswith(".sh"):
                    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                    target.chmod(0o755)
                    continue
                code = 1 if tool == f"forensics/tools/{self.failing}.py" else 0
                target.write_text(self._stub(tool, code), encoding="utf-8")
                target.chmod(0o755)
        self._write_t10_record()

    def _stub(self, tool: str, code: int) -> str:
        payload = {"status": "PASS"}
        if "closure_discipline" in tool:
            payload = {"consumer": "stub", "exclusion_rows": 2,
                       "exclusions_failing": 0,
                       "inventory_availability": {"available": True, "path": "court/x"}}
        return (
            "import json\n"
            f"print(json.dumps({payload!r}))\n"
            f"raise SystemExit({code})\n"
        )

    def _write_t10_record(self) -> None:
        receipts = {}
        for family, receipt in verify.CONSUMER_FAMILIES.items():
            path = self.root / receipt
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n", encoding="utf-8")
            receipts[family] = {
                "receipt": receipt,
                "receipt_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        record = self.root / verify.T10_RECORD
        record.parent.mkdir(parents=True, exist_ok=True)
        record.write_text(json.dumps({"consumers": receipts}), encoding="utf-8")

    def run(self, *args: str, expect: int | None = None) -> tuple[int, str]:
        proc = subprocess.run(
            [sys.executable, str(self.root / "forensics" / "tools" / "verify.py"), *args],
            cwd=str(self.root), capture_output=True, text=True, timeout=300,
        )
        if expect is not None:
            assert proc.returncode == expect, (
                f"expected exit {expect}, got {proc.returncode}\n"
                f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        return proc.returncode, proc.stdout + proc.stderr

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


class StepDecisionControls(unittest.TestCase):
    def test_queue_subcommands_are_all_declared(self) -> None:
        table = verify.steps_for(REPO)
        for name in verify.QUEUE_STEPS:
            self.assertIn(name, table, f"queue subcommand {name} is missing")
        for name in table:
            step = table[name]
            self.assertTrue(step.establishes, f"{name} states no establishment")
            self.assertTrue(step.does_not, f"{name} states no non-claim")
            self.assertTrue(step.needs, f"{name} names no prerequisite")

    def test_every_delegate_exists_in_the_repository(self) -> None:
        for step in verify.steps_for(REPO).values():
            for tool in step.tools:
                self.assertTrue((REPO / tool).exists(), f"{step.name}: {tool} is absent")

    def test_exit_zero_is_pass_and_non_zero_is_fail(self) -> None:
        ctx = make_context(REPO)
        step = verify.STEPS["claims"]
        passed = verify.run_step(step, ctx, execute=FakeExecutor(verify.ExecResult(exit=0)))
        failed = verify.run_step(step, ctx, execute=FakeExecutor(
            verify.ExecResult(exit=1, stderr="REFUSED: XYZ\n")))
        self.assertEqual(passed["status"], "PASS")
        self.assertEqual(failed["status"], "FAIL")
        self.assertIn("REFUSED", failed["reason"])

    def test_missing_tool_is_not_run_and_named(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="verify-missing-"))
        try:
            ctx = make_context(root)
            record = verify.run_step(verify.STEPS["claims"], ctx,
                                     execute=FakeExecutor(verify.ExecResult(exit=0)))
            self.assertEqual(record["status"], "NOT_RUN")
            self.assertIn("forensics/tools/etp_claims.py", record["reason"])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_missing_external_tool_is_not_run(self) -> None:
        with mock.patch.object(verify.shutil, "which", return_value=None):
            ctx = make_context(REPO)
            record = verify.run_step(verify.STEPS["manifest"], ctx,
                                     execute=FakeExecutor(verify.ExecResult(exit=0)))
        self.assertEqual(record["status"], "NOT_RUN")
        self.assertIn("git", record["reason"])

    def test_timeout_is_blocked(self) -> None:
        ctx = make_context(REPO)
        record = verify.run_step(
            verify.STEPS["claims"], ctx,
            execute=FakeExecutor(verify.ExecResult(exit=None, timed_out=True)))
        self.assertEqual(record["status"], "BLOCKED")
        self.assertIn("timed out", record["reason"])

    def test_network_step_is_refused_offline(self) -> None:
        ctx = make_context(REPO, network=False)
        record = verify.run_step(verify.STEPS["authority"], ctx,
                                 execute=FakeExecutor(verify.ExecResult(exit=0)))
        self.assertEqual(record["status"], "NOT_RUN")
        self.assertIn("network", record["reason"])
        self.assertIn("--network", record["reason"])

    def test_network_step_runs_when_declared(self) -> None:
        ctx = make_context(REPO, network=True)
        record = verify.run_step(verify.STEPS["authority"], ctx,
                                 execute=FakeExecutor(verify.ExecResult(exit=0)))
        self.assertEqual(record["status"], "PASS")

    def test_absent_receipt_is_fail_not_not_run(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="verify-receipt-"))
        try:
            tool = root / "forensics" / "tools" / "closure_discipline.py"
            tool.parent.mkdir(parents=True, exist_ok=True)
            tool.write_text("")
            ctx = make_context(root)
            record = verify.run_step(verify.consumer_step("curl", "evidence/x.json"), ctx,
                                     execute=FakeExecutor(verify.ExecResult(exit=0)))
            self.assertEqual(record["status"], "FAIL")
            self.assertIn(verify.T10_RECORD, record["reason"])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_private_state_is_reported(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="verify-private-"))
        try:
            (root / "court" / "tmp").mkdir(parents=True)
            (root / "court" / "tmp" / "scratch.bin").write_text("x")
            ctx = make_context(root)
            self.assertIn("court", ctx.private_present)
            record = verify.run_step(verify.STEPS["instruments"], ctx,
                                     execute=FakeExecutor(verify.ExecResult(exit=0)))
            self.assertIn("court", record["private_state_present"])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_normalisation_removes_volatile_text(self) -> None:
        ctx = make_context(REPO)
        text = verify.normalise(f"{ctx.root}/x ran in 12.5s under {ctx.tmpdir}", ctx)
        self.assertNotIn(str(REPO), text)
        self.assertNotIn("12.5s", text)


class EndToEndControls(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_all_propagates_a_non_pass_and_names_every_step(self) -> None:
        failing = Fixture(failing="etp_claims")
        try:
            code, output = failing.run("all", "--json", expect=1)
            document = json.loads(output)
            self.assertEqual(document["status"], "FAIL")
            self.assertIn("claims", document["non_passing"])
            statuses = {step["name"]: step["status"] for step in document["steps"]}
            self.assertEqual(statuses["claims"], "FAIL")
            self.assertIn("claims", output)
        finally:
            failing.close()

    def test_all_is_green_when_every_runnable_step_passes(self) -> None:
        # The build and authority steps depend on the venue; the stable steps are
        # run through the module API so the fixture asserts the aggregate gate.
        names = ["manifest", "proofs", "instruments", "controls", "receipts",
                 "claims", "closure", "scheduling", "traceability", "hazards",
                 "binary", "docs", "consumer-curl"]
        ctx = make_context(self.fixture.root)
        document = verify.run(names, ctx)
        statuses = {step["name"]: step["status"] for step in document["steps"]}
        self.assertEqual(statuses, {name: "PASS" for name in names})
        self.assertEqual(document["status"], "PASS")
        self.assertEqual(document["non_passing"], [])

    def test_json_is_byte_identical_across_two_runs(self) -> None:
        _, first = self.fixture.run("all", "--json", expect=None)
        _, second = self.fixture.run("all", "--json", expect=None)
        self.assertEqual(first, second)

    def test_single_optional_step_cannot_exit_zero_while_not_pass(self) -> None:
        code, output = self.fixture.run("authority", "--json")
        document = json.loads(output)
        self.assertEqual(document["steps"][0]["status"], "NOT_RUN")
        self.assertNotEqual(code, 0)

    def test_unknown_subcommand_is_a_usage_refusal(self) -> None:
        code, output = self.fixture.run("nonsense")
        self.assertEqual(code, 2)
        self.assertIn("unknown subcommand", output)

    def test_list_names_the_queue_subcommands(self) -> None:
        code, output = self.fixture.run("--list", expect=0)
        names = {line.split("\t")[0] for line in output.splitlines() if "\t" in line}
        for name in verify.QUEUE_STEPS:
            self.assertIn(name, names)
        code, explanation = self.fixture.run("--explain", "authority", expect=0)
        self.assertIn("needs the network", explanation)

    def test_missing_tool_is_not_run_end_to_end(self) -> None:
        (self.fixture.root / "forensics" / "tools" / "freshness.py").unlink()
        code, output = self.fixture.run("freshness", "--json", expect=1)
        document = json.loads(output)
        self.assertEqual(document["steps"][0]["status"], "NOT_RUN")
        self.assertIn("forensics/tools/freshness.py", document["steps"][0]["reason"])

    def test_drifted_receipt_is_fail_end_to_end(self) -> None:
        receipt = self.fixture.root / verify.CONSUMER_FAMILIES["curl"]
        receipt.write_text('{"drifted": true}\n', encoding="utf-8")
        code, output = self.fixture.run("consumer-curl", "--json", expect=1)
        document = json.loads(output)
        step = document["steps"][0]
        self.assertEqual(step["status"], "FAIL")
        self.assertIn("digest", step["reason"])


if __name__ == "__main__":
    unittest.main()
