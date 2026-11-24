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
* ``--json`` reproduces the same deterministic record across two runs over the
  same checkout, while the live ``environment`` readings it observed are
  declared and recorded rather than compared.

Most controls drive the dispatcher with an injected executor, so they test the
decision logic without running a delegate.  The end-to-end controls run the real
command line in a throwaway tree whose delegates are stubs, so the exit contract,
the selection, the serialisation and the determinism control are exercised for
real.

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


def memory_only_step() -> verify.Step:
    """A step whose only prerequisite is the AGENTS.md section 6.1 memory floor."""
    return verify.Step(
        name="memory-probe", title="probe the build floor", required=False,
        needs=("memory:24",), tools=(), identity=(), reads_gitignored=(),
        commands=(), pass_reason="the floor is met", establishes="nothing",
        does_not="anything")


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

    def test_every_declared_private_root_is_audited(self) -> None:
        # D4: a step's declared private read must be inside the set presence
        # reporting audits, or `private_state_present` can never name it.
        audited = set(verify.audited_private_roots(REPO))
        table = verify.steps_for(REPO)
        for step in table.values():
            for path in step.reads_gitignored:
                self.assertIn(path, audited,
                              f"{step.name} declares {path}, which presence reporting "
                              "does not audit")
        # `artifacts/phase2/install` is Git-tracked checkout content, so declaring it
        # private was the defect, not a missing audit root.
        for name in ("consumer-curl", "consumer-ssh", "consumer-sshd"):
            self.assertNotIn("artifacts/phase2/install", table[name].reads_gitignored)
        tracked = verify._tracked_files(REPO, "artifacts/phase2/install")
        self.assertTrue(tracked, "artifacts/phase2/install is expected to be Git-tracked")

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

    def test_normalisation_removes_an_echoed_memory_reading(self) -> None:
        # build_reproducibility.sh echoes the live reading; the environment block is
        # the declared place for it, so it is not compared as a delegate's output.
        ctx = make_context(REPO)
        self.assertEqual(verify.normalise("MemAvailable: 32527932 kB", ctx),
                         "MemAvailable <observed>")
        self.assertEqual(verify.normalise("MemAvailable 11 GiB is below the floor", ctx),
                         "MemAvailable <observed> is below the floor")

    def test_tmp_token_is_substituted_inside_an_argument(self) -> None:
        # A literal `{tmp}` made the delegate write into the checkout, so run 2 read a
        # different untracked count from run 1: the run changed its own input.
        ctx = make_context(REPO)
        executor = FakeExecutor(verify.ExecResult(exit=0))
        step = verify.Step(
            name="tmp-probe", title="probe the temp substitution", required=False,
            needs=("python",), tools=(), identity=(), reads_gitignored=(),
            commands=(verify.Command(argv=("{python}", "-c", "pass",
                                           "--out", "{tmp}/probe")),),
            pass_reason="", establishes="nothing", does_not="anything")
        record = verify.run_step(step, ctx, execute=executor)
        self.assertEqual(executor.requests[0].argv[-1], f"{ctx.tmpdir}/probe")
        self.assertEqual(record["checks"][0]["argv"][-1], "<tmp>/probe")


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
        ok, message = verify.compare_deterministic(first, second)
        self.assertTrue(ok, message)
        # The live readings are still recorded, outside the compared projection.
        environment = json.loads(first)[verify.ENVIRONMENT_KEY]
        self.assertEqual(environment["declared"], "environment-input")
        self.assertIsInstance(environment["mem_available_bytes"], int)
        self.assertIn("court", environment)

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

    def test_list_is_a_real_subcommand(self) -> None:
        # D1: the help text, the refusal message and the surface all name `list`, so
        # the executable must accept it.  It is the flag form's equivalent.
        code, listing = self.fixture.run("list", expect=0)
        _, flag = self.fixture.run("--list", expect=0)
        self.assertEqual(listing, flag)
        names = {line.split("\t")[0] for line in listing.splitlines() if "\t" in line}
        for name in verify.QUEUE_STEPS:
            self.assertIn(name, names)

    def test_a_bare_invocation_is_still_refused(self) -> None:
        code, output = self.fixture.run(expect=2)
        self.assertIn("no subcommand", output)

    def test_list_json_emits_the_listing_document(self) -> None:
        # D2: a flag the listing accepts must not be ignored.
        code, output = self.fixture.run("--list", "--json", expect=0)
        document = json.loads(output)
        self.assertEqual(document["schema"], verify.LISTING_SCHEMA)
        self.assertEqual(sorted(document), ["commands", "interface", "schema"])
        self.assertEqual(len(document["commands"]),
                         len(verify.known_steps(self.fixture.root)))
        commands = {row["name"]: row for row in document["commands"]}
        self.assertTrue(commands["manifest"]["in_all"])
        self.assertFalse(commands["authority"]["in_all"])
        _, subcommand = self.fixture.run("list", "--json", expect=0)
        self.assertEqual(output, subcommand)

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


class MemoryFloorControls(unittest.TestCase):
    """The AGENTS.md section 6.1 floor: the decision is recorded, the reading is an input."""

    def test_environment_records_availability_floor_and_cap(self) -> None:
        for gib, floor_met in ((10, False), (23, False), (24, True), (31, True)):
            with self.subTest(available_gib=gib):
                with mock.patch.object(verify, "_mem_available_bytes",
                                       return_value=gib * 1024 ** 3):
                    environment = make_context(REPO).environment
                self.assertEqual(environment["declared"], "environment-input")
                self.assertEqual(environment["mem_available_bytes"], gib * 1024 ** 3)
                self.assertEqual(environment["floor_gib"], 24)
                self.assertEqual(environment["floor_met"], floor_met)
                self.assertTrue(environment["court"])
                if floor_met:
                    self.assertEqual(environment["court_mem_cap_gib"], 8.0)
                    self.assertIn("min(8 GiB", environment["court_cap_source"])
                else:
                    self.assertIsNone(environment["court_mem_cap_gib"])
                    self.assertIn("not derived", environment["court_cap_source"])

    def test_memory_prerequisite_text_does_not_carry_the_reading(self) -> None:
        # The A4 observation: two runs below the floor differed only in the rounded
        # "MemAvailable N GiB" text.  The step's own record must be a function of the
        # decision, so the same decision over different readings records the same text.
        records = []
        for gib in (10, 11):
            with mock.patch.object(verify, "_mem_available_bytes",
                                   return_value=gib * 1024 ** 3):
                ctx = make_context(REPO)
            record = verify.run_step(memory_only_step(), ctx, execute=FakeExecutor())
            self.assertEqual(ctx.environment["mem_available_bytes"], gib * 1024 ** 3)
            self.assertFalse(ctx.environment["floor_met"])
            records.append(json.dumps(record, indent=2, sort_keys=True))
        self.assertEqual(records[0], records[1])
        self.assertEqual(json.loads(records[0])["status"], "NOT_RUN")
        self.assertNotIn("10 GiB", records[0])
        self.assertNotIn("11 GiB", records[0])
        self.assertIn("environment", records[0])

    def test_met_floor_text_names_the_environment_not_a_reading(self) -> None:
        with mock.patch.object(verify, "_mem_available_bytes",
                               return_value=31 * 1024 ** 3):
            ctx = make_context(REPO)
        ok, detail = verify.check_need("memory:24", ctx)
        self.assertTrue(ok)
        self.assertIn("24 GiB floor", detail)
        self.assertNotIn("31 GiB", detail)

    def test_unreadable_meminfo_is_not_run(self) -> None:
        with mock.patch.object(verify, "_mem_available_bytes", return_value=None):
            ctx = make_context(REPO)
        ok, detail = verify.check_need("memory:24", ctx)
        self.assertFalse(ok)
        self.assertIn("could not be read", detail)
        self.assertIsNone(ctx.environment["court_mem_cap_gib"])


class DeterminismControls(unittest.TestCase):
    """What the determinism control compares, requires, and still catches."""

    def setUp(self) -> None:
        self.fixture = Fixture()
        _, first = self.fixture.run("all", "--json", expect=None)
        _, second = self.fixture.run("all", "--json", expect=None)
        self.first, self.second = first, second

    def tearDown(self) -> None:
        self.fixture.close()

    def _inject(self, mutate) -> str:
        document = json.loads(self.first)
        mutate(document)
        return json.dumps(document, indent=2, sort_keys=True)

    def _assert_fires(self, mutate, *expected: str) -> str:
        ok, message = verify.compare_deterministic(self.first, self._inject(mutate))
        self.assertFalse(ok, message)
        self.assertIn(verify.DETERMINISM_CODE, message)
        for fragment in expected:
            self.assertIn(fragment, message)
        return message

    def test_two_runs_agree_on_the_deterministic_record(self) -> None:
        ok, message = verify.compare_deterministic(self.first, self.second)
        self.assertTrue(ok, message)
        self.assertIn("identical", message)

    def test_environment_block_is_declared_and_populated(self) -> None:
        document = json.loads(self.first)
        environment = document[verify.ENVIRONMENT_KEY]
        self.assertEqual(environment["declared"], "environment-input")
        for field in ("mem_available_bytes", "mem_available_gib", "floor_met",
                      "court_mem_cap_gib", "court_cap_source", "court"):
            self.assertIn(field, environment, field)
        self.assertNotIn(verify.ENVIRONMENT_KEY, verify.deterministic_projection(document))

    def test_a_different_availability_does_not_break_the_claim(self) -> None:
        # The reading is an input, so two runs that observed different availability
        # must still agree on the deterministic record.
        document = json.loads(self.first)
        environment = document[verify.ENVIRONMENT_KEY]
        moved = environment["mem_available_bytes"] + 1024 ** 4
        environment["mem_available_bytes"] = moved
        environment["mem_available_gib"] = round(moved / 1024 ** 3, 2)
        environment["court_mem_cap_gib"] = 2.0
        ok, message = verify.compare_deterministic(
            self.first, json.dumps(document, indent=2, sort_keys=True))
        self.assertTrue(ok, message)

    def test_control_fires_on_a_live_reading_in_the_projection(self) -> None:
        def inject(document: dict) -> None:
            step = next(entry for entry in document["steps"] if entry["prerequisites"])
            step["prerequisites"].append({"requirement": "memory:24", "available": True,
                                          "detail": "MemAvailable 11 GiB"})
        message = self._assert_fires(inject, "prerequisites")
        self.assertIn("differs at", message)

    def test_control_fires_on_a_changed_digest(self) -> None:
        def inject(document: dict) -> None:
            document["steps"][0]["tool_digest"][0]["sha256"] = "0" * 64
        self._assert_fires(inject, "tool_digest")

    def test_control_fires_on_a_changed_ordering(self) -> None:
        def reorder_steps(document: dict) -> None:
            document["steps"].reverse()
        self._assert_fires(reorder_steps, "steps[0].")

        def reorder_selection(document: dict) -> None:
            document["invocation"]["steps"].reverse()
        self._assert_fires(reorder_selection, "invocation.steps[0]")

    def test_control_fires_on_a_changed_member_set(self) -> None:
        def inject(document: dict) -> None:
            document["steps"].pop()
        self._assert_fires(inject, "steps[len")

    def test_control_fires_on_a_changed_step_outcome(self) -> None:
        def inject(document: dict) -> None:
            document["steps"][0]["status"] = "FAIL"
        self._assert_fires(inject, "steps[0].status")

    def test_undeclared_environment_fires(self) -> None:
        def inject(document: dict) -> None:
            del document[verify.ENVIRONMENT_KEY]
        ok, message = verify.compare_deterministic(self.first, self._inject(inject))
        self.assertFalse(ok)
        self.assertIn(verify.DETERMINISM_CODE, message)
        self.assertIn("declares no", message)

    def test_private_state_block_is_declared_and_populated(self) -> None:
        document = json.loads(self.first)
        block = document[verify.PRIVATE_STATE_KEY]
        self.assertEqual(block["declared"], verify.PRIVATE_STATE_DECLARATION)
        self.assertTrue(block["known_roots"], "the audit names no root")
        self.assertIsInstance(block["present"], list)
        self.assertNotIn(verify.PRIVATE_STATE_KEY, verify.deterministic_projection(document))

    def test_a_different_private_state_does_not_break_the_claim(self) -> None:
        # D5: the entry counts are a live reading, declared as an input, so a run
        # that observed a different population must still agree on the record.
        document = json.loads(self.first)
        block = document[verify.PRIVATE_STATE_KEY]
        block["present"] = ["court"]
        for entry in block["known_roots"].values():
            entry["private_entries"] = entry.get("private_entries", 0) + 7
        ok, message = verify.compare_deterministic(
            self.first, json.dumps(document, indent=2, sort_keys=True))
        self.assertTrue(ok, message)

    def test_absent_private_state_fires(self) -> None:
        def inject(document: dict) -> None:
            del document[verify.PRIVATE_STATE_KEY]
        self._assert_fires(inject, "declares no")

    def test_undeclared_private_state_fires(self) -> None:
        def inject(document: dict) -> None:
            document[verify.PRIVATE_STATE_KEY]["declared"] = "environment-input"
        self._assert_fires(inject, "private-state input")

    def test_an_unpopulated_private_state_is_refused(self) -> None:
        def inject(document: dict) -> None:
            document[verify.PRIVATE_STATE_KEY]["known_roots"] = {}
        self._assert_fires(inject, "no audited roots")

    def test_a_floor_decision_without_a_reading_is_refused(self) -> None:
        def inject(document: dict) -> None:
            environment = document[verify.ENVIRONMENT_KEY]
            environment["mem_available_bytes"] = None
            environment["floor_met"] = True
        ok, message = verify.compare_deterministic(self.first, self._inject(inject))
        self.assertFalse(ok)
        self.assertIn("rests on no", message)

    def test_a_run_that_emits_no_document_is_refused(self) -> None:
        ok, message = verify.compare_deterministic(self.first, "not one document")
        self.assertFalse(ok)
        self.assertIn(verify.DETERMINISM_CODE, message)

    def test_text_output_records_the_environment(self) -> None:
        document = verify.run(["manifest"], make_context(self.fixture.root))
        text = verify.render_text(document)
        self.assertIn("environment", text)
        self.assertIn("MemAvailable", text)
        self.assertIn("not compared", text)


if __name__ == "__main__":
    unittest.main()
