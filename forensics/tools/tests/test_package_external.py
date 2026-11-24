#!/usr/bin/env python3
"""Controls for forensics/tools/package_external.py and the A24 records.

Every refusal code has a control that constructs the input the verifier must
refuse. The controls also show that the stripped environment really strips, that
a package runs from a temporary directory with no repository read, that two runs
reproduce, that the manifest and the package are tamper-evident, and that the
external status is never reported as verified.

Run directly (`python3 forensics/tools/tests/test_package_external.py`) or with
`python3 -m unittest discover -s forensics/tools/tests`.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import package_external as pe  # noqa: E402

TOOL = TOOLS / "package_external.py"
DOCUMENT = REPO / "docs/EXTERNAL-PACKAGE.md"
EVIDENCE = REPO / "evidence/a24"
PACKAGE = EVIDENCE / "PACKAGE"

MINI_RECORD = b"{}\n"

_MINI_ENTRY = '''import json
import sys
from pathlib import Path

RECORDS = ("SPEC.json", "DIFFERENTIAL.json", "PROPERTIES.json", "CONTROLS.json")


def main() -> int:
    arguments = list(sys.argv[1:])
    if "--records" not in arguments:
        return 2
    out = Path(arguments[arguments.index("--records") + 1])
    out.mkdir(parents=True, exist_ok=True)
    for name in RECORDS:
        (out / name).write_bytes(b"{}\\n")
    print('{"code":"EV_OK"}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

_MINI_ENTRY_RANDOM = _MINI_ENTRY.replace(
    "import json\nimport sys", "import json\nimport os\nimport sys"
).replace(
    '(out / name).write_bytes(b"{}\\n")',
    '(out / name).write_bytes(os.urandom(8).hex().encode() + b"\\n")',
)

_MINI_ENTRY_TAMPERED = _MINI_ENTRY.replace(
    '(out / name).write_bytes(b"{}\\n")',
    '(out / name).write_bytes(b"{\\"tampered\\":true}\\n" if name == "SPEC.json" '
    'else b"{}\\n")',
)

_MINI_ENTRY_OUTSIDE = '''import sys
from pathlib import Path


def main() -> int:
    Path("/etc/hostname").read_bytes()
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

_MINI_ENTRY_FAIL = "import sys\n\nsys.exit(1)\n"

#: The entry point asserts the environment it was given, so a failure to strip
#: is an entry-point failure rather than a silently weaker run.
_MINI_ENTRY_ENVIRONMENT = '''import json
import sys
from pathlib import Path

RECORDS = ("SPEC.json", "DIFFERENTIAL.json", "PROPERTIES.json", "CONTROLS.json")


def main() -> int:
    environment = __import__("os").environ
    entries = environment.get("PATH", "").split(":")
    if len(entries) != 1:
        print("PATH has %d entries" % len(entries))
        return 1
    if environment.get("A24_POISON") is not None:
        print("A24_POISON survived")
        return 1
    if environment.get("PYTHON" + "PATH") is not None:
        print("the interpreter search variable survived")
        return 1
    if any("poison" in entry for entry in sys.path):
        print("a poisoned path entry survived")
        return 1
    arguments = list(sys.argv[1:])
    if "--records" not in arguments:
        return 2
    out = Path(arguments[arguments.index("--records") + 1])
    out.mkdir(parents=True, exist_ok=True)
    for name in RECORDS:
        (out / name).write_bytes(b"{}" + bytes([10]))
    print('{"code":"EV_OK"}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def mini_members(entry: str, extra: dict[str, bytes] | None = None) -> dict[str, bytes]:
    members = {
        "verify.py": entry.encode("utf-8"),
        "evidence/a23/SPEC.json": MINI_RECORD,
        "evidence/a23/DIFFERENTIAL.json": MINI_RECORD,
        "evidence/a23/PROPERTIES.json": MINI_RECORD,
        "evidence/a23/CONTROLS.json": MINI_RECORD,
    }
    members.update(extra or {})
    return members


def write_mini(root: Path, entry: str, extra: dict[str, bytes] | None = None) -> Path:
    pe.write_package(
        root, mini_members(entry, extra), commit="0" * 40, recorded_at="2026-11-24"
    )
    return root


def code_of(action: Any) -> str:
    try:
        action()
    except pe.Refusal as refusal:
        return refusal.code
    return pe.CODE_OK


_STATE: dict[str, Any] = {}


def state() -> dict[str, Any]:
    """Build one real package and verify it once, however many classes ask."""
    if not _STATE:
        directory = Path(tempfile.mkdtemp(prefix="a24-tests-"))
        package = directory / "PACKAGE"
        manifest = pe.build(
            None, package, commit="b" * 40, recorded_at="2026-11-24"
        )
        result = pe.verify(package)
        atexit.register(shutil.rmtree, directory, True)
        _STATE.update(
            directory=directory, package=package, manifest=manifest, result=result
        )
    return _STATE


class Build(unittest.TestCase):
    """The manifest describes exactly the files the package contains."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = state()
        cls.package = cls.fixture["package"]
        cls.manifest = cls.fixture["manifest"]

    def test_every_declared_input_is_tracked(self) -> None:
        for path in pe.DECLARED_INPUTS:
            self.assertTrue(pe._tracked(REPO, path), f"{path} is not tracked")
            self.assertTrue((REPO / path).is_file(), f"{path} is absent")

    def test_manifest_records_every_member_with_size_and_digest(self) -> None:
        rows = self.manifest["members"]
        declared = {row["path"] for row in rows}
        on_disk = pe._files_under(self.package) - {pe.MANIFEST_NAME}
        self.assertEqual(declared, on_disk)
        for row in rows:
            data = (self.package / row["path"]).read_bytes()
            self.assertEqual(row["bytes"], len(data))
            self.assertEqual(row["sha256"], pe.sha256_bytes(data))

    def test_manifest_declares_no_network_and_no_private_state(self) -> None:
        declarations = self.manifest["declarations"]
        self.assertIs(declarations["network"], False)
        self.assertEqual(declarations["privateState"], "none")
        self.assertIs(declarations["absolutePaths"], False)
        self.assertIs(declarations["untrackedFiles"], False)

    def test_manifest_names_the_entry_point_and_interpreter(self) -> None:
        self.assertEqual(self.manifest["entryPoint"], "verify.py")
        self.assertEqual(self.manifest["minimumInterpreter"], "3.11")
        self.assertIn("python3 verify.py", self.manifest["exactCommands"])
        self.assertIn("env -i", self.manifest["strippedEnvironmentCommand"])

    def test_the_package_is_text_only(self) -> None:
        for path in pe._files_under(self.package):
            (self.package / path).read_bytes().decode("utf-8")

    def test_the_manifest_is_bound_by_its_own_digest(self) -> None:
        self.assertEqual(
            self.manifest["packageDigest"], pe.manifest_digest(self.manifest)
        )

    def test_a_second_build_is_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            other = Path(directory) / "PACKAGE"
            manifest = pe.build(
                None, other, commit="b" * 40, recorded_at="2026-11-24"
            )
            self.assertEqual(manifest["packageDigest"], self.manifest["packageDigest"])
            for path in pe._files_under(self.package):
                self.assertEqual(
                    (self.package / path).read_bytes(),
                    (other / path).read_bytes(),
                    f"{path} differs between two builds",
                )


class Verify(unittest.TestCase):
    """A real package verifies in this venue, and nothing more is claimed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = state()
        cls.package = cls.fixture["package"]
        cls.manifest = cls.fixture["manifest"]
        cls.result = cls.fixture["result"]

    def test_the_in_venue_outcome_is_reported(self) -> None:
        self.assertEqual(self.result["outcome"], "PACKAGE_VERIFIED_IN_VENUE")
        self.assertEqual(self.result["code"], pe.CODE_OK)

    def test_the_external_status_is_never_verified(self) -> None:
        self.assertEqual(self.result["externalStatus"], "EXTERNAL_REVIEW_PENDING")
        self.assertIs(self.result["externalPartyRan"], False)
        self.assertIs(self.result["isExternal"], False)
        self.assertNotIn("VERIFIED_EXTERNALLY", json.dumps(self.result))

    def test_four_records_were_compared_and_all_equal(self) -> None:
        self.assertEqual(self.result["recordsCompared"], 4)
        for row in self.result["records"]:
            self.assertTrue(row["equal"], row["record"])
            self.assertEqual(row["expectedSha256"], row["producedSha256"])

    def test_two_runs_were_made(self) -> None:
        self.assertEqual(self.result["runs"], 2)

    def test_the_environment_was_stripped(self) -> None:
        environment = self.result["environment"]
        self.assertTrue(environment["stripped"])
        self.assertIs(environment["inheritedVariables"], False)
        self.assertIsNone(environment["pythonpath"])
        self.assertEqual(environment["pathEntries"], 1)
        self.assertEqual(environment["isolationFlags"], ["-I", "-S", "-B"])

    def test_the_result_has_no_absolute_run_path(self) -> None:
        serialised = json.dumps(self.result)
        self.assertNotIn(tempfile.gettempdir(), serialised)

    def test_inventory_reports_unverified_and_pending(self) -> None:
        record = pe.inventory(self.package)
        self.assertEqual(record["outcome"], "PACKAGE_UNVERIFIED")
        self.assertEqual(record["externalStatus"], "EXTERNAL_REVIEW_PENDING")
        self.assertEqual(record["memberCount"], len(self.manifest["members"]))


class Environment(unittest.TestCase):
    """The stripped environment really strips, observed from inside the entry point."""

    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="a24-env-"))
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.poison = self.directory / "poison"
        self.poison.mkdir()
        (self.poison / "poisontoken.py").write_text("TOKEN = 1\n", encoding="utf-8")

    def test_the_run_environment_has_one_path_entry_and_no_pythonpath(self) -> None:
        home = self.directory / "home"
        home.mkdir()
        environment = pe.run_environment(home, self.directory)
        self.assertNotIn("PYTHONPATH", environment)
        self.assertEqual(environment["PATH"], str(pe._interpreter_directory()))
        self.assertEqual(environment["PATH"].split(os.pathsep), [environment["PATH"]])
        self.assertEqual(set(environment), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"})

    def test_a_hostile_environment_does_not_reach_the_entry_point(self) -> None:
        os.environ["A24_POISON"] = "1"
        original = os.environ.get("PYTHONPATH")
        os.environ["PYTHONPATH"] = str(self.poison)
        try:
            root = write_mini(self.directory / "pkg", _MINI_ENTRY_ENVIRONMENT)
            result = pe.verify(root)
        finally:
            os.environ.pop("A24_POISON", None)
            if original is None:
                os.environ.pop("PYTHONPATH", None)
            else:
                os.environ["PYTHONPATH"] = original
        self.assertEqual(result["outcome"], "PACKAGE_VERIFIED_IN_VENUE")
        self.assertNotIn("poison", json.dumps(result))


class TemporaryLocation(unittest.TestCase):
    """A package runs from a temporary directory with no repository read."""

    def test_the_real_package_read_nothing_outside_its_unpacked_directory(self) -> None:
        result = state()["result"]
        checks = {row["id"]: row["result"] for row in result["checks"]}
        self.assertEqual(checks["no-outside-read"], "PASS")
        self.assertTrue(result["environment"]["stripped"])

    def test_a_package_runs_with_the_working_directory_elsewhere(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = write_mini(Path(directory) / "pkg", _MINI_ENTRY)
            previous = Path.cwd()
            os.chdir(directory)
            try:
                result = pe.verify(package)
            finally:
                os.chdir(previous)
            self.assertEqual(result["outcome"], "PACKAGE_VERIFIED_IN_VENUE")

    def test_no_member_names_an_absolute_repository_path(self) -> None:
        for path in pe._files_under(PACKAGE):
            text = (PACKAGE / path).read_text(encoding="utf-8")
            self.assertNotIn(str(REPO), text, path)


class Refusals(unittest.TestCase):
    """One control per refusal code. Every row is control-only."""

    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="a24-refuse-"))
        self.addCleanup(shutil.rmtree, self.directory, True)

    def test_every_code_is_registered_and_documented_in_the_manifest(self) -> None:
        self.assertEqual(len(pe.REFUSAL_CODES), len(set(pe.REFUSAL_CODES)))
        for code in pe.REFUSAL_CODES:
            self.assertIn(code, pe.REFUSALS)
            self.assertTrue(pe.REFUSALS[code]["condition"])

    def test_refused_private_state(self) -> None:
        root = write_mini(
            self.directory / "pkg",
            _MINI_ENTRY,
            {"notes/NOTES.md": b"court/tmp/a24\n"},
        )
        self.assertEqual(code_of(lambda: pe.verify(root)), "EV_REFUSED_PRIVATE_STATE")

    def test_refused_missing_input(self) -> None:
        self.assertEqual(
            code_of(
                lambda: pe.build(
                    ["evidence/a23/ABSENT.json"],
                    self.directory / "pkg",
                    declared={"evidence/a23/ABSENT.json": "x"},
                )
            ),
            "EV_REFUSED_MISSING_INPUT",
        )

    def test_refused_absolute_path(self) -> None:
        self.assertEqual(
            code_of(
                lambda: pe.build(
                    ["/etc/passwd"],
                    self.directory / "pkg",
                    declared={"/etc/passwd": "x"},
                )
            ),
            "EV_REFUSED_ABSOLUTE_PATH",
        )

    def test_refused_parent_traversal(self) -> None:
        self.assertEqual(
            code_of(
                lambda: pe.build(
                    ["../outside.json"],
                    self.directory / "pkg",
                    declared={"../outside.json": "x"},
                )
            ),
            "EV_REFUSED_ABSOLUTE_PATH",
        )

    def test_refused_network(self) -> None:
        root = write_mini(
            self.directory / "pkg", _MINI_ENTRY, {"helper/net.py": b"import socket\n"}
        )
        self.assertEqual(code_of(lambda: pe.verify(root)), "EV_REFUSED_NETWORK")

    def test_refused_undeclared_dependency_at_build(self) -> None:
        self.assertEqual(
            code_of(
                lambda: pe.build(["docs/ETP-TODO.md"], self.directory / "pkg")
            ),
            "EV_REFUSED_UNDECLARED_DEPENDENCY",
        )

    def test_refused_undeclared_dependency_at_run(self) -> None:
        root = write_mini(self.directory / "pkg", _MINI_ENTRY_OUTSIDE)
        self.assertEqual(
            code_of(lambda: pe.verify(root)), "EV_REFUSED_UNDECLARED_DEPENDENCY"
        )

    def test_refused_manifest_mismatch_on_a_member_byte(self) -> None:
        root = write_mini(self.directory / "pkg", _MINI_ENTRY)
        target = root / "evidence/a23/SPEC.json"
        target.write_bytes(MINI_RECORD + b" ")
        self.assertEqual(
            code_of(lambda: pe.verify(root)), "EV_REFUSED_MANIFEST_MISMATCH"
        )

    def test_refused_manifest_mismatch_on_a_produced_record(self) -> None:
        root = write_mini(self.directory / "pkg", _MINI_ENTRY_TAMPERED)
        self.assertEqual(
            code_of(lambda: pe.verify(root)), "EV_REFUSED_MANIFEST_MISMATCH"
        )

    def test_refused_reproducible(self) -> None:
        root = write_mini(self.directory / "pkg", _MINI_ENTRY_RANDOM)
        self.assertEqual(code_of(lambda: pe.verify(root)), "EV_REFUSED_REPRODUCIBLE")

    def test_refused_undeclared_tool(self) -> None:
        root = write_mini(
            self.directory / "pkg", _MINI_ENTRY, {"helper/tool.py": b"import subprocess\n"}
        )
        self.assertEqual(code_of(lambda: pe.verify(root)), "EV_REFUSED_UNDECLARED_TOOL")

    def test_refused_package_mutated_by_an_extra_file(self) -> None:
        root = write_mini(self.directory / "pkg", _MINI_ENTRY)
        (root / "extra.txt").write_text("x\n", encoding="utf-8")
        self.assertEqual(code_of(lambda: pe.verify(root)), "EV_REFUSED_PACKAGE_MUTATED")

    def test_refused_package_mutated_by_a_manifest_edit(self) -> None:
        root = write_mini(self.directory / "pkg", _MINI_ENTRY)
        path = root / pe.MANIFEST_NAME
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["candidate"]["recordedAt"] = "2026-11-25"
        path.write_bytes(pe.pretty(manifest))
        self.assertEqual(code_of(lambda: pe.verify(root)), "EV_REFUSED_PACKAGE_MUTATED")

    def test_refused_external_not_run(self) -> None:
        root = write_mini(self.directory / "pkg", _MINI_ENTRY)
        self.assertEqual(
            code_of(lambda: pe.verify(root, claim="external")),
            "EV_REFUSED_EXTERNAL_NOT_RUN",
        )

    def test_refused_untracked_input(self) -> None:
        repo = self.directory / "repo"
        repo.mkdir()
        (repo / "tracked.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(repo), "add", "tracked.py"], check=True, capture_output=True
        )
        (repo / "untracked.py").write_text("x = 2\n", encoding="utf-8")
        self.assertEqual(
            code_of(
                lambda: pe.build(
                    ["untracked.py"],
                    self.directory / "pkg",
                    declared={"untracked.py": "x"},
                    repo=repo,
                )
            ),
            "EV_REFUSED_UNTRACKED_INPUT",
        )

    def test_refused_entrypoint_failed(self) -> None:
        root = write_mini(self.directory / "pkg", _MINI_ENTRY_FAIL)
        self.assertEqual(
            code_of(lambda: pe.verify(root)), "EV_REFUSED_ENTRYPOINT_FAILED"
        )


class StructuralScan(unittest.TestCase):
    """The no-network and no-external-program scans are structural, not prose."""

    def test_every_packaged_python_member_has_no_network_import(self) -> None:
        for path in pe._files_under(PACKAGE):
            if not path.endswith(".py"):
                continue
            imports = pe._imports((PACKAGE / path).read_bytes())
            self.assertEqual(imports & pe.NETWORK_MODULES, set(), path)
            self.assertEqual(imports & pe.PROCESS_MODULES, set(), path)

    def test_the_scan_fires_on_a_socket_member(self) -> None:
        self.assertEqual(
            pe.scan_network({"a.py": b"import socket\n"}),
            ("a.py", "imports 'socket'"),
        )

    def test_the_scan_fires_on_a_subprocess_member(self) -> None:
        found = pe.scan_undeclared_tool({"a.py": b"import subprocess\n"})
        self.assertIsNotNone(found)
        self.assertEqual(found[0], "a.py")

    def test_the_scan_fires_on_an_os_system_call(self) -> None:
        found = pe.scan_undeclared_tool({"a.py": b"import os\nos.system('true')\n"})
        self.assertIsNotNone(found)

    def test_the_scan_fires_on_private_state(self) -> None:
        found = pe.scan_private_state({"a.md": b"see court/tmp/x\n"})
        self.assertIsNotNone(found)

    def test_the_scan_accepts_a_clean_member(self) -> None:
        self.assertIsNone(pe.scan_private_state({"a.py": b"x = 1\n"}))
        self.assertIsNone(pe.scan_network({"a.py": b"import json\n"}))
        self.assertIsNone(pe.scan_undeclared_tool({"a.py": b"import json\n"}))


class Records(unittest.TestCase):
    """The committed records say what happened, and no more."""

    def load(self, name: str) -> Any:
        path = EVIDENCE / name
        self.assertTrue(path.is_file(), f"{path} is absent")
        return json.loads(path.read_text(encoding="utf-8"))

    def test_controls_cover_every_refusal_code(self) -> None:
        record = self.load("CONTROLS.json")
        self.assertTrue(record["coversEveryCode"])
        self.assertEqual(sorted(record["codesCovered"]), sorted(pe.REFUSAL_CODES))
        self.assertTrue(all(row["controlOnly"] for row in record["controls"]))
        self.assertEqual(record["controlCount"], len(record["controls"]))

    def test_status_is_pending_and_not_a_pass(self) -> None:
        status = self.load("STATUS.json")
        self.assertEqual(status["externalStatus"], "EXTERNAL_REVIEW_PENDING")
        self.assertIs(status["externalPartyRan"], False)
        self.assertIs(status["isPass"], False)
        self.assertIs(status["inVenueRunIsNotExternal"], True)
        self.assertTrue(status["whatWouldCountAsExternalReproduction"])
        self.assertTrue(status["evidenceTheExternalPartyMustPublish"])

    def test_the_run_record_is_in_venue_not_external(self) -> None:
        run = self.load("RUN.json")
        self.assertEqual(run["outcome"], "PACKAGE_VERIFIED_IN_VENUE")
        self.assertEqual(run["externalStatus"], "EXTERNAL_REVIEW_PENDING")
        self.assertIs(run["notExternal"], True)
        self.assertIs(run["externalPartyRan"], False)
        self.assertTrue(run["strippedEnvironment"]["stripped"])
        self.assertIsNone(run["strippedEnvironment"]["pythonpath"])
        self.assertEqual(run["recordsCompared"], 4)
        self.assertEqual(run["entryPointRuns"], 2)

    def test_the_run_records_name_the_package_digest(self) -> None:
        run = self.load("RUN.json")
        status = self.load("STATUS.json")
        manifest = json.loads((PACKAGE / pe.MANIFEST_NAME).read_text(encoding="utf-8"))
        self.assertEqual(run["packageDigest"], manifest["packageDigest"])
        self.assertEqual(status["packageDigest"], manifest["packageDigest"])


class EntryPointIntegrity(unittest.TestCase):
    """The entry point refuses a tampered package before it runs anything."""

    def test_the_entry_point_checks_the_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "PACKAGE"
            shutil.copytree(PACKAGE, target)
            spec = target / "evidence/a23/SPEC.json"
            spec.write_bytes(spec.read_bytes() + b" ")
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(target / "verify.py"),
                    "--records",
                    str(Path(directory) / "records"),
                ],
                cwd=directory,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("EV_REFUSED_MANIFEST_MISMATCH", result.stdout)

    def test_the_entry_point_refuses_anything_below_the_minimum(self) -> None:
        source = (PACKAGE / "verify.py").read_text(encoding="utf-8")
        self.assertIn("MINIMUM = (3, 11)", source)
        self.assertIn("EV_REFUSED_UNDECLARED_TOOL", source)

    def test_a_direct_run_writes_nothing_into_the_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "PACKAGE"
            shutil.copytree(PACKAGE, target)
            result = subprocess.run(
                [
                    sys.executable,
                    str(target / "verify.py"),
                    "--records",
                    str(Path(directory) / "records"),
                ],
                cwd=directory,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                sorted(path.name for path in target.rglob("__pycache__")), []
            )
            self.assertEqual(sorted(target.rglob("*.pyc")), [])


class CommandLine(unittest.TestCase):
    """Exit 0 on success, 1 on a refusal, 2 on usage; the code is always printed."""

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )

    def test_usage_exits_two_with_a_code(self) -> None:
        result = self.run_cli()
        self.assertEqual(result.returncode, 2)
        self.assertIn("code=EV_USAGE", result.stdout)
        self.assertIn("outcome=", result.stdout)

    def test_a_missing_argument_exits_two_with_a_code(self) -> None:
        result = self.run_cli("build")
        self.assertEqual(result.returncode, 2)
        self.assertIn("code=EV_USAGE", result.stdout)
        self.assertIn("outcome=PACKAGE_UNVERIFIED", result.stdout)

    def test_inventory_exits_zero_and_prints_the_pending_status(self) -> None:
        result = self.run_cli("inventory", str(PACKAGE))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("code=EV_OK", result.stdout)
        self.assertIn("outcome=PACKAGE_UNVERIFIED", result.stdout)
        self.assertIn("external=EXTERNAL_REVIEW_PENDING", result.stdout)

    def test_a_refused_verify_exits_one_with_its_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(Path(directory) / "pkg", _MINI_ENTRY)
            (root / "extra.txt").write_text("x\n", encoding="utf-8")
            result = self.run_cli("verify", str(root))
        self.assertEqual(result.returncode, 1)
        self.assertIn("code=EV_REFUSED_PACKAGE_MUTATED", result.stdout)
        self.assertIn("outcome=PACKAGE_INVALID", result.stdout)

    def test_an_external_claim_exits_one_and_stays_pending(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(Path(directory) / "pkg", _MINI_ENTRY)
            result = self.run_cli("verify", str(root), "--claim", "external")
        self.assertEqual(result.returncode, 1)
        self.assertIn("code=EV_REFUSED_EXTERNAL_NOT_RUN", result.stdout)
        self.assertIn("outcome=EXTERNAL_REVIEW_PENDING", result.stdout)

    def test_build_exits_zero_and_writes_the_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "pkg"
            result = self.run_cli("build", "--out", str(out))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("code=EV_OK", result.stdout)
            self.assertIn("outcome=PACKAGE_UNVERIFIED", result.stdout)
            self.assertTrue((out / pe.MANIFEST_NAME).is_file())

    def test_verify_on_a_mini_package_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(Path(directory) / "pkg", _MINI_ENTRY)
            result = self.run_cli("verify", str(root))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("code=EV_OK", result.stdout)
        self.assertIn("outcome=PACKAGE_VERIFIED_IN_VENUE", result.stdout)


class Document(unittest.TestCase):
    """The document names every code, every outcome and every limit."""

    def setUp(self) -> None:
        self.assertTrue(DOCUMENT.is_file(), f"{DOCUMENT} is absent")
        self.text = DOCUMENT.read_text(encoding="utf-8")

    def test_every_refusal_code_is_named(self) -> None:
        for code in pe.REFUSAL_CODES:
            self.assertIn(code, self.text, f"the document does not name {code}")

    def test_every_outcome_is_named(self) -> None:
        for outcome in (
            "PACKAGE_VERIFIED_IN_VENUE",
            "PACKAGE_UNVERIFIED",
            "PACKAGE_INVALID",
            "EXTERNAL_REVIEW_PENDING",
        ):
            self.assertIn(outcome, self.text, f"the document does not name {outcome}")

    def test_the_external_status_is_stated(self) -> None:
        self.assertIn("EXTERNAL_REVIEW_PENDING", self.text)
        self.assertIn("no external party has run", self.text)
        self.assertIn("not a pass", self.text)

    def test_the_stripped_environment_rule_is_stated(self) -> None:
        self.assertIn("stripped environment", self.text)
        self.assertIn("PATH", self.text)
        self.assertIn("PYTHONPATH", self.text)

    def test_the_exclusion_rule_is_stated(self) -> None:
        self.assertIn("exclusion rule", self.text.lower())
        self.assertIn("forensics/tools/adversarial_qualification.py", self.text)
        self.assertIn("cc", self.text)

    def test_the_boundaries_are_stated(self) -> None:
        self.assertIn("A12", self.text)
        self.assertIn("A17", self.text)
        self.assertIn("Article 1", self.text)
        self.assertIn("Article 2", self.text)
        self.assertIn("Article 5", self.text)

    def test_the_tests_are_named(self) -> None:
        self.assertIn("forensics/tools/tests/test_package_external.py", self.text)

    def test_not_run_is_stated(self) -> None:
        self.assertIn("NOT_RUN", self.text)


if __name__ == "__main__":
    unittest.main()
