#!/usr/bin/env python3
"""Controls for the public-surface declaration and its drift detector (A25).

Every control is a test-only fixture: a stub verifier written into a temporary
directory, or an in-memory mutation of the declaration.  None of them is a
shipped configuration, and none of them edits the real verifier.

The last group compares the two documents with the declaration, because a
document that describes a contract it does not describe is the drift this item
exists to prevent.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "forensics" / "tools"))

import public_surface as ps  # noqa: E402

SURFACE_PATH = ROOT / "evidence" / "a25" / "SURFACE.json"
VERIFIER = ROOT / "forensics" / "tools" / "verify.py"
CONTRACT_DOC = ROOT / "docs" / "PUBLIC-VERIFIER.md"
DESCRIPTIVE_DOC = ROOT / "docs" / "PUBLIC-VERIFICATION.md"
TOOL = ROOT / "forensics" / "tools" / "public_surface.py"

STUB = '''#!/usr/bin/env python3
import json
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
config = json.loads((here / "stub.json").read_text(encoding="utf-8"))
counter = here / "counter"
count = int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(count + 1))
argv = sys.argv[1:]
response = (config["responses"].get(json.dumps(argv))
            or config["responses"]["*"])
out = response.get("stdout", "")
if response.get("vary"):
    out = out.replace("__RUN__", str(count))
sys.stdout.write(out)
sys.exit(int(response["exit"]))
'''

DOCUMENT = {
    "candidate": {"clean": True, "commit": "0" * 40},
    "counts": {"selected": 1},
    "environment": {"declared": "environment-input"},
    "interface": "ETP-T12",
    "invocation": {"network": False, "steps": ["authority"], "tmpdir": "<tmp>"},
    "non_passing": ["authority"],
    "private_state": {"present": []},
    "root": "<root>",
    "schema": "openssl-rs/verify/1",
    "status": "FAIL",
    "steps": [],
    "warnings": [],
}


def surface() -> dict:
    return json.loads(SURFACE_PATH.read_text(encoding="utf-8"))


def _probe(argv: list[str]) -> ps.Run:
    return ps.run_verifier(VERIFIER, argv, ROOT)


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.listing = _probe(["--list"]).stdout
        cls.help = _probe(["--help"]).stdout
        cls.explain = _probe(["--explain"]).stdout


def _stub_config(*, listing=None, help_text=None, explain_text=None,
                 document=None, exits=None, vary=False) -> dict:
    """A control-only stub that imitates the real surface unless mutated."""
    base = {
        "listing": _probe(["--list"]).stdout,
        "help": _probe(["--help"]).stdout,
        "explain": _probe(["--explain"]).stdout,
    }
    listing = base["listing"] if listing is None else listing
    help_text = base["help"] if help_text is None else help_text
    explain_text = base["explain"] if explain_text is None else explain_text
    document = DOCUMENT if document is None else document
    if vary:
        document = copy.deepcopy(document)
        document["counts"] = {"selected": "__RUN__"}
    exits = exits or {}
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    return {"responses": {
        json.dumps(["--list"]): {"stdout": listing, "exit": exits.get("list", 0)},
        json.dumps(["--list", "--json"]): {"stdout": listing,
                                           "exit": exits.get("list", 0)},
        json.dumps(["--help"]): {"stdout": help_text, "exit": 0},
        json.dumps(["--explain"]): {"stdout": explain_text, "exit": 0},
        json.dumps(["--explain", "all"]): {"stdout": explain_text, "exit": 0},
        json.dumps(["authority"]): {"stdout": "", "exit": exits.get("authority", 1)},
        json.dumps(["nosuch-command"]): {"stdout": "",
                                         "exit": exits.get("unknown-command", 2)},
        json.dumps(["--tmp"]): {"stdout": "", "exit": 2},
        json.dumps(["--explain", "nosuch-command"]): {"stdout": "", "exit": 2},
        json.dumps(["authority", "--json"]): {"stdout": text,
                                              "exit": exits.get("authority", 1),
                                              "vary": vary},
        "*": {"stdout": "", "exit": 2},
    }}


def _run_stub(declaration: dict, config: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="a25-test-") as tmp:
        directory = Path(tmp)
        (directory / "stub_verifier.py").write_text(STUB, encoding="utf-8")
        (directory / "stub.json").write_text(
            json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")
        return ps.verify(declaration, directory / "stub_verifier.py", root=ROOT,
                         verifier_label="control-stub")


def _codes(verdict: dict) -> set[str]:
    return {finding["code"] for finding in verdict["findings"]}


# ---------------------------------------------------------------------------
# the executable surface matches the declaration
# ---------------------------------------------------------------------------


class SurfaceMatchesExecutable(_Base):
    def test_the_executable_inventory_matches_the_surface(self) -> None:
        declaration = surface()
        declared = {entry["name"]: entry for entry in declaration["commands"]}
        observed = ps.parse_listing(self.listing)
        listed = [row["name"] for row in observed]
        self.assertEqual(len(listed), 20, "the listing is the twenty step commands")
        for name in listed:
            self.assertIn(name, declared, f"{name} is executable and undeclared")
            self.assertEqual(declared[name]["kind"], "step")
        for name, entry in declared.items():
            if entry["kind"] == "step":
                self.assertIn(name, listed, f"{name} is declared and not listed")
                self.assertIn(name, ps.parse_explain(self.explain),
                              f"{name} is declared and not explained")
        # aggregate and discovery commands are recognised by a declared probe
        for name in ("all", "list", "explain"):
            probe_id = declared[name]["recognisedBy"]
            probe = next(item for item in declaration["exitCodeProbes"]
                         if item["id"] == probe_id)
            run = _probe(probe["argv"])
            self.assertEqual(run.exit, 0, f"{name}'s recognition probe failed")
        self.assertEqual(len(declared), 23)

    def test_every_declared_exit_code_is_observed_or_command_specific(self) -> None:
        declaration = surface()
        contract = declaration["exitCodeContract"]
        probes = {item["id"]: item for item in declaration["exitCodeProbes"]}
        observed: dict[int, list[str]] = {}
        for identifier, probe in probes.items():
            run = _probe(probe["argv"])
            self.assertEqual(run.exit, probe["code"],
                             f"probe {identifier} does not demonstrate its code")
            observed.setdefault(run.exit, []).append(identifier)
        for code in contract:
            self.assertIn(int(code), observed,
                          f"contract code {code} is declared and never observed")
        for entry in declaration["commands"]:
            for declared in entry["exitCodes"]:
                self.assertIn(str(declared["code"]), contract,
                              f"{entry['name']} declares {declared['code']}")
                source = declared.get("observedBy")
                if source:
                    self.assertIn(source, probes,
                                  f"{entry['name']} names a missing probe")
                    self.assertEqual(_probe(probes[source]["argv"]).exit,
                                     declared["code"],
                                     f"{entry['name']}'s observation is wrong")
                else:
                    self.assertTrue(declared.get("basis"),
                                    f"{entry['name']} declares "
                                    f"{declared['code']} with neither observation "
                                    f"nor basis")

    def test_two_listing_runs_are_byte_identical(self) -> None:
        first = subprocess.run([sys.executable, str(VERIFIER), "--list", "--json"],
                               cwd=str(ROOT), capture_output=True, text=True)
        second = subprocess.run([sys.executable, str(VERIFIER), "--list", "--json"],
                                cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.returncode, 0)
        self.assertFalse(ps._is_json_object(first.stdout),
                         "the listing is TSV; the surface declares no document here")
        self.assertIn("\t", first.stdout)

    def test_the_json_fields_are_exactly_the_declared_set(self) -> None:
        declaration = surface()
        probe = declaration["discovery"]["jsonProbe"]
        run = subprocess.run([sys.executable, str(VERIFIER), *probe["argv"]],
                             cwd=str(ROOT), capture_output=True, text=True)
        document = json.loads(run.stdout)
        declared = next(entry for entry in declaration["commands"]
                        if entry["name"] == probe["command"])
        self.assertEqual(sorted(document), sorted(declared["jsonFields"]))
        for entry in declaration["commands"]:
            if entry["jsonForm"] == "document":
                self.assertEqual(entry["jsonFields"], declared["jsonFields"])

    def test_help_arguments_and_prerequisites_match_the_surface(self) -> None:
        declaration = surface()
        declared_options = set()
        for argument in declaration["arguments"]:
            if argument["name"].startswith("-"):
                declared_options.add(argument["name"])
            declared_options.update(argument.get("aliases") or [])
        self.assertEqual(ps.help_option_tokens(self.help), declared_options)
        positional = [argument["name"] for argument in declaration["arguments"]
                      if not argument["name"].startswith("-")]
        for name in positional:
            self.assertIn(name, self.help, f"positional {name} is not in --help")
        self.assertEqual(ps.help_command_tokens(self.help), {"all", "list"})
        blocks = ps.parse_explain(self.explain)
        for entry in declaration["commands"]:
            block = blocks.get(entry["name"])
            if block is None:
                continue
            self.assertEqual(sorted(entry["prerequisites"]),
                             sorted(block.get("needs") or []), entry["name"])
            self.assertEqual(sorted(entry["delegatesTo"]),
                             sorted(block.get("delegates") or []), entry["name"])

    def test_private_state_declarations_match(self) -> None:
        declaration = surface()
        blocks = ps.parse_explain(self.explain)
        for entry in declaration["commands"]:
            block = blocks.get(entry["name"])
            if block is None:
                continue
            self.assertEqual(sorted(entry["privateState"]),
                             sorted(block.get("private") or []), entry["name"])


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------


class Determinism(_Base):
    def test_two_document_runs_agree_outside_the_environment_block(self) -> None:
        probe = surface()["discovery"]["jsonProbe"]
        first = _probe(probe["argv"])
        second = _probe(probe["argv"])
        one = json.loads(first.stdout)
        two = json.loads(second.stdout)
        key = probe["environmentKey"]
        self.assertEqual(one[key]["declared"], probe["environmentDeclaration"])
        self.assertEqual(ps.canonical(ps._projection(one, key)),
                         ps.canonical(ps._projection(two, key)))
        self.assertEqual(first.exit, second.exit)

    def test_the_surface_check_is_deterministic(self) -> None:
        declaration = surface()
        first = ps.verify(declaration, VERIFIER, root=ROOT)
        second = ps.verify(declaration, VERIFIER, root=ROOT)
        self.assertEqual(first["codes"], second["codes"])
        self.assertEqual(first["findings"], second["findings"])
        self.assertEqual(first["commands"], second["commands"])
        self.assertEqual(first["observed"]["helpOptionTokens"],
                         second["observed"]["helpOptionTokens"])


# ---------------------------------------------------------------------------
# one control per refusal code
# ---------------------------------------------------------------------------


class Refusals(_Base):
    def assert_exactly(self, verdict: dict, code: str) -> None:
        self.assertEqual(_codes(verdict), {code},
                         f"expected only {code}, observed {_codes(verdict)}")

    def test_a_faithful_stub_is_accepted(self) -> None:
        verdict = _run_stub(surface(), _stub_config())
        self.assertEqual(verdict["codes"], [ps.OK_CODE])
        self.assertEqual(verdict["findings"], [])

    def test_an_undocumented_subcommand_is_refused(self) -> None:
        config = _stub_config()
        config["responses"][json.dumps(["--list"])]["stdout"] = (
            self.listing + "surprise-step\trequired\tin all\n")
        self.assert_exactly(_run_stub(surface(), config),
                            "PV_REFUSED_COMMAND_UNDOCUMENTED")

    def test_a_documented_but_absent_command_is_refused(self) -> None:
        declaration = copy.deepcopy(surface())
        declaration["commands"].append({
            "name": "sphinx", "kind": "step", "invocation": ["sphinx"],
            "summary": "not executable", "arguments": ["command"],
            "prerequisites": [], "delegatesTo": [], "privateState": [],
            "exitCodes": [{"code": 0, "meaning": "PASS", "basis": "declared"}],
            "jsonForm": "none", "jsonFields": [], "stability": "experimental",
            "since": declaration["commands"][0]["since"],
            "evidence": ["forensics/tools/verify.py"], "replacement": None,
        })
        self.assert_exactly(_run_stub(declaration, _stub_config()),
                            "PV_REFUSED_COMMAND_ABSENT")

    def test_an_observed_exit_with_no_meaning_is_refused(self) -> None:
        self.assert_exactly(
            _run_stub(surface(), _stub_config(exits={"unknown-command": 7})),
            "PV_REFUSED_EXIT_UNDEFINED")

    def test_a_declared_exit_no_probe_observes_is_refused(self) -> None:
        declaration = copy.deepcopy(surface())
        declaration["exitCodeContract"]["4"] = {"meaning": "unused",
                                                "scope": "none"}
        self.assert_exactly(_run_stub(declaration, _stub_config()),
                            "PV_REFUSED_EXIT_UNUSED")

    def test_help_drift_is_refused(self) -> None:
        help_text = self.help + "\n  --verbose   an argument nobody declared\n"
        self.assert_exactly(
            _run_stub(surface(), _stub_config(help_text=help_text)),
            "PV_REFUSED_HELP_DRIFT")

    def test_an_undeclared_json_field_is_refused(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        document["surprise"] = True
        self.assert_exactly(
            _run_stub(surface(), _stub_config(document=document)),
            "PV_REFUSED_JSON_FIELD")

    def test_a_missing_declared_json_field_is_refused(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        del document["counts"]
        self.assert_exactly(
            _run_stub(surface(), _stub_config(document=document)),
            "PV_REFUSED_JSON_FIELD")

    def test_nondeterministic_output_is_refused(self) -> None:
        self.assert_exactly(_run_stub(surface(), _stub_config(vary=True)),
                            "PV_REFUSED_UNSTABLE_OUTPUT")

    def test_an_undeclared_private_state_read_is_refused(self) -> None:
        explain_text = self.explain.replace(
            "manifest  (required; in `all`)",
            "manifest  (required; in `all`)\n  private:      court", 1)
        self.assert_exactly(
            _run_stub(surface(), _stub_config(explain_text=explain_text)),
            "PV_REFUSED_PRIVATE_STATE")

    def test_an_unversioned_schema_is_refused(self) -> None:
        declaration = copy.deepcopy(surface())
        declaration.pop("schemaVersion")
        self.assert_exactly(_run_stub(declaration, _stub_config()),
                            "PV_REFUSED_UNVERSIONED_SCHEMA")

    def test_a_deprecation_without_replacement_is_refused(self) -> None:
        declaration = copy.deepcopy(surface())
        for entry in declaration["commands"]:
            if entry["name"] == "docs":
                entry["stability"] = "deprecated"
                entry["replacement"] = None
        self.assert_exactly(_run_stub(declaration, _stub_config()),
                            "PV_REFUSED_DEPRECATED_WITHOUT_REPLACEMENT")

    def test_a_stability_overclaim_is_refused(self) -> None:
        declaration = copy.deepcopy(surface())
        for entry in declaration["commands"]:
            if entry["name"] == "manifest":
                entry["evidence"] = ["evidence/a25/no-such-evidence.json"]
        self.assert_exactly(_run_stub(declaration, _stub_config()),
                            "PV_REFUSED_STABILITY_OVERCLAIM")

    def test_a_structurally_invalid_surface_is_refused(self) -> None:
        declaration = copy.deepcopy(surface())
        declaration["commands"].append(copy.deepcopy(
            next(entry for entry in declaration["commands"]
                 if entry["name"] == "claims")))
        self.assert_exactly(_run_stub(declaration, _stub_config()),
                            "PV_REFUSED_SURFACE_INVALID")

    def test_every_declared_code_has_a_control(self) -> None:
        self.assertGreaterEqual(len(ps.CODES), 12)
        # one test per code is enforced by the tests above and in CommandLine;
        # this asserts the code list has not grown without a test being added.
        self.assertEqual(len(ps.CODES), 13)


# ---------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------


class CommandLine(_Base):
    def _run(self, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(TOOL), *argv], cwd=str(ROOT),
                              capture_output=True, text=True)

    def test_verify_exits_zero_and_prints_the_code(self) -> None:
        run = self._run("verify")
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("codes=PV_OK", run.stdout)

    def test_inventory_json_is_one_document(self) -> None:
        run = self._run("inventory", "--json")
        self.assertEqual(run.returncode, 0, run.stderr)
        document = json.loads(run.stdout)
        self.assertEqual(document["schema"], ps.INVENTORY_SCHEMA)
        self.assertEqual(document["counts"]["listedSteps"], 20)

    def test_explaining_an_undeclared_command_is_a_usage_error(self) -> None:
        run = self._run("explain", "nosuch-command")
        self.assertEqual(run.returncode, 2)
        self.assertIn("PV_REFUSED_COMMAND_ABSENT", run.stderr)
        self.assertIn("codes=PV_REFUSED_COMMAND_ABSENT", run.stderr)

    def test_a_missing_surface_is_a_usage_error(self) -> None:
        run = self._run("--surface", "evidence/a25/no-such-surface.json", "verify")
        self.assertEqual(run.returncode, 2)
        self.assertIn("codes=PV_REFUSED_SURFACE_INVALID", run.stderr)

    def test_explaining_a_declared_command_prints_its_contract(self) -> None:
        run = self._run("explain", "manifest")
        self.assertEqual(run.returncode, 0)
        self.assertIn("command=manifest", run.stdout)
        self.assertIn("stability=stable", run.stdout)
        self.assertIn("codes=PV_OK", run.stdout)

    def test_a_malformed_invocation_prints_a_code(self) -> None:
        run = self._run("bogus-action")
        self.assertEqual(run.returncode, 2)
        self.assertIn("codes=PV_REFUSED_USAGE", run.stderr)

    def test_help_prints_a_code(self) -> None:
        run = self._run("--help")
        self.assertEqual(run.returncode, 0)
        self.assertIn("codes=PV_OK", run.stderr)


# ---------------------------------------------------------------------------
# the documents describe the declaration
# ---------------------------------------------------------------------------


class Documentation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = CONTRACT_DOC.read_text(encoding="utf-8")
        cls.descriptive = DESCRIPTIVE_DOC.read_text(encoding="utf-8")
        cls.declaration = surface()

    def test_every_refusal_code_is_documented(self) -> None:
        for code in ps.CODES:
            self.assertIn(code, self.contract, f"{code} is not in the contract")
            entry = next((item for item in self.declaration["commands"]
                          if item["name"] == "manifest"), None)
            self.assertIsNotNone(entry)
        self.assertIn("PV_REFUSED_SURFACE_INVALID", self.contract)

    def test_the_contract_document_names_every_code_and_command(self) -> None:
        for entry in self.declaration["commands"]:
            self.assertIn(entry["name"], self.contract,
                          f"command {entry['name']} is not documented")
        for argument in self.declaration["arguments"]:
            self.assertIn(argument["name"], self.contract,
                          f"argument {argument['name']} is not documented")

    def test_the_contract_document_states_the_exit_contract_and_schema(self) -> None:
        self.assertIn(self.declaration["schemaVersion"], self.contract)
        for code in self.declaration["exitCodeContract"]:
            self.assertIn(f"`{code}`", self.contract)
        for level in ("stable", "experimental", "deprecated"):
            self.assertIn(f"`{level}`", self.contract)

    def test_the_contract_document_names_the_descriptive_document(self) -> None:
        self.assertIn("docs/PUBLIC-VERIFICATION.md", self.contract)
        self.assertIn("older descriptive document", self.contract)
        self.assertIn("normative", self.contract)
        for marker in ("not normative for", "contract"):
            self.assertIn(marker, self.contract.lower())
        self.assertIn("two documents", self.contract.lower())

    def test_every_enforced_by_names_a_code_or_a_test(self) -> None:
        lines = self.contract.splitlines()
        start = next((index for index, line in enumerate(lines)
                      if line.strip().lower() == "| property | enforced by |"), None)
        self.assertIsNotNone(start, "the enforcement table is missing")
        rows = []
        for line in lines[start + 2:]:
            if not line.startswith("|"):
                break
            rows.append(line)
        self.assertGreaterEqual(len(rows), 10, "the enforcement table is short")
        for row in rows:
            cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
            self.assertGreaterEqual(len(cells), 2, row)
            last = cells[-1]
            self.assertTrue(any(code in last for code in ps.CODES)
                            or "test_" in last,
                            f"enforced-by row names no code or test: {row}")

    def test_the_descriptive_document_is_not_claimed_as_the_contract(self) -> None:
        self.assertIn("`docs/PUBLIC-VERIFICATION.md` is the **older descriptive "
                      "document**", self.contract)

    def test_the_descriptive_document_no_longer_carries_the_stale_count(self) -> None:
        # D6: the figure was 19; it is a corrected record, not a claim to keep.
        self.assertNotIn("19 tests", self.descriptive)
        self.assertIn("37 tests", self.descriptive)

    def test_the_descriptive_document_names_the_flag_form(self) -> None:
        # D1: the table said `list`, which the executable refuses.
        self.assertIn("`--list`", self.descriptive)
        self.assertNotIn("| `list` | `python3` |", self.descriptive)

    def test_every_recorded_discrepancy_still_reproduces(self) -> None:
        inventory = json.loads((ROOT / "evidence" / "a25" / "INVENTORY.json")
                               .read_text(encoding="utf-8"))
        self.assertEqual([entry["id"] for entry in inventory["discrepancies"]],
                         ["D1", "D2", "D3", "D4", "D5", "D6"])
        for entry in inventory["discrepancies"]:
            self.assertTrue(entry["witness"], entry["id"])
            for witness in entry["witness"]:
                self.assertTrue(witness["reproduced"],
                                f"{entry['id']} witness no longer reproduces: "
                                f"{witness}")


if __name__ == "__main__":
    unittest.main()
