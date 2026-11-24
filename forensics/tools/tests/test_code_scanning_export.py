#!/usr/bin/env python3
"""Controls for the local code-scanning export.

Each control exercises one rule of `docs/CODE-SCANNING-EXPORT.md`: an export is
a local transformation with no network dependency; a shard is a self-contained
subset of at most 5,000 results and never a census; only the manifest states the
whole population; and `verify` refuses unless the union of the shards' exact
identities is the parent population once each, in the parent's order, with the
parent's tool, rules, artifacts and candidate.

A control mutates a copy in memory or a temporary directory. It is not a source
change and not a defect report: a control that fires proves the refusal works,
not that the substituted form occurs anywhere in the tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import code_scanning_export as export  # noqa: E402

A8 = REPO_ROOT / "evidence" / "a8"
PARENT = REPO_ROOT / "evidence" / "a1" / "SARIF.json"
MANIFEST = A8 / "MANIFEST.json"
PLAN = A8 / "PLAN.json"
SHARD = A8 / "SHARD-000.sarif"
CONTROLS = A8 / "CONTROLS.json"
PRODUCER = A8 / "build_evidence.py"
DOCUMENT = REPO_ROOT / "docs" / "CODE-SCANNING-EXPORT.md"
TOOL = TOOLS / "code_scanning_export.py"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _parent() -> tuple[bytes, dict]:
    raw = PARENT.read_bytes()
    return raw, json.loads(raw)


def _verify_inputs(logs: list[dict]) -> list[dict]:
    return [
        {"bytes": export.serialize_sarif(log).encode("utf-8"), "document": log}
        for log in logs
    ]


class CodeScanningExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parent_bytes, cls.parent = _parent()
        cls.parent_input = {
            "path": "evidence/a1/SARIF.json",
            "bytes": cls.parent_bytes,
            "document": cls.parent,
        }
        cls.shards = export.plan(cls.parent, export.MAX_RESULTS)
        cls.manifest = export.manifest(
            cls.parent,
            cls.shards,
            parent_bytes=cls.parent_bytes,
            parent_path="evidence/a1/SARIF.json",
            limit=export.MAX_RESULTS,
        )
        cls.logs = [export.emit(cls.parent, shard, cls.manifest) for shard in cls.shards]
        cls.text = [export.serialize_sarif(log) for log in cls.logs]

    # ------------------------------------------------------------------
    # The plan.
    # ------------------------------------------------------------------

    def test_the_real_population_plans_one_shard(self) -> None:
        self.assertEqual(len(self.shards), 1)
        self.assertEqual(len(self.shards[0]["results"]), 4245)
        self.assertEqual(self.shards[0]["runIndices"], [0, 1, 2, 3, 4, 5])
        self.assertEqual(self.shards[0]["total"], 1)

    def test_the_plan_is_deterministic(self) -> None:
        again = export.plan(self.parent, export.MAX_RESULTS)
        self.assertEqual(
            export.dump_document({"shards": self.shards}),
            export.dump_document({"shards": again}),
        )

    def test_boundaries_follow_input_order(self) -> None:
        synthetic = export.synthetic_document(12001)
        shards = export.plan(synthetic, export.MAX_RESULTS)
        self.assertEqual(len(shards), 3)
        self.assertEqual([len(shard["results"]) for shard in shards], [5000, 5000, 2001])
        self.assertEqual([shard["results"][0] for shard in shards], [0, 5000, 10000])
        self.assertEqual([shard["results"][-1] for shard in shards], [4999, 9999, 12000])

    # ------------------------------------------------------------------
    # The 5,000 boundary.
    # ------------------------------------------------------------------

    def test_exactly_five_thousand_results_are_accepted(self) -> None:
        document = export.synthetic_document(export.MAX_RESULTS)
        parent = {
            "path": "control/parent.sarif",
            "bytes": export.dump_document(document).encode("utf-8"),
            "document": document,
        }
        shards = export.plan(document, export.MAX_RESULTS)
        self.assertEqual(len(shards), 1)
        built = export.manifest(
            document,
            shards,
            parent_bytes=parent["bytes"],
            parent_path=parent["path"],
            limit=export.MAX_RESULTS,
        )
        logs = [export.emit(document, shard, built) for shard in shards]
        report = export.verify(built, _verify_inputs(logs), parent)
        self.assertEqual(report["results"], export.MAX_RESULTS)
        self.assertEqual(report["union"], "complete")

    def test_five_thousand_and_one_results_are_refused(self) -> None:
        document = export.synthetic_document(export.MAX_RESULTS + 1)
        parent = {
            "path": "control/parent.sarif",
            "bytes": export.dump_document(document).encode("utf-8"),
            "document": document,
        }
        shards = export.plan(document, export.MAX_RESULTS + 1)
        self.assertEqual(len(shards), 1)
        header_manifest = {
            "parent": {
                "sha256": export.digest_bytes(parent["bytes"]),
                "resultCount": export.MAX_RESULTS + 1,
            },
            "candidate": export.candidate_identity(document),
            "limit": export.MAX_RESULTS,
        }
        with self.assertRaises(export.Refusal) as caught:
            export.emit(document, shards[0], header_manifest)
        self.assertEqual(caught.exception.code, export.EX_REFUSED_OVERSIZE_SHARD)

        built = export.manifest(
            document,
            shards,
            parent_bytes=parent["bytes"],
            parent_path=parent["path"],
            limit=export.MAX_RESULTS + 1,
        )
        logs = [export.emit(document, shard, built) for shard in shards]
        oversize_manifest = export.manifest(
            document,
            shards,
            parent_bytes=parent["bytes"],
            parent_path=parent["path"],
            limit=export.MAX_RESULTS,
            shard_documents=logs,
        )
        with self.assertRaises(export.Refusal) as caught:
            export.verify(oversize_manifest, _verify_inputs(logs), parent)
        self.assertEqual(caught.exception.code, export.EX_REFUSED_OVERSIZE_SHARD)

    # ------------------------------------------------------------------
    # The real export.
    # ------------------------------------------------------------------

    def test_the_union_is_the_parent_once_each(self) -> None:
        identities = export.exact_identities(self.parent)
        union: list[str] = []
        for log in self.logs:
            union.extend(export.exact_identities(log))
        self.assertEqual(len(identities), 4245)
        self.assertEqual(sorted(identities), sorted(union))
        self.assertEqual(len(set(union)), len(union))
        self.assertTrue(self.manifest["union"]["equalsParent"])
        report = export.verify(self.manifest, _verify_inputs(self.logs), self.parent_input)
        self.assertEqual(report["union"], "complete")
        self.assertEqual(report["duplicates"], 0)

    def test_order_is_the_parent_order_restricted(self) -> None:
        parent_identities = export.exact_identities(self.parent)
        shard_identities: list[str] = []
        for log in self.logs:
            shard_identities.extend(export.exact_identities(log))
        self.assertEqual(shard_identities, parent_identities)

    def test_the_shard_keeps_the_tool_rules_and_artifacts(self) -> None:
        parent_runs = self.parent["runs"]
        for log in self.logs:
            for run in log["runs"]:
                record = run["properties"]["a1"]["record"]
                parent_run = next(
                    candidate
                    for candidate in parent_runs
                    if candidate["properties"]["a1"]["record"] == record
                )
                self.assertEqual(
                    export.tool_projection(run), export.tool_projection(parent_run)
                )
                parent_rules = {
                    rule["id"]: rule
                    for rule in parent_run["tool"]["driver"]["rules"]
                }
                used_rules = {result["ruleId"] for result in run["results"]}
                for rule in run["tool"]["driver"]["rules"]:
                    self.assertEqual(rule, parent_rules[rule["id"]])
                    self.assertIn(rule["id"], used_rules)
                self.assertEqual(
                    {rule["id"] for rule in run["tool"]["driver"]["rules"]},
                    used_rules,
                )
                parent_artifacts = {
                    artifact["location"]["uri"]: artifact
                    for artifact in parent_run.get("artifacts") or []
                }
                referenced: set[str] = set()
                for result in run["results"]:
                    referenced.update(export.referenced_uris(result))
                listed = {
                    artifact["location"]["uri"]
                    for artifact in run.get("artifacts") or []
                }
                self.assertEqual(listed, referenced)
                for artifact in run.get("artifacts") or []:
                    self.assertEqual(
                        artifact, parent_artifacts[artifact["location"]["uri"]]
                    )
                for result in run["results"]:
                    self.assertEqual(
                        run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"],
                        result["ruleId"],
                    )
                    for artifact_location in export._artifact_locations(result):
                        if "index" not in artifact_location:
                            continue
                        self.assertEqual(
                            run["artifacts"][artifact_location["index"]]["location"][
                                "uri"
                            ],
                            artifact_location["uri"],
                        )

    def test_no_shard_carries_a_census_property(self) -> None:
        for log in self.logs:
            self.assertEqual(export._census_properties(log.get("properties")), [])
            self.assertEqual(
                set(log["properties"]["shard"]),
                {
                    "index",
                    "total",
                    "parentDigest",
                    "parentResultCount",
                    "resultCount",
                    "candidate",
                },
            )

    def test_the_shard_is_self_contained_and_well_formed(self) -> None:
        for log in self.logs:
            self.assertEqual(log["version"], "2.1.0")
            self.assertEqual(log["$schema"], self.parent["$schema"])
            for run in log["runs"]:
                self.assertIn("name", run["tool"]["driver"])
                self.assertIn("rules", run["tool"]["driver"])
                self.assertIn("artifacts", run)
                for result in run["results"]:
                    self.assertIn("ruleId", result)
                    self.assertIn("message", result)
                    self.assertIn("level", result)
                    self.assertIn("a1Exact/v1", result["partialFingerprints"])

    # ------------------------------------------------------------------
    # Determinism and the committed evidence.
    # ------------------------------------------------------------------

    def test_emitted_bytes_are_deterministic(self) -> None:
        again = [export.serialize_sarif(export.emit(self.parent, shard, self.manifest)) for shard in self.shards]
        self.assertEqual(self.text, again)
        rebuilt = export.manifest(
            self.parent,
            self.shards,
            parent_bytes=self.parent_bytes,
            parent_path="evidence/a1/SARIF.json",
            limit=export.MAX_RESULTS,
        )
        self.assertEqual(export.dump_document(self.manifest), export.dump_document(rebuilt))

    def test_the_committed_shard_and_manifest_match_a_fresh_build(self) -> None:
        self.assertEqual(SHARD.read_text(encoding="utf-8"), self.text[0])
        self.assertEqual(
            MANIFEST.read_text(encoding="utf-8"), export.dump_document(self.manifest)
        )
        recorded = _load(MANIFEST)
        self.assertEqual(
            recorded["shards"][0]["sha256"],
            hashlib.sha256(SHARD.read_bytes()).hexdigest(),
        )
        self.assertEqual(recorded["parent"]["sha256"], hashlib.sha256(self.parent_bytes).hexdigest())

    # ------------------------------------------------------------------
    # Every refusal code, one control each.
    # ------------------------------------------------------------------

    def test_every_control_fires_its_named_code(self) -> None:
        controls = export.build_controls(self.parent, self.parent_bytes)
        self.assertEqual(len(controls), len(export.REFUSALS))
        self.assertEqual({control["code"] for control in controls}, set(export.REFUSALS))
        for control in controls:
            with self.subTest(control=control["control"]):
                self.assertEqual(control["observed"], control["code"])

    def test_the_recorded_controls_are_current(self) -> None:
        recorded = _load(CONTROLS)
        self.assertEqual(recorded["schema"], export.CONTROLS_SCHEMA)
        self.assertEqual(len(recorded["controls"]), len(export.REFUSALS))
        self.assertEqual(
            {control["code"] for control in recorded["controls"]}, set(export.REFUSALS)
        )
        self.assertEqual(recorded["realModule"], "no network client, no credential read, no upload")

    # ------------------------------------------------------------------
    # The structural no-dependency rule.
    # ------------------------------------------------------------------

    def test_the_module_imports_no_network_client(self) -> None:
        tree = ast.parse(TOOL.read_text(encoding="utf-8"))
        roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                roots.add((node.module or "").split(".")[0])
        self.assertEqual(roots & export.FORBIDDEN_MODULES, set())

    def test_the_module_reads_no_credential(self) -> None:
        source = TOOL.read_text(encoding="utf-8")
        self.assertEqual(export.network_dependency_findings(source), [])
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id == "os":
                    self.fail(f"the export module touches os.{node.attr}")

    def test_a_network_import_is_refused_structurally(self) -> None:
        findings = export.network_dependency_findings(
            "import urllib.request\nimport os\nTOKEN = os.environ['GITHUB_TOKEN']\n"
        )
        self.assertTrue(findings)
        self.assertEqual({finding["code"] for finding in findings},
                         {export.EX_REFUSED_NETWORK_OR_CREDENTIAL})
        self.assertEqual({finding["kind"] for finding in findings}, {"import", "credential"})

    # ------------------------------------------------------------------
    # The command line.
    # ------------------------------------------------------------------

    def test_cli_plan_reports_the_plan(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "plan"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("shards=1", result.stdout)
        self.assertIn("results=4245", result.stdout)

    def test_cli_verify_accepts_the_committed_export(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "verify", str(A8)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("union=complete", result.stdout)
        self.assertIn("results=4245", result.stdout)

    def test_cli_refusal_prints_the_code(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "plan", "--parent", "evidence/a8/absent.sarif"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(export.EX_REFUSED_PARENT_SHAPE, result.stderr)

    def test_cli_verify_refuses_a_directory_without_a_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(TOOL), "verify", directory],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn(export.EX_REFUSED_MANIFEST_ABSENT, result.stderr)

    def test_cli_usage_errors_exit_two(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "plan", "--limit", "0"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 2)
        no_command = subprocess.run(
            [sys.executable, str(TOOL)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(no_command.returncode, 2)

    def test_emit_refuses_a_non_empty_directory_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "export"
            output.mkdir()
            (output / "existing.txt").write_text("not this export\n", encoding="utf-8")
            refused = subprocess.run(
                [sys.executable, str(TOOL), "emit", str(output)],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
            self.assertEqual(refused.returncode, 1)
            self.assertIn(export.EX_REFUSED_OUTPUT_NOT_EMPTY, refused.stderr)
            self.assertEqual(
                (output / "existing.txt").read_text(encoding="utf-8"),
                "not this export\n",
            )

    # ------------------------------------------------------------------
    # Document synchronisation.
    # ------------------------------------------------------------------

    @classmethod
    def setUpDocument(cls) -> str:
        return DOCUMENT.read_text(encoding="utf-8") if DOCUMENT.is_file() else ""

    def test_the_document_names_every_refusal_code(self) -> None:
        text = self.setUpDocument()
        for code in export.REFUSALS:
            with self.subTest(code=code):
                self.assertIn(code, text)

    def test_the_document_names_every_control(self) -> None:
        text = self.setUpDocument()
        for control in export.build_controls(self.parent, self.parent_bytes):
            with self.subTest(control=control["control"]):
                self.assertIn(control["control"], text)

    def test_the_document_matches_the_manifest(self) -> None:
        text = self.setUpDocument()
        manifest = _load(MANIFEST)
        self.assertIn(f"{manifest['parent']['resultCount']:,}", text)
        self.assertIn(manifest["parent"]["sha256"], text)
        self.assertIn(manifest["shards"][0]["sha256"], text)
        self.assertIn(f"{manifest['shards'][0]['bytes']:,}", text)
        self.assertIn(manifest["candidate"]["token"], text)
        self.assertIn(export.TOOL_PATH, text)
        self.assertIn(str(export.MAX_RESULTS), text)

    def test_the_recorded_plan_proves_the_boundary(self) -> None:
        plan = _load(PLAN)
        self.assertEqual(plan["limit"], export.MAX_RESULTS)
        self.assertEqual(plan["real"]["shardCount"], 1)
        self.assertEqual(plan["real"]["resultCount"], 4245)
        self.assertEqual(plan["synthetic"]["resultCount"], 12001)
        self.assertEqual(plan["synthetic"]["shardCount"], 3)
        self.assertEqual(
            [row["first"] for row in plan["synthetic"]["boundaries"]], [0, 5000, 10000]
        )
        self.assertEqual(
            [row["count"] for row in plan["synthetic"]["boundaries"]], [5000, 5000, 2001]
        )
        self.assertEqual(
            plan["real"]["boundaries"][0]["results"], list(range(4245))
        )

    def test_the_producer_is_recorded(self) -> None:
        self.assertTrue(PRODUCER.is_file())
        self.assertTrue(TOOL.is_file())
        manifest = _load(MANIFEST)
        self.assertEqual(manifest["tool"]["sha256"], hashlib.sha256(TOOL.read_bytes()).hexdigest())
        self.assertEqual(manifest["tool"]["dependency"],
                         "none: no API client, no network call, no token, no upload")


if __name__ == "__main__":
    unittest.main()
