#!/usr/bin/env python3
"""Controls for forensics/tools/key_lifecycle.py and the A18 records.

One control per refusal code; each rollback role individually; a rotation signed
by the new root only; a revoked key whose signature verifies; the freeze
interval at exactly the boundary and one second past it; the targets/snapshot
hash chain; the stale-release rule in both its forms; ``NOT_RUN`` for an absent
repository; determinism; the command line with printed codes; and document
synchronisation.

Run directly (`python3 forensics/tools/tests/test_key_lifecycle.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics/tools"
sys.path.insert(0, str(TOOLS))

import key_lifecycle as kl  # noqa: E402

EVIDENCE = REPO / "evidence/a18"
BUILDER = EVIDENCE / "build_evidence.py"
DOCUMENT = REPO / "docs/KEY-LIFECYCLE.md"
FULL_COMMIT = "2e8e9aa65ba60321c18f54890aa73caa200f5bd7"
NOW = "2026-11-24T00:00:00Z"
INTERVAL = 7 * 24 * 60 * 60
NAMES = ("INVENTORY.json", "EVALUATION.json", "CONTROLS.json")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_builder() -> Any:
    spec = importlib.util.spec_from_file_location("a18_builder", BUILDER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def previous() -> dict[str, Any]:
    return load_builder().healthy_repository(1, "old")


def healthy() -> dict[str, Any]:
    return load_builder().healthy_repository(2, "rotate")


def evaluate(repository: Any, prior: Any = None) -> dict[str, Any]:
    return kl.evaluate(repository, NOW, prior)


def sign(record: dict[str, Any], keyids: list[str]) -> dict[str, Any]:
    return kl._sign(record, keyids)


class ControlCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controls = load_json(EVIDENCE / "CONTROLS.json")

    def test_every_refusal_code_has_a_control(self) -> None:
        covered = {control["code"] for control in self.controls["controls"]}
        self.assertEqual(covered, set(kl.CODE_ORDER))

    def test_every_control_observed_its_own_code(self) -> None:
        for control in self.controls["controls"]:
            self.assertTrue(control["controlOnly"], control["id"])
            self.assertEqual(
                control["observed"]["outcome"], kl.OUTCOME_REFUSED, control["id"]
            )
            self.assertEqual(
                control["observed"]["code"], control["code"], control["id"]
            )

    def test_the_counts_are_the_recorded_ones(self) -> None:
        self.assertEqual(self.controls["coverage"]["refusalCodes"], 21)
        self.assertEqual(self.controls["coverage"]["controls"], 22)

    def test_the_positive_control_is_accepted(self) -> None:
        observed = self.controls["positive"]["observed"]
        self.assertEqual(observed["outcome"], kl.OUTCOME_ACCEPTED)
        self.assertEqual(observed["code"], kl.CODE_OK)
        self.assertEqual(observed["accepted"]["targetsVersion"], 2)


class Rollback(unittest.TestCase):
    def test_root_rollback(self) -> None:
        prior = load_builder().healthy_repository(2, "new")
        offered = load_builder().healthy_repository(2, "new")
        result = evaluate(offered, prior)
        self.assertEqual(result["code"], kl.TK_REFUSED_ROOT_ROLLBACK)

    def test_each_rollback_role_individually(self) -> None:
        builder = load_builder()
        cases = {
            kl.ROLE_TARGETS: kl.TK_REFUSED_TARGETS_ROLLBACK,
            kl.ROLE_SNAPSHOT: kl.TK_REFUSED_SNAPSHOT_ROLLBACK,
            kl.ROLE_TIMESTAMP: kl.TK_REFUSED_TIMESTAMP_ROLLBACK,
        }
        prior = builder.healthy_repository(2, "new")
        for role, code in cases.items():
            repository = builder.healthy_repository(3, "new")
            repository["metadata"][role]["version"] = 1
            builder.rebuild_chain(repository)
            result = evaluate(repository, prior)
            self.assertEqual(result["code"], code, role)
            self.assertEqual(result["roles"][role]["outcome"], kl.OUTCOME_REFUSED)


class Rotation(unittest.TestCase):
    def test_rotation_signed_by_new_root_only_is_refused(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        sign(
            repository["metadata"][kl.ROLE_ROOT],
            [builder.K_ROOT_NEW_A, builder.K_ROOT_NEW_B],
        )
        result = evaluate(repository, previous())
        self.assertEqual(
            result["code"], kl.TK_REFUSED_ROOT_ROTATION_UNSIGNED_BY_OLD
        )

    def test_rotation_by_both_sides_is_accepted(self) -> None:
        result = evaluate(healthy(), previous())
        self.assertEqual(result["outcome"], kl.OUTCOME_ACCEPTED, result["detail"])
        self.assertEqual(result["code"], kl.CODE_OK)

    def test_old_root_threshold_is_required(self) -> None:
        builder = load_builder()
        prior = builder.healthy_repository(1, "old")
        prior["metadata"][kl.ROLE_ROOT]["threshold"] = 2
        result = evaluate(builder.healthy_repository(2, "rotate"), prior)
        self.assertEqual(
            result["code"], kl.TK_REFUSED_ROOT_ROTATION_UNSIGNED_BY_OLD
        )


class HashChain(unittest.TestCase):
    def test_targets_hash_mismatch(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        snapshot = repository["metadata"][kl.ROLE_SNAPSHOT]
        snapshot["targets"]["sha256"] = "0" * 64
        sign(snapshot, [builder.K_SNAPSHOT])
        timestamp = repository["metadata"][kl.ROLE_TIMESTAMP]
        timestamp["snapshot"] = {
            "version": snapshot["version"],
            "sha256": kl.metadata_digest(snapshot),
        }
        sign(timestamp, [builder.K_TIMESTAMP])
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_TARGETS_HASH_MISMATCH)

    def test_snapshot_hash_mismatch(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        timestamp = repository["metadata"][kl.ROLE_TIMESTAMP]
        timestamp["snapshot"]["sha256"] = "0" * 64
        sign(timestamp, [builder.K_TIMESTAMP])
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_SNAPSHOT_HASH_MISMATCH)


class ExpiryAndFreeze(unittest.TestCase):
    def test_expired_metadata(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        repository["metadata"][kl.ROLE_TIMESTAMP]["expires"] = "2026-11-23T00:00:00Z"
        builder.rebuild_chain(repository)
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_EXPIRED_METADATA)

    def test_freeze_exactly_at_the_interval_is_accepted(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(
            2, "rotate", issued_at="2026-11-17T00:00:00Z"
        )
        result = evaluate(repository, previous())
        self.assertEqual(result["outcome"], kl.OUTCOME_ACCEPTED, result["detail"])
        self.assertEqual(result["code"], kl.CODE_OK)

    def test_freeze_one_unit_past_the_interval_is_refused(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(
            2, "rotate", issued_at="2026-11-16T23:59:59Z"
        )
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_FREEZE)
        # The repository declares exactly the interval this test assumes.
        self.assertEqual(repository["maxTimestampInterval"], INTERVAL)


class Keys(unittest.TestCase):
    def test_revoked_key_with_a_verifying_signature(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        targets = repository["metadata"][kl.ROLE_TARGETS]
        targets["keys"] = [
            builder.key(
                builder.K_TARGETS_REVOKED,
                kl.ROLE_TARGETS,
                revoked_at=builder.REVOKED,
            )
        ]
        sign(targets, [builder.K_TARGETS_REVOKED])
        builder.rebuild_chain(repository)
        self.assertEqual(
            targets["signatures"][0]["sig"],
            kl.signature_value(targets, builder.K_TARGETS_REVOKED),
            "the signature must verify before revocation is the reason",
        )
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_KEY_REVOKED)

    def test_expired_key(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        targets = repository["metadata"][kl.ROLE_TARGETS]
        targets["keys"] = [
            builder.key(
                builder.K_TARGETS_EXPIRED,
                kl.ROLE_TARGETS,
                not_after="2026-06-01T00:00:00Z",
            )
        ]
        sign(targets, [builder.K_TARGETS_EXPIRED])
        builder.rebuild_chain(repository)
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_KEY_EXPIRED)

    def test_key_not_yet_valid(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        targets = repository["metadata"][kl.ROLE_TARGETS]
        targets["keys"] = [
            builder.key(
                builder.K_TARGETS_FUTURE,
                kl.ROLE_TARGETS,
                not_before="2027-06-01T00:00:00Z",
                not_after="2028-01-01T00:00:00Z",
            )
        ]
        sign(targets, [builder.K_TARGETS_FUTURE])
        builder.rebuild_chain(repository)
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_KEY_NOT_YET_VALID)

    def test_unknown_key(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        targets = repository["metadata"][kl.ROLE_TARGETS]
        targets["signatures"] = [
            {"keyid": "control-only:not-a-key", "sig": "sha256:" + "0" * 64}
        ]
        builder.rebuild_chain(repository)
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_UNKNOWN_KEY)

    def test_role_key_mismatch(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        targets = repository["metadata"][kl.ROLE_TARGETS]
        targets["keys"] = [builder.key(builder.K_WRONG_ROLE, kl.ROLE_TIMESTAMP)]
        sign(targets, [builder.K_WRONG_ROLE])
        builder.rebuild_chain(repository)
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_ROLE_KEY_MISMATCH)

    def test_metadata_threshold(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        repository["metadata"][kl.ROLE_TARGETS]["threshold"] = 2
        builder.rebuild_chain(repository)
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_METADATA_THRESHOLD)


class Delegations(unittest.TestCase):
    def test_delegation_unknown(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        repository["delegations"] = []
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_DELEGATION_UNKNOWN)

    def test_delegation_expired(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        repository["delegations"][0]["expires"] = "2026-11-23T00:00:00Z"
        builder.rebuild_chain(repository)
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_DELEGATION_EXPIRED)

    def test_delegation_hash_mismatch(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        targets = repository["metadata"][kl.ROLE_TARGETS]
        targets["delegations"][0]["sha256"] = "0" * 64
        sign(targets, [builder.K_TARGETS])
        builder.reseal_from_targets(repository)
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_DELEGATION_HASH_MISMATCH)


class Releases(unittest.TestCase):
    def test_stale_release_by_version(self) -> None:
        builder = load_builder()
        prior = builder.healthy_repository(2, "new")
        repository = builder.healthy_repository(3, "new")
        repository["releases"][0]["version"] = 2
        result = evaluate(repository, prior)
        self.assertEqual(result["code"], kl.TK_REFUSED_STALE_RELEASE)

    def test_stale_release_by_revoked_key(self) -> None:
        builder = load_builder()
        prior = builder.healthy_repository(2, "new")
        repository = builder.healthy_repository(3, "new")
        repository["releases"][0]["keyid"] = builder.K_RELEASE_REVOKED
        result = evaluate(repository, prior)
        self.assertEqual(result["code"], kl.TK_REFUSED_STALE_RELEASE)

    def test_a_release_at_the_accepted_version_is_not_stale(self) -> None:
        result = evaluate(healthy(), previous())
        self.assertEqual(result["outcome"], kl.OUTCOME_ACCEPTED)
        self.assertEqual(result["accepted"]["releases"], ["control-only:release"])


class Signature(unittest.TestCase):
    def test_signature_not_over_the_bytes(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        targets = repository["metadata"][kl.ROLE_TARGETS]
        targets["signatures"][0]["sig"] = "sha256:" + "0" * 64
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_SIGNATURE)

    def test_root_signature_not_over_the_bytes(self) -> None:
        builder = load_builder()
        repository = builder.healthy_repository(2, "rotate")
        root = repository["metadata"][kl.ROLE_ROOT]
        root["signatures"][0]["sig"] = "sha256:" + "0" * 64
        result = evaluate(repository, previous())
        self.assertEqual(result["code"], kl.TK_REFUSED_SIGNATURE)


class NotRun(unittest.TestCase):
    def test_absent_repository_is_not_run(self) -> None:
        result = kl.evaluate(None, NOW, None)
        self.assertEqual(result["outcome"], kl.OUTCOME_NOT_RUN)
        self.assertEqual(result["code"], kl.CODE_NOT_RUN)
        for role, status in result["roles"].items():
            self.assertEqual(status["outcome"], kl.OUTCOME_NOT_RUN, role)
            self.assertEqual(status["code"], kl.CODE_NOT_RUN, role)
        self.assertEqual(result["staleRelease"]["outcome"], kl.OUTCOME_NOT_RUN)
        self.assertEqual(result["staleRelease"]["code"], kl.CODE_NOT_RUN)

    def test_not_run_is_never_accepted(self) -> None:
        result = kl.evaluate(None, NOW, None)
        self.assertNotEqual(result["outcome"], kl.OUTCOME_ACCEPTED)

    def test_evaluate_requires_a_time(self) -> None:
        with self.assertRaises(kl.ToolError):
            kl.evaluate(None, None, None)


class Determinism(unittest.TestCase):
    def test_two_runs_are_byte_identical_and_match_committed(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for out in (first, second):
                run = subprocess.run(
                    [sys.executable, str(BUILDER), "--out", out],
                    cwd=str(REPO), text=True, capture_output=True, timeout=120,
                )
                self.assertEqual(run.returncode, 0, run.stderr)
            for name in NAMES:
                left = (Path(first) / name).read_bytes()
                right = (Path(second) / name).read_bytes()
                self.assertEqual(left, right, name)
                self.assertEqual(left, (EVIDENCE / name).read_bytes(), name)

    def test_build_is_deterministic_in_process(self) -> None:
        builder = load_builder()
        first = builder.build()
        second = builder.build()
        for name, document, other in zip(NAMES, first, second):
            rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
            rendered_again = json.dumps(other, indent=2, sort_keys=True) + "\n"
            self.assertEqual(rendered, rendered_again, name)
            self.assertEqual(rendered.encode(), (EVIDENCE / name).read_bytes(), name)


class CommandLine(unittest.TestCase):
    def run_tool(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(TOOLS / "key_lifecycle.py"), *args],
            cwd=str(REPO), text=True, capture_output=True, timeout=120,
        )

    def write_repository(self, directory: Path, name: str, document: Any) -> str:
        path = directory / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return str(path)

    def test_accepted_repository_exits_zero_and_prints_tk_ok(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self.write_repository(root, "repo.json", healthy())
            prior = self.write_repository(root, "previous.json", previous())
            run = self.run_tool(
                "evaluate", repository, "--now", NOW, "--previous", prior
            )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("outcome=ACCEPTED", run.stdout)
        self.assertIn("code=TK_OK", run.stdout)

    def test_refused_repository_exits_one_and_prints_the_code(self) -> None:
        builder = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prior = builder.healthy_repository(2, "new")
            repository = builder.healthy_repository(3, "new")
            repository["releases"][0]["version"] = 2
            path = self.write_repository(root, "repo.json", repository)
            prior_path = self.write_repository(root, "previous.json", prior)
            run = self.run_tool(
                "evaluate", path, "--now", NOW, "--previous", prior_path
            )
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("outcome=REFUSED", run.stdout)
        self.assertIn("TK_REFUSED_STALE_RELEASE", run.stdout)

    def test_absent_repository_exits_one_with_not_run(self) -> None:
        run = self.run_tool(
            "evaluate", "/tmp/a18-no-such-repository.json", "--now", NOW
        )
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("outcome=NOT_RUN", run.stdout)
        self.assertIn("code=TK_NOT_RUN", run.stdout)

    def test_inventory_exits_zero_and_reports_zero_repositories(self) -> None:
        run = self.run_tool("inventory")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("keys=1", run.stdout)
        self.assertIn("repositories=0", run.stdout)
        self.assertIn("singlePointOfCompromise=True", run.stdout)

    def test_explain_prints_condition_and_prevention(self) -> None:
        run = self.run_tool("explain", kl.TK_REFUSED_FREEZE)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("code=TK_REFUSED_FREEZE", run.stdout)
        self.assertIn("condition:", run.stdout)
        self.assertIn("prevents:", run.stdout)

    def test_explain_unknown_code_is_exit_two(self) -> None:
        run = self.run_tool("explain", "TK_REFUSED_NOT_A_CODE")
        self.assertEqual(run.returncode, 2)

    def test_usage_error_is_exit_two(self) -> None:
        run = self.run_tool("inventory", "--not-an-option")
        self.assertEqual(run.returncode, 2)


class DocumentSynchronisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8")
        cls.flat = " ".join(cls.text.split())

    def test_every_refusal_code_is_documented(self) -> None:
        for code in kl.CODE_ORDER:
            self.assertIn(code, self.text, code)

    def test_every_enforced_by_names_a_code_or_test(self) -> None:
        markers = ("TK_REFUSED_", "test_", "`key_lifecycle.py`", "`build_evidence.py`")
        for line in self.text.splitlines():
            if "Enforced by" in line:
                self.assertTrue(
                    any(marker in line for marker in markers),
                    f"enforcement line names no code or test: {line!r}",
                )

    def test_the_document_states_the_real_result(self) -> None:
        self.assertIn("0 repositories", self.flat)
        self.assertIn("nothing accepted", self.flat)
        self.assertIn("single point of compromise", self.flat)
        self.assertIn("indistinguishable", self.flat)

    def test_the_document_names_every_control(self) -> None:
        controls = load_json(EVIDENCE / "CONTROLS.json")
        for control in controls["controls"]:
            self.assertIn(control["id"], self.text, control["id"])
        self.assertIn(controls["positive"]["id"], self.text)

    def test_the_document_has_a_not_run_section(self) -> None:
        self.assertIn("## `NOT_RUN`", self.text)

    def test_the_document_names_the_tool_and_producer(self) -> None:
        self.assertIn("forensics/tools/key_lifecycle.py", self.text)
        self.assertIn("evidence/a18/build_evidence.py", self.text)


class JsonRecords(unittest.TestCase):
    def test_every_record_parses_and_is_bound(self) -> None:
        schemas = {
            "INVENTORY.json": kl.INVENTORY_SCHEMA,
            "EVALUATION.json": kl.EVALUATION_SCHEMA,
            "CONTROLS.json": kl.CONTROLS_SCHEMA,
        }
        for name, schema in schemas.items():
            document = load_json(EVIDENCE / name)
            self.assertEqual(document["schema"], schema, name)
            self.assertEqual(document["sourceIdentity"]["baseCommit"], FULL_COMMIT, name)
            self.assertTrue(document["sourceIdentity"]["tool"]["sha256"], name)

    def test_the_inventory_records_the_single_key(self) -> None:
        document = load_json(EVIDENCE / "INVENTORY.json")
        self.assertEqual(document["keyCount"], 1)
        self.assertEqual(document["repositories"], 0)
        self.assertEqual(document["metadataVersions"], 0)
        self.assertEqual(document["revocationRecords"], 0)
        self.assertEqual(document["expiryRecords"], 0)
        self.assertEqual(document["delegations"], 0)
        self.assertTrue(document["singlePointOfCompromise"])
        self.assertFalse(document["detectable"])
        self.assertFalse(document["recoverable"])
        self.assertTrue(document["beforeAfterIndistinguishable"])
        key = document["keys"][0]
        self.assertTrue(key["symmetric"])
        self.assertIsNone(key["expires"])
        self.assertIsNone(key["revocationRecord"])
        self.assertIsNone(key["metadataVersion"])
        self.assertIsNone(key["delegation"])

    def test_the_evaluation_records_every_role_not_run(self) -> None:
        document = load_json(EVIDENCE / "EVALUATION.json")
        self.assertEqual(document["outcome"], kl.OUTCOME_NOT_RUN)
        self.assertEqual(document["code"], kl.CODE_NOT_RUN)
        self.assertFalse(document["repositoryPresent"])
        self.assertEqual(set(document["roles"]), set(kl.ROLES))
        for role, status in document["roles"].items():
            self.assertEqual(status["outcome"], kl.OUTCOME_NOT_RUN, role)
        self.assertEqual(document["staleRelease"]["outcome"], kl.OUTCOME_NOT_RUN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
