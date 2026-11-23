#!/usr/bin/env python3
"""Controls for forensics/tools/scheduling.py (ETP-T11).

Run directly (`python3 forensics/tools/tests/test_scheduling.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.

Each control changes exactly one thing and asserts the policy's response:

  1. the tier is derived per change class, and the maximum wins over a mixed set;
  2. the exported ABI and a SAFE_COMPATIBLE assertion reach `SEAL`, while a
     claim-document edit that does not touch graduation stays at `FAST`;
  3. an empty change set and an unresolvable range are refused, not scheduled;
  4. every rule in the table is reachable, and every declared shared mechanism
     exists in the repository;
  5. an identical identity is reused, and a changed tool version, population,
     profile, instrument configuration or source commit is recomputed;
  6. an incomplete identity never reuses, at the cache or at the declaration;
  7. an incomplete or tampered cache entry is refused rather than read;
  8. a simulated memory exhaustion is `BLOCKED` with the bound and the observed
     value, and `PASS` after exceeding a bound is refused;
  9. a `NOT_RUN` never produces a passing aggregate, and a `BLOCKED` row is
     visible in the aggregate even when every other check is satisfied;
 10. the same inputs produce byte-identical output.
"""

from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import scheduling  # noqa: E402

COMMIT = "a" * 40
COMMIT_B = "b" * 40
TREE = "c" * 40
TOOL_SHA = "d" * 64


def identity(
    commit: str = COMMIT,
    tool_sha: str = TOOL_SHA,
    profile: str = "debug",
    instrument_config: dict[str, Any] | None = None,
    population: list[str] | None = None,
) -> dict[str, Any]:
    return scheduling.build_identity(
        commit=commit,
        tree=TREE,
        tool_paths=[{"path": "forensics/tools/scheduling.py", "sha256": tool_sha}],
        instrument_name="python3-stdlib-unittest",
        instrument_config={"kind": "unittest"} if instrument_config is None else instrument_config,
        profile=profile,
        triple="x86_64-unknown-linux-gnu",
        features=[],
        population=["test_reuse", "test_refusal"] if population is None else population,
    )


def resources(memory: tuple[float, float] = (6144, 41), time: tuple[float, float] = (900, 12.5), disk: tuple[float, float] = (4096, 3)) -> dict[str, Any]:
    return {
        "memory_mib": {"bound": memory[0], "observed": memory[1]},
        "time_s": {"bound": time[0], "observed": time[1]},
        "disk_mib": {"bound": disk[0], "observed": disk[1]},
    }


def run_main(argv: list[str]) -> tuple[int, dict[str, Any]]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = scheduling.main(argv)
    text = buffer.getvalue().strip()
    try:
        return code, json.loads(text) if text else {}
    except json.JSONDecodeError:
        return code, {"raw": text}


class Fixture:
    """A throwaway repository with a small tree and two commits."""

    files = {
        "Cargo.toml": "[package]\nname = \"fixture\"\n",
        "src/unit.rs": "pub fn f() -> u8 {\n    1\n}\n",
        "docs/NOTES.md": "notes\n",
        "evidence/etp/claims.json": "{\n  \"claims\": []\n}\n",
    }

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "repo"
        self.root.mkdir(parents=True)
        self.git = scheduling.freshness.Git(self.root)
        self._run("init", "-q", "-b", "main")
        for relpath, text in self.files.items():
            self.write(relpath, text)
        self.base = self.commit("base")
        self.write("src/unit.rs", "pub fn f() -> u8 {\n    2\n}\n")
        self.head = self.commit("change")

    def close(self) -> None:
        self._tmp.cleanup()

    def _run(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                "git",
                "-c",
                "user.name=etp-t11",
                "-c",
                "user.email=etp-t11@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-C",
                str(self.root),
                *args,
            ],
            capture_output=True,
            check=False,
        )

    def write(self, relpath: str, text: str) -> None:
        path = self.root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def commit(self, message: str) -> str:
        self._run("add", "-A")
        self._run("commit", "-q", "-m", message)
        return self.git.head() or ""


# ---------------------------------------------------------------------------
# 1-4: the rule table
# ---------------------------------------------------------------------------


class RuleTable(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = Fixture()

    def tearDown(self) -> None:
        self.fx.close()

    def tier_of(self, *paths: str, base: str | None = None, head: str | None = None) -> dict[str, Any]:
        argv = ["tier", "--repo", str(self.fx.root)]
        for path in paths:
            argv.extend(["--paths", path])
        if base and head:
            argv = ["tier", "--repo", str(self.fx.root), "--base", base, "--head", head]
        code, payload = run_main(argv)
        self.assertEqual(code, 0, payload)
        return payload

    def test_each_rule_is_reachable(self) -> None:
        samples = {
            "SC_RULE_EXPORTED_ABI": ["artifacts/phase2/libcrypto.ld"],
            "SC_RULE_GRADUATION_CLAIM": ["evidence/etp/claims.json"],
            "SC_RULE_SHARED_MECHANISM": ["src/runtime/stack.rs", "src/ffi/callbacks.rs"],
            "SC_RULE_INSTRUMENT": ["evidence/etp3/instruments.json"],
            "SC_RULE_INDEPENDENCE": ["evidence/etp-t6/TCB.json"],
            "SC_RULE_VENUE": ["docker/openssl-rs-court.sh"],
            "SC_RULE_BUILD_INPUT": ["Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml"],
            "SC_RULE_TOOL": ["forensics/tools/freshness.py", "courts/phase18/interop/manifest.py"],
            "SC_RULE_SOURCE": ["src/aes.rs"],
            "SC_RULE_UNCLASSIFIED": ["Makefile.ci"],
            "SC_RULE_EVIDENCE_ONLY": ["evidence/etp0/RECEIPT.md"],
            "SC_RULE_DOCS": ["docs/ETP-TODO.md"],
        }
        self.assertEqual(set(samples), {rule.id for rule in scheduling.RULES})
        for rule_id, paths in samples.items():
            for path in paths:
                with self.subTest(rule=rule_id, path=path):
                    payload = self.tier_of(path)
                    rules = {group["rule"] for group in payload["by_class"]}
                    self.assertIn(rule_id, rules, payload)
                    self.assertEqual(payload["tier"], scheduling.RULE_BY_ID[rule_id].tier)

    def test_maximum_wins_over_a_mixed_change_set(self) -> None:
        docs_only = self.tier_of("docs/ETP-TODO.md", "evidence/etp0/RECEIPT.md")
        self.assertEqual(docs_only["tier"], "FAST")
        with_source = self.tier_of("docs/ETP-TODO.md", "src/aes.rs")
        self.assertEqual(with_source["tier"], "BATCH")
        with_mechanism = self.tier_of("docs/ETP-TODO.md", "src/unit.rs", "src/runtime/stack.rs")
        self.assertEqual(with_mechanism["tier"], "BOUNDARY")
        with_abi = self.tier_of("docs/ETP-TODO.md", "src/unit.rs", "artifacts/phase2/libcrypto.ld")
        self.assertEqual(with_abi["tier"], "SEAL")
        self.assertIn("SC_RULE_EXPORTED_ABI", {group["rule"] for group in with_abi["by_class"]})

    def test_external_is_never_derived_from_a_change_set(self) -> None:
        for path in ("src/aes.rs", "artifacts/phase2/libcrypto.ld", "docs/ETP-TODO.md"):
            self.assertNotEqual(self.tier_of(path)["tier"], "EXTERNAL")
        self.assertEqual(scheduling.required_checks("EXTERNAL")[-1]["from_tier"], "EXTERNAL")

    def test_a_graduation_assertion_reaches_seal_and_an_ordinary_claim_edit_does_not(self) -> None:
        claims = self.fx.root / "evidence" / "etp" / "claims.json"
        asserted = {
            "claims": [
                {
                    "id": "C1",
                    "note": "first",
                    "verdict": {"state": "SAFE_COMPATIBLE"},
                }
            ]
        }
        claims.write_text(json.dumps(asserted, indent=2) + "\n", encoding="utf-8")
        graduation = self.fx.commit("assert a graduation")
        code, payload = run_main(
            ["tier", "--repo", str(self.fx.root), "--base", self.fx.head, "--head", graduation]
        )
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["tier"], "SEAL")
        self.assertEqual(payload["rule"], "SC_RULE_GRADUATION_CLAIM")

        asserted["claims"][0]["note"] = "second"
        claims.write_text(json.dumps(asserted, indent=2) + "\n", encoding="utf-8")
        reworded = self.fx.commit("reword a claim")
        code, payload = run_main(["tier", "--repo", str(self.fx.root), "--base", graduation, "--head", reworded])
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["tier"], "FAST")
        self.assertEqual(payload["rule"], "SC_RULE_EVIDENCE_ONLY")

    def test_an_added_claim_document_is_conservatively_seal(self) -> None:
        path = self.fx.root / "evidence" / "etp" / "claims.json"
        path.unlink()
        removed = self.fx.commit("remove the claim document")
        code, payload = run_main(["tier", "--repo", str(self.fx.root), "--base", self.fx.head, "--head", removed])
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["tier"], "SEAL")

    def test_the_range_derives_the_same_tier_as_the_path_list(self) -> None:
        by_range = self.tier_of(base=self.fx.base, head=self.fx.head)
        self.assertEqual(by_range["tier"], "BATCH")
        self.assertEqual(by_range["count"], 1)
        self.assertEqual(by_range["deciding_paths"], ["src/unit.rs"])

    def test_an_empty_change_set_is_refused(self) -> None:
        code, payload = run_main(
            ["tier", "--repo", str(self.fx.root), "--base", self.fx.head, "--head", self.fx.head]
        )
        self.assertEqual(code, 2)
        self.assertEqual(payload["status"], "REFUSED")
        self.assertEqual(payload["rule"], "SC_EMPTY_CHANGE_SET")

    def test_an_unresolvable_range_is_refused(self) -> None:
        code, payload = run_main(
            ["tier", "--repo", str(self.fx.root), "--base", "0" * 40, "--head", self.fx.head]
        )
        self.assertEqual(code, 2)
        self.assertEqual(payload["rule"], "SC_RANGE_UNRESOLVED")

    def test_declared_shared_mechanisms_exist_in_the_repository(self) -> None:
        root = Path(scheduling.REPO_ROOT)
        missing = [path for path in scheduling.SHARED_MECHANISMS if not (root / path).exists()]
        self.assertEqual(missing, [], "a stale mechanism declaration schedules nothing")
        self.assertTrue((root / scheduling.EXPORTED_ABI).exists())
        self.assertTrue((root / scheduling.CLAIMS_DOCUMENT).exists())

    def test_requirements_accumulate(self) -> None:
        fast = [row["check"] for row in scheduling.required_checks("FAST")]
        batch = [row["check"] for row in scheduling.required_checks("BATCH")]
        boundary = [row["check"] for row in scheduling.required_checks("BOUNDARY")]
        seal = [row["check"] for row in scheduling.required_checks("SEAL")]
        self.assertTrue(set(fast) < set(batch) < set(boundary) < set(seal))
        self.assertIn("BATCH_AFFECTED_COURTS", batch)
        self.assertIn("BOUNDARY_REVIEWER_INDEPENDENCE", boundary)
        self.assertIn("SEAL_HELD_OUT_COMPAT", seal)


# ---------------------------------------------------------------------------
# 5-7: identity and the content-addressed cache
# ---------------------------------------------------------------------------


class CacheControls(unittest.TestCase):
    def setUp(self) -> None:
        self.store = scheduling.empty_store()

    def put(self, ident: dict[str, Any], check: str = "FAST_FMT", result: str = "PASS", **kwargs: Any) -> dict[str, Any]:
        return scheduling.cache_put(
            self.store,
            check,
            ident,
            result,
            kwargs.pop("resources", resources()),
            kwargs.pop("evidence", ["evidence/etp-t11/RECEIPT.md"]),
            kwargs.pop("provenance", "run"),
            kwargs.pop("note", None),
        )

    def test_identical_identity_reuses(self) -> None:
        ident = identity()
        self.put(ident)
        hit = scheduling.cache_get(self.store, "FAST_FMT", identity())
        self.assertEqual(hit.kind, "HIT")
        self.assertEqual(hit.entry["result"], "PASS")

    def test_each_identity_field_change_recomputes(self) -> None:
        self.put(identity())
        changes = {
            "tool": identity(tool_sha="e" * 64),
            "population": identity(population=["test_reuse"]),
            "profile": identity(profile="release"),
            "instrument": identity(instrument_config={"kind": "unittest", "trace": True}),
            "source": identity(commit=COMMIT_B),
        }
        self.assertEqual(len({scheduling.identity_digest(value) for value in changes.values()}), 5)
        for field, changed in changes.items():
            with self.subTest(field=field):
                hit = scheduling.cache_get(self.store, "FAST_FMT", changed)
                self.assertEqual(hit.kind, "MISS", f"a changed {field} must not reuse")

    def test_an_incomplete_identity_never_reuses(self) -> None:
        self.put(identity())
        document = copy.deepcopy(identity())
        del document["population"]
        _, problems = scheduling.normalise_identity(document)
        self.assertTrue(problems)
        document = copy.deepcopy(identity())
        document["target"]["profile"] = ""
        identity_value, problems = scheduling.normalise_identity(document)
        self.assertIsNone(identity_value)
        self.assertTrue(problems)

    def test_a_tampered_entry_is_refused(self) -> None:
        ident = identity()
        self.put(ident)
        self.store["entries"][0]["identity"]["tool"]["paths"][0]["sha256"] = "f" * 64
        hit = scheduling.cache_get(self.store, "FAST_FMT", ident)
        self.assertEqual(hit.kind, "REFUSED")
        self.assertEqual(hit.refusal["rule"], "SC_CACHE_ENTRY_INCOMPLETE")

    def test_a_conflicting_result_is_refused(self) -> None:
        ident = identity()
        self.put(ident, result="PASS")
        with self.assertRaises(scheduling.SchedulingRefusal) as raised:
            self.put(ident, result="FAILED")
        self.assertEqual(raised.exception.rule, "SC_CACHE_CONFLICT")

    def test_repeating_the_same_put_is_unchanged_and_deterministic(self) -> None:
        ident = identity()
        self.assertEqual(self.put(ident)["status"], "STORED")
        self.assertEqual(self.put(ident)["status"], "UNCHANGED")
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "a.json"
            second = Path(temporary) / "b.json"
            for path in (first, second):
                store = scheduling.empty_store()
                scheduling.cache_put(store, "FAST_FMT", ident, "PASS", resources(), [], "run", None)
                scheduling.save_store(path, store)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_a_control_entry_is_not_evidence(self) -> None:
        ident = identity()
        self.put(ident, provenance="control")
        hit = scheduling.cache_get(self.store, "FAST_FMT", ident)
        self.assertEqual(hit.kind, "HIT")
        run = {
            "id": "declared",
            "checks": ["FAST_FMT"],
            "change_sets": ["cs"],
            "status": "SATISFIED",
            "identity": ident,
            "evidence": [],
        }
        row = scheduling.resolve_run(run, "FAST_FMT", self.store)
        self.assertEqual(row["state"], "REFUSED")
        self.assertIn("control", row["detail"])


# ---------------------------------------------------------------------------
# 8: resource exhaustion is BLOCKED
# ---------------------------------------------------------------------------


class ExhaustionControls(unittest.TestCase):
    def setUp(self) -> None:
        self.store = scheduling.empty_store()

    def test_simulated_exhaustion_is_blocked_with_bound_and_observed(self) -> None:
        ident = identity()
        scheduling.cache_put(
            self.store,
            "BATCH_SUITE_PARALLEL",
            ident,
            "BLOCKED",
            resources(memory=(4096, 8192), time=(900, 41), disk=(4096, 7)),
            [],
            "run",
            "the simulated run hit the memory bound",
        )
        hit = scheduling.cache_get(self.store, "BATCH_SUITE_PARALLEL", ident)
        self.assertEqual(hit.kind, "HIT")
        self.assertEqual(hit.entry["result"], "BLOCKED")
        self.assertEqual(hit.entry["exhausted"], ["memory_mib"])
        self.assertEqual(hit.entry["resources"]["memory_mib"], {"bound": 4096, "observed": 8192})

        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "CACHE.json"
            ident_path = Path(temporary) / "ID.json"
            ident_path.write_text(json.dumps(ident), encoding="utf-8")
            scheduling.save_store(store_path, self.store)
            code, payload = run_main(
                ["cache-get", "--store", str(store_path), "--check", "BATCH_SUITE_PARALLEL", "--identity", str(ident_path)]
            )
        self.assertEqual(code, 4, payload)
        self.assertEqual(payload["status"], "HIT")
        self.assertEqual(payload["result"], "BLOCKED")
        self.assertNotEqual(code, 0)

    def test_pass_after_exceeding_a_bound_is_refused(self) -> None:
        with self.assertRaises(scheduling.SchedulingRefusal) as raised:
            scheduling.cache_put(
                self.store,
                "BATCH_SUITE_SERIAL",
                identity(),
                "PASS",
                resources(memory=(4096, 5000)),
                [],
                "run",
                None,
            )
        self.assertEqual(raised.exception.rule, "SC_RESULT_EXCEEDS_BOUND")
        self.assertEqual(self.store["entries"], [])

    def test_blocked_without_a_bound_is_refused(self) -> None:
        with self.assertRaises(scheduling.SchedulingRefusal) as raised:
            scheduling.cache_put(
                self.store,
                "BATCH_SUITE_SERIAL",
                identity(),
                "BLOCKED",
                resources(memory=(4096, 4000)),
                [],
                "run",
                None,
            )
        self.assertEqual(raised.exception.rule, "SC_BLOCKED_WITHOUT_BOUND")

    def test_a_blocked_declaration_shows_in_the_aggregate_even_when_all_else_is_satisfied(self) -> None:
        ident = identity()
        required = [row["check"] for row in scheduling.required_checks("FAST")]
        for check in required:
            scheduling.cache_put(self.store, check, ident, "PASS", resources(), [], "run", None)
        runs = [
            {
                "id": "everything",
                "checks": required,
                "change_sets": ["cs"],
                "status": "SATISFIED",
                "identity": ident,
                "evidence": [],
            },
            {
                "id": "exhausted",
                "checks": ["FAST_FOCUSED_TESTS"],
                "change_sets": ["cs"],
                "status": "BLOCKED",
                "resources": resources(time=(60, 61)),
                "evidence": [],
                "note": "the simulated run hit the time bound",
            },
        ]
        _, aggregate, rows = scheduling.evaluate("FAST", runs, self.store, "cs")
        self.assertEqual(aggregate["status"], "BLOCKED")
        self.assertEqual(aggregate["counts"]["SATISFIED"], 3)
        self.assertEqual(len(aggregate["blocked"]), 1)
        self.assertEqual(aggregate["blocked"][0]["check"], "FAST_FOCUSED_TESTS")
        self.assertIn("FAST_FOCUSED_TESTS", aggregate["not_satisfied"])
        self.assertEqual(scheduling.exit_code_for(aggregate["status"]), 4)

    def test_a_blocked_declaration_without_a_bound_is_refused_not_deferred(self) -> None:
        runs = [
            {
                "id": "vague",
                "checks": ["FAST_FMT"],
                "change_sets": ["cs"],
                "status": "BLOCKED",
                "evidence": [],
            }
        ]
        _, aggregate, rows = scheduling.evaluate("FAST", runs, self.store, "cs")
        self.assertEqual(rows[0]["state"], "REFUSED")
        self.assertEqual(aggregate["status"], "REFUSED")
        self.assertNotEqual(aggregate["status"], "NOT_RUN")


# ---------------------------------------------------------------------------
# 9: a NOT_RUN is never a pass
# ---------------------------------------------------------------------------


class DeclarationControls(unittest.TestCase):
    def setUp(self) -> None:
        self.store = scheduling.empty_store()

    def test_not_run_is_never_satisfied(self) -> None:
        runs = [
            {
                "id": "nothing",
                "checks": [row["check"] for row in scheduling.required_checks("BATCH")],
                "change_sets": ["cs"],
                "status": "NOT_RUN",
                "evidence": ["evidence/etp-t10/RECEIPT.md"],
            }
        ]
        _, aggregate, rows = scheduling.evaluate("BATCH", runs, self.store, "cs")
        self.assertEqual(aggregate["status"], "NOT_RUN")
        self.assertEqual(aggregate["counts"]["SATISFIED"], 0)
        self.assertEqual(len(aggregate["not_satisfied"]), len(scheduling.required_checks("BATCH")))
        self.assertEqual(scheduling.exit_code_for(aggregate["status"]), 1)
        self.assertTrue(all(row["state"] == "NOT_RUN" for row in rows))

    def test_a_satisfied_declaration_needs_a_cached_result(self) -> None:
        runs = [
            {
                "id": "prose",
                "checks": ["FAST_FMT"],
                "change_sets": ["cs"],
                "status": "SATISFIED",
                "identity": identity(),
                "evidence": ["evidence/etp-t9/RECEIPT.md"],
            }
        ]
        row = scheduling.resolve_run(runs[0], "FAST_FMT", self.store)
        self.assertEqual(row["state"], "REFUSED")
        self.assertIn("no cached result", row["detail"])

    def test_a_satisfied_declaration_with_an_incomplete_identity_never_reuses(self) -> None:
        ident = identity()
        scheduling.cache_put(self.store, "FAST_FMT", ident, "PASS", resources(), [], "run", None)
        partial = copy.deepcopy(ident)
        del partial["instrument"]
        runs = [
            {
                "id": "partial",
                "checks": ["FAST_FMT"],
                "change_sets": ["cs"],
                "status": "SATISFIED",
                "identity": partial,
                "evidence": [],
            }
        ]
        row = scheduling.resolve_run(runs[0], "FAST_FMT", self.store)
        self.assertEqual(row["state"], "REFUSED")
        self.assertNotEqual(row["state"], "SATISFIED")

    def test_a_declared_failure_is_visible(self) -> None:
        runs = [
            {
                "id": "failed",
                "checks": ["FAST_CLIPPY"],
                "change_sets": ["cs"],
                "status": "FAILED",
                "evidence": [],
            }
        ]
        _, aggregate, _ = scheduling.evaluate("FAST", runs, self.store, "cs")
        self.assertEqual(aggregate["status"], "FAILED")
        self.assertEqual(scheduling.exit_code_for(aggregate["status"]), 1)

    def test_rows_for_another_change_set_do_not_count(self) -> None:
        runs = [
            {
                "id": "other",
                "checks": ["FAST_FMT"],
                "change_sets": ["cs-other"],
                "status": "NOT_RUN",
                "evidence": [],
            }
        ]
        _, aggregate, rows = scheduling.evaluate("FAST", runs, self.store, "cs")
        self.assertEqual(rows, [])
        self.assertEqual(aggregate["status"], "NOT_RUN")

    def test_a_cache_that_cannot_be_read_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "CACHE.json"
            path.write_text(json.dumps({"schema": scheduling.CACHE_SCHEMA, "entries": "nope"}), encoding="utf-8")
            with self.assertRaises(scheduling.SchedulingRefusal) as raised:
                scheduling.load_store(path)
        self.assertEqual(raised.exception.rule, "SC_CACHE_ENTRIES")


# ---------------------------------------------------------------------------
# The policy applied end to end to a repository
# ---------------------------------------------------------------------------


class ReportControls(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = Fixture()
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name)
        self.sets = self.out / "SETS.json"
        self.runs = self.out / "RUNS.json"
        self.store_path = self.out / "CACHE.json"
        self.sets.write_text(
            json.dumps(
                {
                    "schema": scheduling.SETS_SCHEMA,
                    "change_sets": [
                        {
                            "id": "cs-source",
                            "base": self.fx.base,
                            "head": self.fx.head,
                            "purpose": "a source change",
                        }
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.fx.close()
        self._tmp.cleanup()

    def write_runs(self, document: dict[str, Any]) -> None:
        self.runs.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    def report(self, target: Path) -> tuple[int, dict[str, Any]]:
        return run_main(
            [
                "report",
                "--repo",
                str(self.fx.root),
                "--change-sets",
                str(self.sets),
                "--runs",
                str(self.runs),
                "--store",
                str(self.store_path),
                "--out",
                str(target),
            ]
        )

    def test_a_not_run_change_set_does_not_pass_and_the_report_is_deterministic(self) -> None:
        self.write_runs(
            {
                "schema": scheduling.RUNS_SCHEMA,
                "runs": [
                    {
                        "id": "receipt",
                        "checks": [row["check"] for row in scheduling.required_checks("BATCH")],
                        "change_sets": ["cs-source"],
                        "status": "NOT_RUN",
                        "evidence": ["evidence/etp-t11/RECEIPT.md"],
                        "note": "the receipt records no applicability identity",
                    }
                ],
            }
        )
        first = self.out / "TIERS-a.json"
        second = self.out / "TIERS-b.json"
        code_a, payload_a = self.report(first)
        code_b, _ = self.report(second)
        self.assertEqual(code_a, 1)
        self.assertEqual(code_b, 1)
        self.assertEqual(payload_a["status"], "NOT_RUN")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        document = json.loads(first.read_text(encoding="utf-8"))
        change_set = document["change_sets"][0]
        self.assertEqual(change_set["tier"], "BATCH")
        self.assertEqual(change_set["aggregate"]["status"], "NOT_RUN")
        self.assertEqual(change_set["aggregate"]["counts"]["SATISFIED"], 0)
        self.assertEqual(
            sorted(change_set["aggregate"]["not_satisfied"]),
            sorted(row["check"] for row in scheduling.required_checks("BATCH")),
        )

    def test_a_fully_bound_change_set_can_be_satisfied(self) -> None:
        ident = identity()
        checks = [row["check"] for row in scheduling.required_checks("BATCH")]
        store = scheduling.empty_store()
        for check in checks:
            scheduling.cache_put(store, check, ident, "PASS", resources(), [], "run", None)
        scheduling.save_store(self.store_path, store)
        self.write_runs(
            {
                "schema": scheduling.RUNS_SCHEMA,
                "runs": [
                    {
                        "id": "bound",
                        "checks": checks,
                        "change_sets": ["cs-source"],
                        "status": "SATISFIED",
                        "identity": ident,
                        "evidence": ["evidence/etp-t11/RECEIPT.md"],
                    }
                ],
            }
        )
        code, payload = self.report(self.out / "TIERS.json")
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["status"], "SATISFIED")

    def test_a_blocked_run_makes_the_report_blocked(self) -> None:
        ident = identity()
        checks = [row["check"] for row in scheduling.required_checks("BATCH")]
        store = scheduling.empty_store()
        for check in checks:
            if check == "BATCH_SUITE_SERIAL":
                scheduling.cache_put(
                    store,
                    check,
                    ident,
                    "BLOCKED",
                    resources(memory=(2048, 4096)),
                    [],
                    "run",
                    "simulated exhaustion",
                )
                continue
            scheduling.cache_put(store, check, ident, "PASS", resources(), [], "run", None)
        scheduling.save_store(self.store_path, store)
        self.write_runs(
            {
                "schema": scheduling.RUNS_SCHEMA,
                "runs": [
                    {
                        "id": "bound",
                        "checks": checks,
                        "change_sets": ["cs-source"],
                        "status": "SATISFIED",
                        "identity": ident,
                        "evidence": [],
                    }
                ],
            }
        )
        code, payload = self.report(self.out / "TIERS.json")
        self.assertEqual(code, 4, payload)
        document = json.loads((self.out / "TIERS.json").read_text(encoding="utf-8"))
        aggregate = document["change_sets"][0]["aggregate"]
        self.assertEqual(aggregate["status"], "BLOCKED")
        self.assertEqual(aggregate["counts"]["BLOCKED"], 1)
        self.assertEqual(aggregate["blocked"][0]["resources"]["memory_mib"], {"bound": 2048, "observed": 4096})

    def test_an_unresolvable_change_set_refuses_the_whole_report(self) -> None:
        self.write_runs({"schema": scheduling.RUNS_SCHEMA, "runs": []})
        self.sets.write_text(
            json.dumps(
                {
                    "schema": scheduling.SETS_SCHEMA,
                    "change_sets": [{"id": "cs-bad", "base": "0" * 40, "head": self.fx.head}],
                }
            ),
            encoding="utf-8",
        )
        target = self.out / "TIERS.json"
        code, payload = self.report(target)
        self.assertEqual(code, 2)
        self.assertEqual(payload["rule"], "SC_SETS_UNRESOLVED")
        self.assertFalse(target.exists(), "a refused report must not write a verdict")

    def test_an_unknown_check_in_a_record_is_refused(self) -> None:
        self.write_runs(
            {
                "schema": scheduling.RUNS_SCHEMA,
                "runs": [
                    {
                        "id": "typo",
                        "checks": ["FAST_FMT_TYPO"],
                        "change_sets": ["cs-source"],
                        "status": "NOT_RUN",
                        "evidence": [],
                    }
                ],
            }
        )
        code, payload = self.report(self.out / "TIERS.json")
        self.assertEqual(code, 2)
        self.assertEqual(payload["rule"], "SC_RUNS_ENTRY_CHECK")

    def test_a_control_that_disagrees_or_is_unlabelled_is_refused(self) -> None:
        disagreeing = {
            "schema": scheduling.RUNS_SCHEMA,
            "runs": [],
            "controls": [
                {
                    "control": "reuse-on-identical-identity",
                    "simulated": True,
                    "agrees": False,
                }
            ],
        }
        self.write_runs(disagreeing)
        code, payload = self.report(self.out / "TIERS.json")
        self.assertEqual(code, 2)
        self.assertEqual(payload["rule"], "SC_CONTROLS_DISAGREE")

        unlabelled = copy.deepcopy(disagreeing)
        unlabelled["controls"][0]["agrees"] = True
        del unlabelled["controls"][0]["simulated"]
        self.write_runs(unlabelled)
        code, payload = self.report(self.out / "TIERS.json")
        self.assertEqual(code, 2)
        self.assertEqual(payload["rule"], "SC_CONTROLS_UNLABELLED")


class IdentityBuilder(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = Fixture()

    def tearDown(self) -> None:
        self.fx.close()

    def test_the_identity_builder_binds_the_commit_and_the_tool_bytes(self) -> None:
        target = Path(self.fx.root) / "ID.json"
        code, payload = run_main(
            [
                "identity",
                "--repo",
                str(self.fx.root),
                "--source-commit",
                self.fx.head,
                "--tool-path",
                "src/unit.rs",
                "--population",
                "case-b",
                "--population",
                "case-a",
                "--out",
                str(target),
            ]
        )
        self.assertEqual(code, 0, payload)
        document = json.loads(target.read_text(encoding="utf-8"))
        identity_value, problems = scheduling.normalise_identity(document)
        self.assertEqual(problems, [])
        self.assertEqual(identity_value["source"]["commit"], self.fx.head)
        self.assertEqual(identity_value["population"]["items"], ["case-a", "case-b"])

    def test_a_changed_working_tree_tool_is_refused(self) -> None:
        self.fx.write("src/unit.rs", "pub fn f() -> u8 {\n    3\n}\n")
        code, payload = run_main(
            [
                "identity",
                "--repo",
                str(self.fx.root),
                "--source-commit",
                self.fx.head,
                "--tool-path",
                "src/unit.rs",
                "--population",
                "case-a",
            ]
        )
        self.assertEqual(code, 2)
        self.assertEqual(payload["rule"], "SC_TOOL_IDENTITY")


if __name__ == "__main__":
    unittest.main(verbosity=2)
