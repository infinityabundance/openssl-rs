#!/usr/bin/env python3
"""Controls for the SARIF profile and its adapter.

Each control constructs a native-record fixture in a temporary directory, mutates
exactly one thing, and asserts the profile behaviour `docs/SARIF-PROFILE.md` claims:
a superseded finding is still emitted, a binary finding is not given a line, two
occurrences in different artefacts are not interchangeable, an unchanged finding
keeps its logical identity, a moved location changes only the exact identity, and a
missing candidate identity refuses the emission.

The fixtures are deliberately small and hand-written so that a control cannot pass
because the real repository happens to contain the shape it looks for. One test
runs the adapter over the real records and asserts the counts the receipt records.

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

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import sarif_adapter as adapter  # noqa: E402

BINARY = Path(__file__).resolve().parents[1] / "sarif_adapter.py"


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

def _secrets_document() -> dict:
    def entry(identifier, path, line, klass, required, met, evidence, item):
        return {
            "id": identifier,
            "item": item,
            "class": klass,
            "source": {"path": path, "line": line, "symbol": "f", "token": "t"},
            "owner": "o",
            "cleansing_obligation": {
                "required": required,
                "extent": "x",
                "mechanism": "m",
                "met": met,
            },
            "evidence": evidence,
            "note": "native note",
        }

    contract = {
        "kind": "source-contract",
        "reference": "src/a.rs:1",
        "result": "CONTRACT_ONLY",
    }
    return {
        "schema": "openssl-rs/etp-t7/secrets/1",
        "candidate": {"commit": "a" * 40, "branch": "staging"},
        "entries": [
            entry("SEC-A", "src/a.rs", 10, "SECRET_DATA", True, False, contract, "item A"),
            entry(
                "SEC-B",
                "src/b.rs",
                20,
                "SECRET_DEPENDENT_CONTROL",
                False,
                True,
                "NONE",
                "item B",
            ),
            entry("SEC-DUP", "src/c.rs", 30, "SECRET_DATA", True, False, contract, "dup C"),
            entry("SEC-DUP", "src/d.rs", 40, "SECRET_DATA", True, False, contract, "dup D"),
        ],
        "counts": {"SECRET_DATA": 3, "SECRET_DEPENDENT_CONTROL": 1},
        "secret_dependent_control_without_evidence": ["SEC-B"],
        "secret_bearing_without_cleansing": ["SEC-A", "SEC-DUP", "SEC-DUP"],
        "non_claims": ["a fixture non-claim"],
    }


def _timing_document() -> dict:
    name = "BN_mod_exp_mont_consttime"
    return {
        "schema": "openssl-rs/timing-bn-findings/1",
        "candidate": {
            "source_head": "b" * 40,
            "branch": "staging",
            "libcrypto": {
                "path": "artifacts/x/lib/libcrypto.so.3",
                "sha256": "c" * 64,
                "build_id": "deadbeef",
            },
        },
        "primitives": {
            name: {
                "libcrypto_offset": "0x1000",
                "size": 100,
                "dynsym_name": "n@@OPENSSL_3.0.0",
                "got_slot": "0x899010",
            }
        },
        "ctgrind": {
            name: {
                "errors": 5,
                "contexts": 2,
                "kinds": {"branch": 5},
                "function": "f (0x1000, size 0x64)",
                "sites": [{"offset": "0x1010", "instr": "je"}],
                "source_interpretation": "s",
                "file_line": "NOT AVAILABLE. no rows",
                "log": "court/tmp/vg.log",
            }
        },
        "dudect": {
            name: {
                "t_values": [1.5],
                "verdict": "LEAKAGE_DETECTED",
                "dudect_text": "not constant time",
                "consistency": "c",
            }
        },
        "not_run": ["an analysis"],
        "non_claims": ["a fixture non-claim"],
    }


def _safety_document() -> dict:
    return {
        "schema": "openssl-rs/etp/unsafe-sites/1",
        "identity": {
            "commit": "d" * 40,
            "branch": "staging",
            "source_tree_sha256": "e" * 64,
            "scanner": "forensics/tools/unsafe_obligations.py",
            "scanner_sha256": "f" * 64,
        },
        "sites": {
            "encoding": "indexed-v1",
            "columns": [
                "id",
                "path",
                "line",
                "column",
                "kind",
                "symbol",
                "class",
                "impact",
                "impacts",
                "contract_state",
                "contract_reason",
                "contract_sha256",
                "boundary_kind",
                "boundary_id",
                "coverage_kind",
                "coverage_id",
            ],
            "tables": {
                "path": ["src/a.rs", "src/b.rs"],
                "symbol": ["fa", "fb"],
                "boundary_id": ["UNCONFINED"],
                "coverage_id": ["none"],
                "contract_reason": ["no_comment"],
            },
            "vocabularies": {
                "kind": ["unsafe_block"],
                "class": ["raw_dereference"],
                "impact": ["memory_unsafety"],
                "contract_state": ["absent", "restatement", "argument"],
                "boundary_kind": ["UNCONFINED"],
                "coverage_kind": ["none"],
            },
            "rows": [
                ["us-1", 0, 10, 4, 0, 0, 0, 0, 1, 0, 0, "h" * 16, 0, 0, 0, 0],
                ["us-2", 1, 20, 1, 0, 1, 0, 0, 1, 1, 0, "h" * 16, 0, 0, 0, 0],
            ],
        },
        "operations": {"columns": ["id"], "rows": []},
        "contracts": {"note": "n", "entries": {}},
        "vacuity": {
            "discharges": [],
            "findings": [
                {
                    "site": "us-1",
                    "path": "src/a.rs",
                    "line": 10,
                    "symbol": "fa",
                    "status": "CALLER_OBLIGATION_UNESTABLISHED",
                    "scope": "unsafe_fn_without_contract",
                    "detail": "d",
                    "production_callers": 0,
                    "test_callers": 0,
                    "witness": "w",
                },
                {
                    "site": "us-2",
                    "path": "src/b.rs",
                    "line": 20,
                    "symbol": "fb",
                    "status": "CALLER_OBLIGATION_UNESTABLISHED",
                    "scope": "unsafe_fn_without_contract",
                    "detail": "d",
                    "production_callers": 0,
                    "test_callers": 0,
                    "witness": "w",
                },
            ],
            "refusals": [],
            "summary": {"caller_obligation_unestablished": 2},
        },
        "assertions": {"tautological": 0, "ignored": 0},
        "suppressions": {"total": 3, "by_lint": {"dead_code": 3}, "test_modules": []},
        "summary": {"sites": 2, "contract_absent": 1, "ignored_tests": 0},
        "non_claims": ["a fixture non-claim"],
    }


def _curl_document() -> dict:
    return {
        "schema": "openssl-rs/campaign/safe-c33/consumer-closure/v2",
        "tool": {"path": "forensics/tools/consumer_closure.py"},
        "family": "curl",
        "source_identity": {
            "repository_head": "1" * 40,
            "branch": "staging",
            "tracked_tree_dirty": False,
        },
        "candidate_identity": {
            "install_prefix": "artifacts/x/install",
            "libcrypto_so_3_sha256": "2" * 64,
            "libssl_so_3_sha256": "3" * 64,
            "all_openssl_under_install": True,
        },
        "counts": {"reachable_production_obligations": 1},
        "obligations": [
            {
                "id": "V1:src/x.rs:7:UNSAFE_FN_DEF",
                "stable_id": "src/x.rs::UNSAFE_FN_DEF::f",
                "file": "src/x.rs",
                "line": 7,
                "kind": "UNSAFE_FN_DEF",
                "item": "f",
                "partition": "production",
                "mechanism": "C_ABI_CONTRACT",
                "status": "DISCHARGED",
                "discharge_receipt": "r1",
                "disposition_conflicts": [
                    {
                        "discharging_boundary": "src/x.rs:7",
                        "boundary": "B1",
                        "receipt": "r0",
                        "disposition": "BLOCKED",
                        "keyword": "BLOCKED",
                        "superseded": True,
                    }
                ],
            }
        ],
        "precision": {
            "totals": {"reachable_unresolved_sites": 2},
            "residual_sites": [
                {
                    "dso": "libcrypto.so.3",
                    "function": "0x10",
                    "call_site": "0x14",
                    "reason": "exported-callback contract",
                    "class": "ABI_CONTRACT_EXPORT_CALLBACK",
                    "text": "call   *%r9",
                }
            ],
            "residual_sites_bound": {
                "status": "TRUNCATED_BOUNDED",
                "sample_size": 1,
                "population_size": 2,
                "omitted_members": 1,
                "omitted_members_recorded": False,
                "omitted_members_note": "n",
                "selection_rule": {"rule": "r", "locator": "l", "rerunnable": True},
            },
            "predicate_element_7": {
                "established": False,
                "status": "FAIL",
                "basis": "b",
                "reachable_unresolved_sites": 2,
                "target_bounded_unresolved_sites": 1,
            },
        },
        "verdict": {"state": "ACCEPTED", "safe_compatible": False, "reason": "none"},
        "refusals": [],
        "non_claims": ["a fixture non-claim"],
    }


def _adjudication_document() -> dict:
    return {
        "schema": "openssl-rs/safe-c33/adjudication/v1",
        "kind": "independent-adversarial-adjudication",
        "candidate_tag": "fixture",
        "evidence_source_head": "4" * 40,
        "head_at_adjudication": "5" * 40,
        "source_content_commit": "7" * 40,
        "src_content_sha256": "6" * 64,
        "freeze": {"sha256": "8" * 64},
        "verdict": {
            "state": "NOT ESTABLISHED",
            "for": ["SAFE_COMPATIBLE (ssh)"],
            "reason": "r",
            "reproduced": [],
        },
        "item4_mechanisms": {
            "per_mechanism": {
                "M1": {"obligations": 3, "verdict": "NOT_ESTABLISHED"},
                "M2": {"obligations": 1, "verdict": "SAFETY_DISCHARGED (scoped)"},
            },
            "cross_cutting": "all four NOT_ESTABLISHED",
        },
        "ordered_refutations": ["1. first refutation", "2. second refutation"],
        "non_claims": ["a fixture non-claim"],
    }


def _reconciliation_document() -> dict:
    return {
        "schema": "openssl-rs/safe-c33/row-reconciliation/v1",
        "source_candidate": "9" * 40,
        "head_at_review": "9" * 40,
        "branch": "staging",
        "rows": [
            {
                "ledger_pointer": "/findings/0",
                "obligation": "o1",
                "decision": "LEDGER_STALE",
                "old_state": "open",
                "new_state": "closed",
                "note": "n",
            }
        ],
        "limits": {"evidence_level": "FAST", "not_claimed": "x"},
    }


FIXTURES = {
    "evidence/etp-t7/SECRETS.json": _secrets_document,
    "evidence/timing-bn-findings.json": _timing_document,
    "evidence/etp-t4/SAFETY-SITES.json": _safety_document,
    "evidence/closure-curl-049.json": _curl_document,
    "evidence/b85c-adjudication.json": _adjudication_document,
    "evidence/b85c-row-reconciliation.json": _reconciliation_document,
}


def write_fixture(root: Path, overrides: dict | None = None) -> Path:
    overrides = overrides or {}
    for relative, builder in FIXTURES.items():
        document = overrides.get(relative, builder)()
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return root


def build(root: Path, sources=None) -> dict:
    return adapter.build_document(root, sources)


def results_for(document: dict, rule_id: str) -> list:
    found = []
    for run in document["runs"]:
        for result in run["results"]:
            if result["ruleId"] == rule_id:
                found.append(result)
    return found


# --------------------------------------------------------------------------
# Controls
# --------------------------------------------------------------------------

class FixtureControls(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = write_fixture(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    # Control 1 -----------------------------------------------------------
    def test_superseded_row_is_emitted_and_marked(self):
        document = build(self.root, ["curl"])
        results = results_for(document, "A1-OBLIGATION-DISPOSITION-SUPERSEDED")
        self.assertEqual(len(results), 1, "a superseded disposition must not be dropped")
        result = results[0]
        self.assertEqual(result["level"], "note")
        self.assertEqual(result["kind"], "fail")
        self.assertTrue(result["properties"]["a1"]["superseded"])
        self.assertTrue(
            result["properties"]["a1"]["native"]["fields"]["superseded"],
            "the native superseded flag is carried verbatim",
        )
        self.assertEqual(
            result["properties"]["a1"]["native"]["fields"]["keyword"], "BLOCKED"
        )
        self.assertIn("superseded", result["message"]["text"])
        # The superseded row did not replace the discharged obligation result.
        self.assertEqual(len(results_for(document, "A1-OBLIGATION-DISCHARGED")), 1)

    # Control 2 -----------------------------------------------------------
    def test_binary_finding_has_no_fabricated_line(self):
        document = build(self.root, ["timing"])
        results = results_for(document, "A1-TIMING-LEAKAGE-DETECTED")
        self.assertEqual(len(results), 1)
        result = results[0]
        location = result["locations"][0]["physicalLocation"]
        self.assertNotIn("startLine", location["region"])
        self.assertNotIn("endLine", location["region"])
        self.assertNotIn("startColumn", location["region"])
        self.assertEqual(location["region"]["byteOffset"], 0x1000)
        self.assertEqual(location["region"]["byteLength"], 100)
        self.assertEqual(location["address"]["absoluteAddress"], 0x1000)
        self.assertEqual(location["address"]["kind"], "function")
        self.assertFalse(result["properties"]["a1"]["lineInfoAvailable"])
        self.assertEqual(
            result["properties"]["a1"]["locationPrecision"],
            "function-offset-and-extent",
        )
        # Related branch sites are offsets too, never lines.
        for related in result["relatedLocations"]:
            physical = related["physicalLocation"]
            self.assertNotIn("startLine", physical["region"])
            self.assertIn("byteOffset", physical["region"])
            self.assertFalse(
                related["properties"]["a1"]["lineInfoAvailable"],
                "a machine-code site must not claim line information",
            )
        # No result in the run claims a source line for a binary finding.
        for other in document["runs"][0]["results"]:
            for loc in other.get("locations") or []:
                region = loc["physicalLocation"]["region"]
                self.assertNotIn("startLine", region)

    # Control 3 -----------------------------------------------------------
    def test_same_rule_in_different_artifacts_not_interchangeable(self):
        document = build(self.root, ["secrets"])
        results = results_for(document, "A1-SECRET-CLEANSING-UNMET")
        # SEC-A and the two SEC-DUP entries.
        self.assertEqual(len(results), 3)
        duplicates = [
            r
            for r in results
            if r["properties"]["a1"]["native"]["fields"]["id"] == "SEC-DUP"
        ]
        self.assertEqual(len(duplicates), 2, "both occurrences are emitted")
        first, second = duplicates
        self.assertEqual(first["ruleId"], second["ruleId"])
        self.assertEqual(
            first["partialFingerprints"]["a1Logical/v1"],
            second["partialFingerprints"]["a1Logical/v1"],
            "the logical finding is the same",
        )
        self.assertNotEqual(
            first["partialFingerprints"]["a1Exact/v1"],
            second["partialFingerprints"]["a1Exact/v1"],
            "the exact occurrence is not the same",
        )
        self.assertNotEqual(
            first["properties"]["a1"]["artifact"]["uri"],
            second["properties"]["a1"]["artifact"]["uri"],
        )
        self.assertFalse(
            adapter.fingerprints_interchangeable(first, second),
            "fingerprints must not be treated as interchangeable across artefacts",
        )
        self.assertTrue(adapter.fingerprints_interchangeable(first, first))

    def test_same_rule_different_logical_findings(self):
        document = build(self.root, ["safety"])
        results = results_for(document, "A1-UNSAFE-OBLIGATION-UNESTABLISHED")
        self.assertEqual(len(results), 2)
        first, second = results
        self.assertEqual(first["ruleId"], second["ruleId"])
        self.assertNotEqual(
            first["partialFingerprints"]["a1Logical/v1"],
            second["partialFingerprints"]["a1Logical/v1"],
            "different symbols in different files are different logical findings",
        )
        self.assertFalse(adapter.fingerprints_interchangeable(first, second))

    # Control 4 -----------------------------------------------------------
    def test_unchanged_finding_keeps_logical_identity(self):
        first = build(self.root, ["secrets"])
        second = build(self.root, ["secrets"])
        left = results_for(first, "A1-SECRET-CLEANSING-UNMET")
        right = results_for(second, "A1-SECRET-CLEANSING-UNMET")
        self.assertEqual(
            [r["partialFingerprints"] for r in left],
            [r["partialFingerprints"] for r in right],
        )

    # Control 5 -----------------------------------------------------------
    def test_changed_location_changes_exact_not_logical(self):
        before = results_for(build(self.root, ["secrets"]), "A1-SECRET-CLEANSING-UNMET")
        target = self.root / "evidence/etp-t7/SECRETS.json"
        document = json.loads(target.read_text(encoding="utf-8"))
        document["entries"][0]["source"]["line"] = 11
        target.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        after = results_for(build(self.root, ["secrets"]), "A1-SECRET-CLEANSING-UNMET")

        before_by_locator = {r["properties"]["a1"]["native"]["locator"]: r for r in before}
        after_by_locator = {r["properties"]["a1"]["native"]["locator"]: r for r in after}
        self.assertEqual(
            before_by_locator["entries[0]"]["partialFingerprints"]["a1Logical/v1"],
            after_by_locator["entries[0]"]["partialFingerprints"]["a1Logical/v1"],
            "moving a line must not change the logical identity",
        )
        self.assertNotEqual(
            before_by_locator["entries[0]"]["partialFingerprints"]["a1Exact/v1"],
            after_by_locator["entries[0]"]["partialFingerprints"]["a1Exact/v1"],
            "moving a line must change the exact identity",
        )
        for locator in ("entries[2]", "entries[3]"):
            self.assertEqual(
                before_by_locator[locator]["partialFingerprints"],
                after_by_locator[locator]["partialFingerprints"],
                "an untouched finding is unchanged",
            )

    # Control 6 -----------------------------------------------------------
    def test_colliding_exact_identities_are_counted_not_merged(self):
        broken = copy.deepcopy(_secrets_document())
        duplicate = copy.deepcopy(broken["entries"][2])
        duplicate["item"] = "an identical occurrence"
        broken["entries"].append(duplicate)
        broken["counts"]["SECRET_DATA"] = 4
        broken["secret_bearing_without_cleansing"] = ["SEC-A", "SEC-DUP", "SEC-DUP", "SEC-DUP"]
        write_fixture(self.root, {"evidence/etp-t7/SECRETS.json": lambda: broken})
        document = build(self.root, ["secrets"])
        run = document["runs"][0]
        props = run["properties"]["a1"]
        self.assertEqual(props["fingerprintCollisions"], 1)
        entry = props["fingerprintCollisionList"][0]
        self.assertEqual(entry["count"], 2)
        self.assertEqual(len(entry["locators"]), 2)
        self.assertEqual(len(results_for(document, "A1-SECRET-CLEANSING-UNMET")), 4)

    def test_missing_candidate_identity_refuses_emission(self):
        broken = copy.deepcopy(_secrets_document())
        broken["candidate"] = {"commit": "", "branch": "staging"}
        write_fixture(self.root, {"evidence/etp-t7/SECRETS.json": lambda: broken})
        with self.assertRaises(adapter.Refusal) as caught:
            build(self.root, ["secrets"])
        self.assertEqual(caught.exception.code, adapter.R_MISSING_CANDIDATE)

    def test_missing_candidate_block_refuses_emission(self):
        broken = copy.deepcopy(_curl_document())
        del broken["source_identity"]["repository_head"]
        write_fixture(self.root, {"evidence/closure-curl-049.json": lambda: broken})
        with self.assertRaises(adapter.Refusal) as caught:
            build(self.root, ["curl"])
        self.assertEqual(caught.exception.code, adapter.R_MISSING_CANDIDATE)

    def test_cli_refusal_writes_no_output(self):
        broken = copy.deepcopy(_secrets_document())
        broken["candidate"] = {"branch": "staging"}
        write_fixture(self.root, {"evidence/etp-t7/SECRETS.json": lambda: broken})
        out = self.root / "out.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(BINARY),
                "--repo-root",
                str(self.root),
                "--out",
                str(out),
                "--source",
                "secrets",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn(adapter.R_MISSING_CANDIDATE, completed.stderr)
        self.assertFalse(out.exists(), "a refused emission must write no file")

    # Population and shape refusals ---------------------------------------
    def test_population_mismatch_refuses_emission(self):
        broken = copy.deepcopy(_safety_document())
        broken["summary"]["contract_absent"] = 5
        write_fixture(self.root, {"evidence/etp-t4/SAFETY-SITES.json": lambda: broken})
        with self.assertRaises(adapter.Refusal) as caught:
            build(self.root, ["safety"])
        self.assertEqual(caught.exception.code, adapter.R_POPULATION)

    def test_truncation_bound_mismatch_refuses_emission(self):
        broken = copy.deepcopy(_curl_document())
        broken["precision"]["residual_sites_bound"]["omitted_members"] = 99
        write_fixture(self.root, {"evidence/closure-curl-049.json": lambda: broken})
        with self.assertRaises(adapter.Refusal) as caught:
            build(self.root, ["curl"])
        self.assertEqual(caught.exception.code, adapter.R_POPULATION)

    def test_unknown_native_status_refuses_emission(self):
        broken = copy.deepcopy(_safety_document())
        for item in broken["vacuity"]["findings"]:
            item["status"] = "SOME_NEW_STATUS"
        broken["vacuity"]["summary"] = {"some_new_status": 2}
        write_fixture(self.root, {"evidence/etp-t4/SAFETY-SITES.json": lambda: broken})
        with self.assertRaises(adapter.Refusal) as caught:
            build(self.root, ["safety"])
        self.assertEqual(caught.exception.code, adapter.R_SHAPE)

    def test_binary_site_without_dso_digest_refuses_emission(self):
        broken = copy.deepcopy(_curl_document())
        broken["precision"]["residual_sites"][0]["dso"] = "libother.so.3"
        write_fixture(self.root, {"evidence/closure-curl-049.json": lambda: broken})
        with self.assertRaises(adapter.Refusal) as caught:
            build(self.root, ["curl"])
        self.assertEqual(caught.exception.code, adapter.R_MISSING_ARTIFACT_DIGEST)


class EmissionControls(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = write_fixture(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_determinism_is_byte_identical(self):
        first = self.root / "one.json"
        second = self.root / "two.json"
        for out in (first, second):
            completed = subprocess.run(
                [
                    sys.executable,
                    str(BINARY),
                    "--repo-root",
                    str(self.root),
                    "--out",
                    str(out),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertTrue(first.read_bytes().endswith(b"\n"))
        parsed = json.loads(first.read_text(encoding="utf-8"))
        self.assertEqual(parsed["version"], "2.1.0")

    def test_no_absolute_path_or_time_fields(self):
        document = build(self.root)
        payload = json.dumps(document, sort_keys=True)
        self.assertNotIn(str(self.root), payload)
        self.assertNotIn("/home/", payload)
        self.assertNotIn("/work/", payload)
        self.assertNotIn("startTimeUtc", payload)
        self.assertNotIn("endTimeUtc", payload)
        for run in document["runs"]:
            self.assertNotIn("conversion", run)
            for result in run["results"]:
                self.assertNotIn("suppressions", result)
                self.assertNotIn("baselineState", result)
                self.assertNotIn("rank", result)

    def test_every_result_is_attributed(self):
        document = build(self.root)
        for run in document["runs"]:
            candidate = run["properties"]["a1"]["candidate"]
            self.assertTrue(candidate)
            for result in run["results"]:
                a1 = result["properties"]["a1"]
                self.assertTrue(a1["candidate"])
                self.assertIn("digest", a1["artifact"])
                self.assertIn(a1["artifact"]["digestScope"], {
                    "artifact",
                    "source-tree",
                    "candidate-commit",
                    "record",
                })
                self.assertTrue(a1["native"]["locator"])
                self.assertEqual(
                    a1["native"]["recordSha256"],
                    run["properties"]["a1"]["record"]["sha256"],
                )

    def test_runs_are_one_per_record_in_path_order(self):
        document = build(self.root)
        records = [run["properties"]["a1"]["record"]["path"] for run in document["runs"]]
        self.assertEqual(records, sorted(FIXTURES))
        self.assertEqual(len(records), len(set(records)))

    def test_unknown_rule_or_level_cannot_be_emitted(self):
        self.assertNotIn("A1-NOT-A-RULE", adapter.RULE_BY_ID)
        for rule in adapter.RULES:
            self.assertIn(rule["level"], adapter._KIND_FOR_LEVEL)


class RealRecordControls(unittest.TestCase):
    """The emission over the tracked records, at the identity the receipt names."""

    @classmethod
    def setUpClass(cls):
        cls.document = adapter.build_document(REPO_ROOT)

    def test_six_runs_one_per_native_record(self):
        records = [
            run["properties"]["a1"]["record"]["path"] for run in self.document["runs"]
        ]
        self.assertEqual(
            records,
            [
                "evidence/b85c-adjudication.json",
                "evidence/b85c-row-reconciliation.json",
                "evidence/closure-curl-049.json",
                "evidence/etp-t4/SAFETY-SITES.json",
                "evidence/etp-t7/SECRETS.json",
                "evidence/timing-bn-findings.json",
            ],
        )

    def test_populations_match_the_known_totals(self):
        counts = {}
        for run in self.document["runs"]:
            counts[run["properties"]["a1"]["record"]["path"]] = len(run["results"])
        self.assertEqual(counts["evidence/etp-t7/SECRETS.json"], 51)
        self.assertEqual(counts["evidence/timing-bn-findings.json"], 9)
        self.assertEqual(counts["evidence/etp-t4/SAFETY-SITES.json"], 3953)
        self.assertEqual(counts["evidence/closure-curl-049.json"], 211)
        self.assertEqual(counts["evidence/b85c-adjudication.json"], 17)
        self.assertEqual(counts["evidence/b85c-row-reconciliation.json"], 4)
        self.assertEqual(sum(counts.values()), 4245)

    def test_named_classes_are_present(self):
        for rule in (
            "A1-TIMING-LEAKAGE-DETECTED",
            "A1-TIMING-NOT-RUN",
            "A1-UNSAFE-OBLIGATION-UNESTABLISHED",
            "A1-UNSAFE-CONTRACT-ABSENT",
            "A1-ISA-BINARY-UNRESOLVED",
            "A1-ISA-POPULATION-TRUNCATED",
            "A1-ELEMENT7-PREDICATE",
            "A1-ADJUDICATION-VERDICT",
            "A1-RECONCILIATION-ROW",
            "A1-OBLIGATION-DISPOSITION-SUPERSEDED",
            "A1-UNSAFE-SUPPRESSION-MEMBERS-ABSENT",
        ):
            self.assertTrue(results_for(self.document, rule), f"{rule} is absent")

    def test_superseded_real_row_is_present(self):
        results = results_for(self.document, "A1-OBLIGATION-DISPOSITION-SUPERSEDED")
        self.assertEqual(len(results), 1)
        fields = results[0]["properties"]["a1"]["native"]["fields"]
        self.assertTrue(fields["superseded"])
        self.assertEqual(fields["boundary"], "P25-ENGINE-CB-000")

    def test_real_binary_findings_never_claim_a_line(self):
        for result in results_for(self.document, "A1-ISA-BINARY-UNRESOLVED"):
            region = result["locations"][0]["physicalLocation"]["region"]
            self.assertNotIn("startLine", region)
            self.assertIn("byteOffset", region)
        for result in results_for(self.document, "A1-TIMING-LEAKAGE-DETECTED"):
            self.assertFalse(result["properties"]["a1"]["lineInfoAvailable"])

    def test_candidate_identities_are_the_records_own(self):
        by_record = {
            run["properties"]["a1"]["record"]["path"]: run["properties"]["a1"]["candidate"]
            for run in self.document["runs"]
        }
        self.assertEqual(
            by_record["evidence/etp-t7/SECRETS.json"]["commit"],
            "0eddfe839f552a6e22a8cf375ec308c8bf7c478b",
        )
        self.assertEqual(
            by_record["evidence/etp-t4/SAFETY-SITES.json"]["commit"],
            "246e30580f909c047eeb04a93a06f9bd05dc65f3",
        )
        self.assertEqual(
            by_record["evidence/closure-curl-049.json"]["repository_head"],
            "17e45eec1a48a7a5e1679e1d29ee69451e9d59a1",
        )
        self.assertEqual(
            by_record["evidence/timing-bn-findings.json"]["source_head"],
            "18d12e1d5f5ff2faea22c81ee6351bc39add1b60",
        )
        self.assertEqual(
            by_record["evidence/b85c-adjudication.json"]["evidence_source_head"],
            "17042ccf29bc39df638c63e69d3be6c6f965eef7",
        )

    def test_profile_document_states_the_schema_uri(self):
        profile = (REPO_ROOT / "docs/SARIF-PROFILE.md").read_text(encoding="utf-8")
        self.assertIn(adapter.SCHEMA_URI, profile)
        self.assertIn("Errata 01", profile)


if __name__ == "__main__":
    unittest.main()
