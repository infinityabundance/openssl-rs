#!/usr/bin/env python3
"""Controls for A2 lossless evidence preservation and population reconciliation.

Each control constructs its own native record and export fixture in a temporary
directory, mutates exactly one thing, and asserts the behaviour
`docs/EVIDENCE-PRESERVATION.md` claims: preserved bytes are re-derivable, a
population that disagrees with its own record without a declared bound is
refused, a record with no invocation and no instrument identity is refused, a
bound that does not say what was not examined is refused, a re-export over
changed bytes that reuses the old digest is refused, and a partly emitted
population is reported as bounded rather than as a census.

The fixtures are hand-written so that a control cannot pass because the real
repository happens to contain the shape it looks for. Three tests run over the
real records and assert the figures the receipt records.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import evidence_preservation as preservation  # noqa: E402

CURL = "evidence/closure-curl-049.json"
TIMING = "evidence/timing-bn-findings.json"
SECRETS = "evidence/etp-t7/SECRETS.json"


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

def curl_document(
    residual: int = 3,
    population: int = 5,
    with_bound: bool = True,
    totals: int | None = None,
    with_tool: bool = True,
) -> dict:
    document = {
        "schema": "openssl-rs/campaign/safe-c33/consumer-closure/v2",
        "tool": (
            {
                "path": "forensics/tools/consumer_closure.py",
                "version": 6,
                "sha256": "a" * 64,
                "schema": "openssl-rs/campaign/safe-c33/edge-record/v1.4",
            }
            if with_tool
            else {}
        ),
        "generated_utc": "2026-11-19T10:31:55Z",
        "source_identity": {"repository_head": "1" * 40, "branch": "staging"},
        "candidate_identity": {"libcrypto_so_3_sha256": "2" * 64},
        "closure_scope": {
            "excluded_from_upper_bound": [
                {"file": "src/a.rs", "line": 1, "kind": "UNSAFE_FN_DEF", "reason": "not reachable"}
            ]
        },
        "counts": {"reachable_production_obligations": 2},
        "obligations": [{"id": "OB-0"}, {"id": "OB-1"}],
        "refusals": [],
        "precision": {
            "residual_sites": [
                {"dso": "libcrypto.so.3", "function": "0x1", "call_site": "0x2"}
                for _ in range(residual)
            ],
            "totals": {"reachable_unresolved_sites": totals if totals is not None else population},
            "predicate_element_7": {"status": "FAIL", "established": False},
        },
        "non_claims": ["a fixture, not evidence"],
    }
    if with_bound:
        document["precision"]["residual_sites_bound"] = {
            "status": "TRUNCATED_BOUNDED",
            "population_size": population,
            "sample_size": residual,
            "omitted_members": population - residual,
            "omitted_members_recorded": False,
            "omitted_members_note": "the omitted members are written to a sidecar",
            "selection_rule": {
                "rule": "a sorted prefix of the population",
                "locator": "forensics/tools/consumer_closure.py: LIMIT",
                "requires": "python3 forensics/tools/consumer_closure.py",
            },
        }
    return document


def timing_document(primitives: int = 2, not_run: int = 2) -> dict:
    return {
        "schema": "openssl-rs/etp-t8/timing/1",
        "generated_utc": "2026-11-20T19:27:00Z",
        "candidate": {"source_head": "3" * 40, "libcrypto": {"sha256": "4" * 64}},
        "primitives": {f"BN_prim_{index}": {"size": index} for index in range(primitives)},
        "phase18_screen": {"instrument": "CT-PRIMITIVES, 320 samples"},
        "reachability": {"method": {"binary": "libcrypto.so.3"}},
        "ctgrind": {"harness": "court/tmp/timing/ct_bn.c"},
        "dudect": {
            "compile": "clang -O2 -c dudect_bn.c",
            "harness": "court/tmp/timing/dudect_bn.c",
        },
        "instruments": {
            "valgrind": "3.19.0",
            "clang": "14.0.6",
            "court_image": "openssl-rs-court-tools:1",
            "court_caps": "cgroup memory 16 GiB",
        },
        "not_run": [f"analysis {index} was not executed" for index in range(not_run)],
        "non_claims": ["a fixture"],
    }


def secrets_document(entries: int = 2) -> dict:
    return {
        "schema": "openssl-rs/etp-t7/secrets/1",
        "generated": "2026-11-23T06:05:00Z",
        "candidate": {"commit": "5" * 40, "branch": "staging"},
        "entries": [
            {"id": f"SEC-{index}", "class": "SECRET_DATA"} for index in range(entries)
        ],
        "counts": {"SECRET_DATA": entries},
        "non_claims": ["a fixture"],
    }


def curl_results(document: dict) -> list[tuple[str, str]]:
    results = [("A1-OBLIGATION-DISCHARGED", "obligations[0]"),
               ("A1-OBLIGATION-DISCHARGED", "obligations[1]")]
    for index in range(len(document["precision"]["residual_sites"])):
        results.append(("A1-ISA-BINARY-UNRESOLVED", f"precision.residual_sites[{index}]"))
    if "residual_sites_bound" in document["precision"]:
        results.append(
            ("A1-ISA-POPULATION-TRUNCATED", "precision.residual_sites_bound")
        )
    results.append(("A1-CLOSURE-VERDICT", "verdict"))
    results.append(("A1-ELEMENT7-PREDICATE", "precision.predicate_element_7"))
    return results


def timing_results(document: dict) -> list[tuple[str, str]]:
    results = [
        ("A1-TIMING-LEAKAGE-DETECTED", f"primitives.{name}")
        for name in sorted(document["primitives"])
    ]
    results += [
        ("A1-TIMING-NOT-RUN", f"not_run[{index}]")
        for index in range(len(document["not_run"]))
    ]
    return results


def secrets_results(document: dict) -> list[tuple[str, str]]:
    return [
        ("A1-SECRET-CLASSIFICATION-RECORDED", f"entries[{index}]")
        for index in range(len(document["entries"]))
    ]


def adjudication_document() -> dict:
    return {
        "schema": "openssl-rs/safe-c33/adjudication/v1",
        "kind": "independent-adversarial-adjudication",
        "head_at_adjudication": "a" * 9,
        "evidence_source_head": "b" * 40,
        "source_content_commit": "c" * 40,
        "src_content_sha256": "d" * 64,
        "freeze": {"path": "evidence/FREEZE-b85c.json", "sha256": "e" * 64},
        "item1_identity": {},
        "item2_closures": {},
        "item3_instruments": {},
        "item4_mechanisms": {
            "per_mechanism": {"MECH": {"obligations": 1, "verdict": "X"}},
            "cross_cutting": "a fixture",
        },
        "item5_ledger": {},
        "ordered_refutations": ["a fixture refutation"],
        "verdict": {"state": "NOT ESTABLISHED"},
        "non_claims": ["first", "second"],
    }


def adjudication_results(document: dict) -> list[tuple[str, str]]:
    return [
        ("A1-ADJUDICATION-MECHANISM", "item4_mechanisms.per_mechanism.MECH"),
        ("A1-ADJUDICATION-CROSS-CUTTING", "item4_mechanisms.cross_cutting"),
        ("A1-ADJUDICATION-REFUTATION", "ordered_refutations[0]"),
        ("A1-ADJUDICATION-VERDICT", "verdict"),
    ]


class Fixture:
    """A temporary repository holding native records and one SARIF export."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.records: dict[str, dict] = {}
        self.results: dict[str, list[tuple[str, str]]] = {}
        self.not_projected: dict[str, list[dict]] = {}

    def add(self, path: str, document: dict, results: list[tuple[str, str]]) -> None:
        self.records[path] = document
        self.results[path] = results
        self._write_record(path, document)

    def _write_record(self, path: str, document: dict) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def digests(self) -> dict[str, str]:
        return {
            path: preservation.sha256_bytes((self.root / path).read_bytes())
            for path in self.records
        }

    def write_export(self, overrides: dict[str, str] | None = None) -> Path:
        digests = self.digests()
        overrides = overrides or {}
        runs = []
        for path in sorted(self.records):
            digest = overrides.get(path, digests[path])
            results = self.results[path]
            projected: dict[str, int] = {}
            for rule, _ in results:
                projected[rule] = projected.get(rule, 0) + 1
            runs.append(
                {
                    "tool": {"driver": {"name": "fixture"}},
                    "properties": {
                        "a1": {
                            "record": {"path": path, "sha256": digest},
                            "projection": {
                                "nativePopulation": {},
                                "projected": projected,
                                "projectedTotal": len(results),
                                "notProjected": self.not_projected.get(path, []),
                                "sumMatchesPopulation": True,
                            },
                        }
                    },
                    "results": [
                        {
                            "ruleId": rule,
                            "properties": {
                                "a1": {"native": {"locator": locator, "record": path}}
                            },
                        }
                        for rule, locator in results
                    ],
                }
            )
        document = {"version": "2.1.0", "$schema": "fixture", "runs": runs}
        target = self.root / "evidence/a1/SARIF.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return target

    def capture(self, sources=None) -> dict:
        return preservation.capture(
            self.root,
            sources=list(sources) if sources is not None else sorted(self.records),
            store_root=self.root / "_store",
        )

    def verify(self, document: dict, reconciliation: dict | None = None) -> dict:
        if reconciliation is not None:
            preservation.check_reconciliation(
                self.root, reconciliation, document
            )
        return preservation.verify(
            self.root, document, store_root=self.root / "_store"
        )


def make_fixture(root: Path, entries: dict[str, tuple[dict, list]]) -> Fixture:
    fixture = Fixture(root)
    for path, (document, results) in entries.items():
        fixture.add(path, document, results)
    fixture.write_export()
    return fixture


# --------------------------------------------------------------------------
# Preservation controls
# --------------------------------------------------------------------------

class PreservationControls(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_capture_preserves_bytes_and_digest(self):
        fixture = make_fixture(self.root, {TIMING: (timing_document(), timing_results(timing_document()))})
        document = fixture.capture()
        source = document["sources"][0]
        digest = source["raw"]["sha256"]
        self.assertEqual(digest, source["raw"]["address"].split(":")[-1])
        stored = (self.root / "_store" / digest).read_bytes()
        self.assertEqual(preservation.sha256_bytes(stored), digest)
        self.assertEqual(stored, (self.root / TIMING).read_bytes())
        self.assertEqual(source["raw"]["byte_length"], len(stored))

    def test_capture_is_deterministic(self):
        fixture = make_fixture(self.root, {TIMING: (timing_document(), timing_results(timing_document()))})
        first = preservation.dump_json(fixture.capture())
        second = preservation.dump_json(fixture.capture())
        self.assertEqual(first, second)

    def test_certified_source_verifies(self):
        fixture = make_fixture(self.root, {TIMING: (timing_document(), timing_results(timing_document()))})
        document = fixture.capture()
        report = fixture.verify(document)
        self.assertEqual(report["refusals"], [])
        self.assertTrue(report["checked"][0]["certified"])

    def test_verify_refuses_missing_raw_bytes(self):
        fixture = make_fixture(self.root, {TIMING: (timing_document(), timing_results(timing_document()))})
        document = fixture.capture()
        digest = document["sources"][0]["raw"]["sha256"]
        (self.root / "_store" / digest).unlink()
        with self.assertRaises(preservation.Refusal) as raised:
            fixture.verify(document)
        self.assertEqual(raised.exception.code, preservation.R_RAW_ABSENT)

    def test_verify_refuses_corrupt_raw_bytes(self):
        fixture = make_fixture(self.root, {TIMING: (timing_document(), timing_results(timing_document()))})
        document = fixture.capture()
        digest = document["sources"][0]["raw"]["sha256"]
        (self.root / "_store" / digest).write_bytes(b"{}")
        with self.assertRaises(preservation.Refusal) as raised:
            fixture.verify(document)
        self.assertEqual(raised.exception.code, preservation.R_DIGEST_MISMATCH)

    def test_verify_refuses_changed_bytes_with_old_export_digest(self):
        fixture = make_fixture(self.root, {TIMING: (timing_document(), timing_results(timing_document()))})
        document = fixture.capture()
        changed = timing_document(primitives=3)
        fixture._write_record(TIMING, changed)
        with self.assertRaises(preservation.Refusal) as raised:
            fixture.verify(document)
        self.assertEqual(raised.exception.code, preservation.R_STALE_REEXPORT)

    def test_verify_refuses_changed_bytes_with_new_export_digest(self):
        fixture = make_fixture(self.root, {TIMING: (timing_document(), timing_results(timing_document()))})
        document = fixture.capture()
        fixture._write_record(TIMING, timing_document(primitives=3))
        new_digest = preservation.sha256_bytes((self.root / TIMING).read_bytes())
        fixture.write_export({TIMING: new_digest})
        with self.assertRaises(preservation.Refusal) as raised:
            fixture.verify(document)
        self.assertEqual(raised.exception.code, preservation.R_MANIFEST_STALE)

    def test_verify_refuses_missing_invocation_and_instrument(self):
        fixture = make_fixture(self.root, {SECRETS: (secrets_document(), secrets_results(secrets_document()))})
        document = fixture.capture()
        self.assertFalse(document["sources"][0]["certification"]["certified"])
        self.assertEqual(
            document["sources"][0]["certification"]["refusal"],
            preservation.R_NO_INVOCATION_OR_INSTRUMENT,
        )
        self.assertEqual(len(document["refusals"]), 1)
        with self.assertRaises(preservation.Refusal) as raised:
            fixture.verify(document)
        self.assertEqual(raised.exception.code, preservation.R_NO_INVOCATION_OR_INSTRUMENT)

    def test_verify_refuses_a_different_producing_tool(self):
        fixture = make_fixture(self.root, {TIMING: (timing_document(), timing_results(timing_document()))})
        document = fixture.capture()
        document["tool"]["sha256"] = "0" * 64
        with self.assertRaises(preservation.Refusal) as raised:
            fixture.verify(document)
        self.assertEqual(raised.exception.code, preservation.R_TOOL_IDENTITY)

    def test_capture_refuses_an_unreadable_native_record(self):
        fixture = make_fixture(self.root, {TIMING: (timing_document(), timing_results(timing_document()))})
        (self.root / TIMING).unlink()
        with self.assertRaises(preservation.Refusal) as raised:
            fixture.capture()
        self.assertEqual(raised.exception.code, preservation.R_UNREADABLE)

    def test_capture_refuses_invalid_json(self):
        fixture = make_fixture(self.root, {TIMING: (timing_document(), timing_results(timing_document()))})
        (self.root / TIMING).write_bytes(b"{not json")
        with self.assertRaises(preservation.Refusal) as raised:
            fixture.capture()
        self.assertEqual(raised.exception.code, preservation.R_UNREADABLE)

    def test_capture_refuses_population_mismatch_without_bound(self):
        document = curl_document(residual=3, population=5, with_bound=False)
        fixture = make_fixture(self.root, {CURL: (document, curl_results(document))})
        with self.assertRaises(preservation.Refusal) as raised:
            fixture.capture()
        self.assertEqual(raised.exception.code, preservation.R_POPULATION)

    def test_capture_refuses_declared_population_disagreement(self):
        document = curl_document(residual=3, population=5, with_bound=True, totals=4)
        fixture = make_fixture(self.root, {CURL: (document, curl_results(document))})
        with self.assertRaises(preservation.Refusal) as raised:
            fixture.capture()
        self.assertEqual(raised.exception.code, preservation.R_POPULATION)

    def test_bound_without_statement_of_what_was_not_examined_is_refused(self):
        with self.assertRaises(preservation.Refusal) as raised:
            preservation.bound(
                kind="truncation",
                population=5,
                sample=3,
                omitted=2,
                members_recorded=False,
                what_was_not_examined="",
                source="precision.residual_sites_bound",
            )
        self.assertEqual(raised.exception.code, preservation.R_BOUND_UNEXPLAINED)

        fixture = make_fixture(self.root, {TIMING: (timing_document(), timing_results(timing_document()))})
        document = fixture.capture()
        document["sources"][0]["bounds"][0]["what_was_not_examined"] = ""
        with self.assertRaises(preservation.Refusal) as raised:
            fixture.verify(document)
        self.assertEqual(raised.exception.code, preservation.R_BOUND_UNEXPLAINED)


# --------------------------------------------------------------------------
# Reconciliation controls
# --------------------------------------------------------------------------

class ReconciliationControls(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _timing_reconciliation(self, results=None, record=None):
        record = record or timing_document()
        fixture = make_fixture(
            self.root, {TIMING: (record, results or timing_results(record))}
        )
        manifest = fixture.capture()
        sarif = fixture.write_export()
        return fixture, manifest, preservation.reconcile(self.root, manifest, sarif)

    def test_truncated_population_is_bounded_not_a_census(self):
        document = curl_document(residual=3, population=5, with_bound=True)
        fixture = make_fixture(self.root, {CURL: (document, curl_results(document))})
        manifest = fixture.capture()
        sarif = fixture.write_export()
        reconciliation = preservation.reconcile(self.root, manifest, sarif)
        run = reconciliation["runs"][0]
        block = [item for item in run["blocks"] if item["name"] == "residual_sites"][0]
        self.assertEqual(block["declared"], 5)
        self.assertEqual(block["enumerated"], 3)
        self.assertEqual(block["exported_members"], 3)
        self.assertEqual(block["unidentified"], 2)
        self.assertFalse(block["bound"]["members_recorded"])
        self.assertEqual(block["coverage"], "TRUNCATED_BOUNDED")
        self.assertFalse(block["covers_population"])
        self.assertFalse(run["coverage"]["covers_population"])
        self.assertEqual(run["difference"]["native_members_outside_export"], 2)
        self.assertEqual(run["difference"]["export_members_absent_from_native"], 0)
        with self.assertRaises(preservation.Refusal) as raised:
            preservation.assert_covers_population(run)
        self.assertEqual(raised.exception.code, preservation.R_COVERAGE_CLAIM)

    def test_complete_population_admits_coverage(self):
        fixture, manifest, reconciliation = self._timing_reconciliation()
        run = reconciliation["runs"][0]
        self.assertTrue(run["coverage"]["covers_population"])
        preservation.assert_covers_population(run)  # must not raise
        self.assertEqual(run["difference"]["native_members_outside_export"], 0)

    def test_reconcile_refuses_fabricated_member(self):
        record = timing_document(primitives=2, not_run=2)
        results = timing_results(record) + [("A1-TIMING-NOT-RUN", "not_run[9]")]
        fixture = make_fixture(self.root, {TIMING: (record, results)})
        manifest = fixture.capture()
        sarif = fixture.write_export()
        with self.assertRaises(preservation.Refusal) as raised:
            preservation.reconcile(self.root, manifest, sarif)
        self.assertEqual(raised.exception.code, preservation.R_FABRICATED)

    def test_reconcile_refuses_unaccounted_member(self):
        record = timing_document(primitives=2, not_run=2)
        results = [item for item in timing_results(record) if item[1] != "not_run[1]"]
        fixture = make_fixture(self.root, {TIMING: (record, results)})
        manifest = fixture.capture()
        sarif = fixture.write_export()
        with self.assertRaises(preservation.Refusal) as raised:
            preservation.reconcile(self.root, manifest, sarif)
        self.assertEqual(raised.exception.code, preservation.R_UNACCOUNTED)

    def test_reconcile_refuses_unrouted_result(self):
        record = timing_document()
        results = timing_results(record) + [("A1-TIMING-NOT-RUN", "some_other_block")]
        fixture = make_fixture(self.root, {TIMING: (record, results)})
        manifest = fixture.capture()
        sarif = fixture.write_export()
        with self.assertRaises(preservation.Refusal) as raised:
            preservation.reconcile(self.root, manifest, sarif)
        self.assertEqual(raised.exception.code, preservation.R_UNROUTED)

    def test_reconcile_refuses_a_rescoped_declared_omission(self):
        document = adjudication_document()
        fixture = make_fixture(
            self.root,
            {"evidence/b85c-adjudication.json": (document, adjudication_results(document))},
        )
        fixture.not_projected["evidence/b85c-adjudication.json"] = [
            {"block": "item1..item5", "count": 5, "reason": "prose"},
            {"block": "non_claims", "count": 1, "reason": "prose"},
        ]
        sarif = fixture.write_export()
        manifest = fixture.capture()
        with self.assertRaises(preservation.Refusal) as raised:
            preservation.reconcile(self.root, manifest, sarif)
        self.assertEqual(raised.exception.code, preservation.R_POPULATION)

    def test_matching_declared_omission_reconciles(self):
        document = adjudication_document()
        fixture = make_fixture(
            self.root,
            {"evidence/b85c-adjudication.json": (document, adjudication_results(document))},
        )
        fixture.not_projected["evidence/b85c-adjudication.json"] = [
            {"block": "item1..item5", "count": 5, "reason": "prose"},
            {"block": "non_claims", "count": 2, "reason": "prose"},
        ]
        sarif = fixture.write_export()
        manifest = fixture.capture()
        reconciliation = preservation.reconcile(self.root, manifest, sarif)
        run = reconciliation["runs"][0]
        self.assertTrue(run["coverage"]["covers_population"])
        self.assertEqual(run["difference"]["declared_scope_members_not_emitted"], 7)

    def test_check_reconciliation_refuses_a_reused_digest(self):
        fixture, manifest, reconciliation = self._timing_reconciliation()
        before = preservation.check_reconciliation(self.root, reconciliation, manifest)
        self.assertEqual(before["export"], "verified")

        fixture._write_record(TIMING, timing_document(primitives=3))
        new_digest = preservation.sha256_bytes((self.root / TIMING).read_bytes())
        fixture.write_export({TIMING: new_digest})
        with self.assertRaises(preservation.Refusal) as raised:
            preservation.check_reconciliation(self.root, reconciliation, manifest)
        self.assertEqual(raised.exception.code, preservation.R_DIGEST_MISMATCH)


# --------------------------------------------------------------------------
# Real-data controls
# --------------------------------------------------------------------------

class RealRecordControls(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = Path(self._tmp.name) / "store"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_real_curl_reconciliation_reports_200_of_449(self):
        manifest = preservation.capture(
            REPO_ROOT, sources=[CURL, TIMING], store_root=self.store
        )
        reconciliation = preservation.reconcile(REPO_ROOT, manifest)
        curl = [run for run in reconciliation["runs"] if run["record"] == CURL][0]
        block = [item for item in curl["blocks"] if item["name"] == "residual_sites"][0]
        self.assertEqual(block["declared"], 449)
        self.assertEqual(block["enumerated"], 200)
        self.assertEqual(block["exported_members"], 200)
        self.assertEqual(block["exported_results"], 201)  # 200 members + 1 bound result
        self.assertEqual(block["unidentified"], 249)
        self.assertFalse(block["bound"]["members_recorded"])
        self.assertEqual(block["coverage"], "TRUNCATED_BOUNDED")
        self.assertFalse(curl["coverage"]["covers_population"])
        self.assertEqual(curl["difference"]["native_members_outside_export"], 249)
        self.assertEqual(curl["difference"]["export_members_absent_from_native"], 0)
        with self.assertRaises(preservation.Refusal):
            preservation.assert_covers_population(curl)

    def test_real_capture_certifies_three_and_refuses_three(self):
        manifest = preservation.capture(REPO_ROOT, store_root=self.store)
        self.assertEqual(len(manifest["sources"]), 6)
        certified = {
            source["record"]
            for source in manifest["sources"]
            if source["certification"]["certified"]
        }
        self.assertEqual(
            certified,
            {
                "evidence/closure-curl-049.json",
                "evidence/etp-t4/SAFETY-SITES.json",
                "evidence/timing-bn-findings.json",
            },
        )
        refused = {item["record"] for item in manifest["refusals"]}
        self.assertEqual(
            refused,
            {
                "evidence/b85c-adjudication.json",
                "evidence/b85c-row-reconciliation.json",
                "evidence/etp-t7/SECRETS.json",
            },
        )
        for item in manifest["refusals"]:
            self.assertEqual(item["code"], preservation.R_NO_INVOCATION_OR_INSTRUMENT)

    def test_real_reconciliation_covers_every_emitted_result(self):
        manifest = preservation.capture(REPO_ROOT, store_root=self.store)
        reconciliation = preservation.reconcile(REPO_ROOT, manifest)
        self.assertEqual(reconciliation["summary"]["runs"], 6)
        self.assertEqual(reconciliation["summary"]["results"], 4245)
        self.assertEqual(
            reconciliation["summary"]["results_reconciled"],
            reconciliation["summary"]["results"],
        )
        self.assertEqual(reconciliation["summary"]["fabricated"], 0)
        self.assertEqual(reconciliation["summary"]["unaccounted"], 0)
        for run in reconciliation["runs"]:
            self.assertTrue(run["digest_match"])
            self.assertTrue(run["projection_consistent"])
        safety = [
            run
            for run in reconciliation["runs"]
            if run["record"] == "evidence/etp-t4/SAFETY-SITES.json"
        ][0]
        suppressions = [
            item for item in safety["blocks"] if item["name"] == "suppressions"
        ][0]
        self.assertEqual(suppressions["declared"], 1999)
        self.assertEqual(suppressions["enumerated"], 0)
        self.assertEqual(suppressions["aggregate_results"], 1)
        self.assertEqual(suppressions["coverage"], "AGGREGATE_ONLY")
        self.assertFalse(safety["coverage"]["covers_population"])


if __name__ == "__main__":
    unittest.main()
