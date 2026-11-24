#!/usr/bin/env python3
"""Controls for the B0 protocol and infrastructure audit.

One control per refusal code, plus the rules the item exists to enforce: every
registry entry is sourced, no digest is invented, presence is checked, a service
claim is refused, a witness is not asserted, the real audit passes, the producer
is deterministic, the command line exits 0/1/2 and the normative document is in
step with the tool.

The tests read the committed records.  A mutant is always a deep copy in memory
or a temporary file; no committed record is modified.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
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

import protocol_audit as pa  # noqa: E402

B0 = REPO_ROOT / "evidence/b0"
REGISTRY_PATH = B0 / "REGISTRY.json"
SERVICE_PATH = B0 / "SERVICE-CONFIGURATION.json"
BUILD = B0 / "build_evidence.py"
DOC = REPO_ROOT / "docs/PROTOCOL-AUDIT.md"
ADDENDUM = REPO_ROOT / pa.ADDENDUM

ALL_CODES = set(pa.REFUSAL_CODES) | set(pa.INVOCATION_CODES)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _document() -> str:
    return ADDENDUM.read_text(encoding="utf-8")


def _codes(findings: list[tuple[str, str]]) -> set[str]:
    return {code for code, _ in findings}


def _registry() -> dict:
    return _load(REGISTRY_PATH)


def _service() -> dict:
    return _load(SERVICE_PATH)


def _component(registry: dict, cid: str) -> dict:
    for component in registry["components"]:
        if component["id"] == cid:
            return component
    raise AssertionError(f"no component {cid}")


def _check_registry(registry: dict) -> list[tuple[str, str]]:
    return pa.check_registry(registry, REPO_ROOT, _document(), live=False)


def _check_service(service: dict, registry: dict | None = None) -> list[tuple[str, str]]:
    return pa.check_service(
        service, registry if registry is not None else _registry(), REPO_ROOT, _document()
    )


def _producer():
    spec = importlib.util.spec_from_file_location("b0_build_evidence", BUILD)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _run_cli(argv: list[str]) -> tuple[int, str]:
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = pa.main(argv)
    except SystemExit as exc:  # the parser raises SystemExit(2) on a usage error
        code = int(exc.code or 0)
    return code, buffer.getvalue()


class RegistryTests(unittest.TestCase):
    def test_the_real_registry_passes(self) -> None:
        self.assertEqual(_check_registry(_registry()), [])

    def test_every_required_component_is_present(self) -> None:
        present = {c["id"] for c in _registry()["components"]}
        for required in pa.REQUIRED_COMPONENTS:
            self.assertIn(required, present)

    def test_every_entry_has_a_source_version_role_and_presence(self) -> None:
        for component in _registry()["components"]:
            self.assertTrue(component["source"]["clause"], component["id"])
            self.assertEqual(component["source"]["path"], pa.ADDENDUM, component["id"])
            self.assertIn("version", component, component["id"])
            self.assertTrue(component["role"], component["id"])
            self.assertIn("presence", component, component["id"])
            self.assertIsInstance(component["presence"]["pinned"], bool, component["id"])

    def test_every_version_date_commit_and_digest_appears_in_its_clause(self) -> None:
        document = _document()
        for component in _registry()["components"]:
            text = pa.clause_text(document, component["source"]["clause"])
            self.assertIsNotNone(text, component["id"])
            for field in ("version", "releaseDate", "upstreamCommit", "observedDate"):
                value = component.get(field)
                if value is not None:
                    self.assertIn(value, text, f"{component['id']}.{field}")
            digest = component["artefact"]["digest"]
            if digest is not None:
                self.assertIn(digest, text, f"{component['id']}.digest")

    def test_no_entry_claims_an_installed_or_executable_component(self) -> None:
        for component in _registry()["components"]:
            self.assertFalse(component["presence"]["installed"], component["id"])
            self.assertFalse(component["presence"]["executable"], component["id"])
            self.assertFalse(component.get("serviceClaim"), component["id"])

    def test_only_one_digest_is_recorded_and_it_is_the_addendum_digest(self) -> None:
        recorded = [
            c["artefact"]["digest"]
            for c in _registry()["components"]
            if c["artefact"]["digest"] is not None
        ]
        self.assertEqual(recorded, [pa_ref_digest()])

    def test_the_summary_matches_the_entries(self) -> None:
        registry = _registry()
        summary = registry["summary"]
        self.assertEqual(summary["components"], len(registry["components"]))
        self.assertEqual(
            summary["pinned"],
            sum(1 for c in registry["components"] if c["presence"]["pinned"]),
        )
        self.assertEqual(summary["servicesReachable"], 0)

    def test_every_feature_is_sourced(self) -> None:
        document = _document()
        for component in _registry()["components"]:
            for field in ("supportedFeatures", "unsupportedFeatures"):
                for feature in component[field]:
                    clause = feature.get("clause")
                    self.assertIn(clause, pa.ALLOWED_CLAUSES, component["id"])
                    self.assertIsNotNone(
                        pa.clause_text(document, clause), f"{component['id']} {clause}"
                    )

    def test_an_invented_digest_is_refused(self) -> None:
        registry = _registry()
        _component(registry, "rekor-tiles-v2.4.2")["artefact"]["digest"] = "sha256:" + "a" * 64
        self.assertIn(pa.PA_REFUSED_INVENTED_DIGEST, _codes(_check_registry(registry)))

    def test_a_malformed_digest_is_refused(self) -> None:
        registry = _registry()
        _component(registry, "rekor-tiles-v2.4.2")["artefact"]["digest"] = "sha256:not-hex"
        self.assertIn(pa.PA_REFUSED_INVENTED_DIGEST, _codes(_check_registry(registry)))

    def test_a_null_digest_without_a_reason_is_refused(self) -> None:
        registry = _registry()
        _component(registry, "c2sp-tlog-tiles-v1.0.0")["artefact"]["digestNullReason"] = ""
        self.assertIn(pa.PA_REFUSED_DIGEST_UNSTATED, _codes(_check_registry(registry)))

    def test_an_unsourced_version_is_refused(self) -> None:
        registry = _registry()
        _component(registry, "rekor-tiles-v2.4.2")["version"] = "v9.9.9"
        self.assertIn(pa.PA_REFUSED_UNSOURCED_VERSION, _codes(_check_registry(registry)))

    def test_a_null_version_without_a_reason_is_refused(self) -> None:
        registry = _registry()
        _component(registry, "sigstore-signing-config-v1-endpoint")["versionNullReason"] = ""
        self.assertIn(pa.PA_REFUSED_UNSOURCED_VERSION, _codes(_check_registry(registry)))

    def test_an_unsourced_release_date_is_refused(self) -> None:
        registry = _registry()
        _component(registry, "rekor-tiles-v2.4.2")["releaseDate"] = "2030-01-01"
        self.assertIn(pa.PA_REFUSED_UNSOURCED_VERSION, _codes(_check_registry(registry)))

    def test_an_installed_entry_without_a_check_is_refused(self) -> None:
        registry = _registry()
        presence = _component(registry, "rekor-tiles-v2.4.2")["presence"]
        presence["installed"] = True
        presence["checkedBy"] = None
        self.assertIn(pa.PA_REFUSED_UNCHECKED_PRESENCE, _codes(_check_registry(registry)))

    def test_an_installed_entry_with_an_absent_check_is_refused(self) -> None:
        registry = _registry()
        presence = _component(registry, "rekor-tiles-v2.4.2")["presence"]
        presence["installed"] = True
        presence["checkedBy"] = "command-v-rekor-server"
        self.assertIn(pa.PA_REFUSED_UNCHECKED_PRESENCE, _codes(_check_registry(registry)))

    def test_an_installed_entry_with_an_unrecorded_check_is_refused(self) -> None:
        registry = _registry()
        presence = _component(registry, "rekor-tiles-v2.4.2")["presence"]
        presence["installed"] = True
        presence["checkedBy"] = "a-check-that-was-never-run"
        self.assertIn(pa.PA_REFUSED_UNCHECKED_PRESENCE, _codes(_check_registry(registry)))

    def test_a_service_claim_is_refused(self) -> None:
        registry = _registry()
        _component(registry, "rekor-tiles-v2.4.2")["serviceClaim"] = True
        self.assertIn(pa.PA_REFUSED_SERVICE_CLAIM, _codes(_check_registry(registry)))

    def test_top_level_service_reachability_is_refused(self) -> None:
        registry = _registry()
        registry["serviceReachable"] = True
        self.assertIn(pa.PA_REFUSED_SERVICE_CLAIM, _codes(_check_registry(registry)))

    def test_a_missing_component_is_refused(self) -> None:
        registry = _registry()
        registry["components"] = [
            c for c in registry["components"] if c["id"] != "c2sp-tlog-checkpoint-v1.1.0"
        ]
        findings = _codes(_check_registry(registry))
        self.assertIn(pa.PA_REFUSED_MISSING_MEMBER, findings)
        self.assertIn(pa.PA_REFUSED_OBSERVATION_DRIFT, findings)

    def test_an_unknown_clause_is_refused(self) -> None:
        registry = _registry()
        _component(registry, "rekor-tiles-v2.4.2")["source"]["clause"] = "B.3.4"
        self.assertIn(pa.PA_REFUSED_CLAUSE_UNKNOWN, _codes(_check_registry(registry)))

    def test_a_supported_feature_without_a_clause_is_refused(self) -> None:
        registry = _registry()
        _component(registry, "rekor-tiles-v2.4.2")["supportedFeatures"][0].pop("clause")
        self.assertIn(pa.PA_REFUSED_UNSOURCED_FEATURE, _codes(_check_registry(registry)))

    def test_a_feature_with_an_unknown_clause_is_refused(self) -> None:
        registry = _registry()
        _component(registry, "rekor-tiles-v2.4.2")["supportedFeatures"][0]["clause"] = "B.99"
        self.assertIn(pa.PA_REFUSED_CLAUSE_UNKNOWN, _codes(_check_registry(registry)))

    def test_an_unknown_role_is_refused(self) -> None:
        registry = _registry()
        _component(registry, "rekor-tiles-v2.4.2")["role"] = ["witness"]
        self.assertIn(pa.PA_REFUSED_ENTRY_INCOMPLETE, _codes(_check_registry(registry)))

    def test_the_real_digest_is_the_one_the_addendum_records(self) -> None:
        text = pa.clause_text(_document(), "B.3.2")
        self.assertIsNotNone(text)
        self.assertIn(pa_ref_digest(), text)


class ServiceTests(unittest.TestCase):
    def test_the_real_service_configuration_passes(self) -> None:
        self.assertEqual(_check_service(_service()), [])

    def test_every_client_support_module_and_code_is_present(self) -> None:
        service = _service()
        for entry in service["clientSupport"]:
            module = REPO_ROOT / entry["module"]
            self.assertTrue(module.exists(), entry["item"])
            self.assertTrue((REPO_ROOT / entry["doc"]).exists(), entry["item"])
            source = module.read_text(encoding="utf-8")
            for code in entry["refusalCodes"]:
                self.assertIn(code, source, f"{entry['item']}:{code}")
                self.assertTrue(code.startswith(entry["refusalPrefix"]), entry["item"])

    def test_the_client_support_covers_every_required_item(self) -> None:
        items = {entry["item"] for entry in _service()["clientSupport"]}
        for required in pa.REQUIRED_CLIENT_SUPPORT:
            self.assertIn(required, items)

    def test_the_five_support_states_are_the_measured_ones(self) -> None:
        service = _service()
        by_item = {entry["item"]: entry for entry in service["clientSupport"]}
        self.assertEqual(by_item["A12"]["observed"][0]["equals"], 0)
        self.assertEqual(by_item["A16"]["observed"][0]["equals"], 0)
        self.assertEqual(by_item["A18"]["observed"][0]["equals"], 0)
        self.assertEqual(by_item["A10"]["observed"][0]["equals"], 4)
        self.assertEqual(by_item["A9"]["observed"][0]["equals"], 4)

    def test_an_observation_that_drifted_is_refused(self) -> None:
        service = _service()
        for entry in service["clientSupport"]:
            if entry["item"] == "A12":
                entry["observed"][0]["equals"] = 1
        self.assertIn(pa.PA_REFUSED_OBSERVATION_DRIFT, _codes(_check_service(service)))

    def test_the_finding_is_recorded_and_not_verified(self) -> None:
        finding = _service()["serviceConfigurationFinding"]
        self.assertEqual(finding["state"], "RECORDED")
        self.assertFalse(finding["verifiedHere"])
        self.assertEqual(finding["clause"], "B.3.3")
        self.assertEqual(finding["observedDate"], "2026-10-22")

    def test_a_verified_finding_is_refused(self) -> None:
        service = _service()
        service["serviceConfigurationFinding"]["state"] = "VERIFIED"
        self.assertIn(pa.PA_REFUSED_SERVICE_CLAIM, _codes(_check_service(service)))
        service = _service()
        service["serviceConfigurationFinding"]["verifiedHere"] = True
        self.assertIn(pa.PA_REFUSED_SERVICE_CLAIM, _codes(_check_service(service)))

    def test_a_finding_date_outside_its_clause_is_refused(self) -> None:
        service = _service()
        service["serviceConfigurationFinding"]["observedDate"] = "2026-11-24"
        self.assertIn(pa.PA_REFUSED_UNSOURCED_VERSION, _codes(_check_service(service)))

    def test_there_are_exactly_three_unresolved_tensions(self) -> None:
        service = _service()
        tensions = service["tensions"]
        self.assertEqual([t["id"] for t in tensions], ["T1", "T2", "T3"])
        text = pa.clause_text(_document(), "B.3.3")
        self.assertIsNotNone(text)
        for tension in tensions:
            self.assertEqual(tension["clause"], "B.3.3")
            self.assertTrue(tension["consequence"])
            self.assertFalse(tension["resolved"])

    def test_a_missing_tension_is_refused(self) -> None:
        service = _service()
        service["tensions"] = service["tensions"][:2]
        self.assertIn(pa.PA_REFUSED_MISSING_MEMBER, _codes(_check_service(service)))

    def test_a_resolved_tension_is_refused(self) -> None:
        service = _service()
        service["tensions"][0]["resolved"] = True
        self.assertIn(pa.PA_REFUSED_SERVICE_CLAIM, _codes(_check_service(service)))

    def test_a_witness_marked_available_is_refused(self) -> None:
        service = _service()
        service["witnesses"]["classes"][0]["available"] = True
        self.assertIn(pa.PA_REFUSED_WITNESS_CLAIM, _codes(_check_service(service)))

    def test_a_witness_population_above_zero_is_refused(self) -> None:
        for field, value in (("operators", 1), ("keys", 1), ("quorum", 2), ("independent", True)):
            service = _service()
            service["witnesses"]["witnessSet"][field] = value
            self.assertIn(
                pa.PA_REFUSED_WITNESS_CLAIM,
                _codes(_check_service(service)),
                field,
            )

    def test_a_missing_witness_class_is_refused(self) -> None:
        service = _service()
        service["witnesses"]["classes"] = [
            c for c in service["witnesses"]["classes"] if c["id"] != "rfc3161-tsa"
        ]
        self.assertIn(pa.PA_REFUSED_MISSING_MEMBER, _codes(_check_service(service)))

    def test_every_witness_is_unavailable_and_says_why(self) -> None:
        service = _service()
        self.assertEqual(len(service["witnesses"]["classes"]), len(pa.REQUIRED_WITNESSES))
        for entry in service["witnesses"]["classes"]:
            self.assertFalse(entry["available"], entry["id"])
            self.assertTrue(entry["checkedBy"], entry["id"])
            self.assertTrue((REPO_ROOT / entry["record"]).exists(), entry["id"])

    def test_a_met_trust_assumption_is_refused(self) -> None:
        service = _service()
        service["trustAssumptions"][0]["state"] = "MET"
        self.assertIn(pa.PA_REFUSED_SERVICE_CLAIM, _codes(_check_service(service)))

    def test_a_missing_trust_assumption_is_refused(self) -> None:
        service = _service()
        service["trustAssumptions"] = service["trustAssumptions"][:5]
        self.assertIn(pa.PA_REFUSED_MISSING_MEMBER, _codes(_check_service(service)))

    def test_every_trust_assumption_is_unmet_and_names_a_record(self) -> None:
        service = _service()
        self.assertEqual(
            [t["id"] for t in service["trustAssumptions"]], list(pa.REQUIRED_TRUST)
        )
        for entry in service["trustAssumptions"]:
            self.assertEqual(entry["state"], "UNMET", entry["id"])
            self.assertTrue((REPO_ROOT / entry["record"]).exists(), entry["id"])

    def test_an_established_claim_needs_existing_evidence(self) -> None:
        service = _service()
        for claim in service["claimsMade"]:
            if claim["established"]:
                self.assertIsNotNone(claim["evidence"], claim["id"])
                self.assertTrue((REPO_ROOT / claim["evidence"]).exists(), claim["id"])

    def test_an_established_claim_without_evidence_is_refused(self) -> None:
        service = _service()
        for claim in service["claimsMade"]:
            if claim["established"]:
                claim["evidence"] = "docs/DOES-NOT-EXIST.md"
                break
        self.assertIn(pa.PA_REFUSED_UNEVIDENCED_CLAIM, _codes(_check_service(service)))

    def test_no_service_claim_is_established(self) -> None:
        service = _service()
        service_claims = [c for c in service["claimsMade"] if c["kind"] == "service"]
        self.assertTrue(service_claims)
        for claim in service_claims:
            self.assertFalse(claim["established"], claim["id"])

    def test_an_established_service_claim_is_refused(self) -> None:
        service = _service()
        for claim in service["claimsMade"]:
            if claim["kind"] == "service":
                claim["established"] = True
                claim["evidence"] = "docs/ETP-ADDENDUM-B.md"
                break
        self.assertIn(pa.PA_REFUSED_SERVICE_CLAIM, _codes(_check_service(service)))

    def test_the_finding_is_not_established_here(self) -> None:
        claims = {c["id"]: c for c in _service()["claimsMade"]}
        self.assertFalse(claims["CLM-14"]["established"])
        self.assertEqual(claims["CLM-14"]["evidence"], "docs/ETP-ADDENDUM-B.md")

    def test_the_record_states_non_claims(self) -> None:
        self.assertTrue(_service()["nonClaims"])


class FreezeTests(unittest.TestCase):
    def test_the_two_freeze_members_are_declared_and_exist(self) -> None:
        self.assertEqual(pa.check_freeze_members(REPO_ROOT), [])
        freeze = _load(REPO_ROOT / pa.FREEZE)
        declared = {m["id"]: m["path"] for m in freeze["members"]}
        self.assertEqual(declared["b0-registry"], "evidence/b0/REGISTRY.json")
        self.assertEqual(
            declared["b0-service-configuration"], "evidence/b0/SERVICE-CONFIGURATION.json"
        )

    def test_a_missing_freeze_member_is_refused(self) -> None:
        freeze = _load(REPO_ROOT / pa.FREEZE)
        freeze["members"] = [m for m in freeze["members"] if m["id"] != "b0-registry"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "evidence/a17").mkdir(parents=True)
            (root / "evidence/a17/FREEZE-forward.json").write_text(
                json.dumps(freeze), encoding="utf-8"
            )
            (root / "evidence/b0").mkdir(parents=True)
            (root / "evidence/b0/REGISTRY.json").write_text("{}", encoding="utf-8")
            (root / "evidence/b0/SERVICE-CONFIGURATION.json").write_text("{}", encoding="utf-8")
            findings = pa.check_freeze_members(root)
        self.assertIn(pa.PA_REFUSED_MISSING_MEMBER, _codes(findings))


class DeterminismTests(unittest.TestCase):
    def test_the_checks_are_deterministic(self) -> None:
        registry = _registry()
        service = _service()
        self.assertEqual(_check_registry(registry), _check_registry(registry))
        self.assertEqual(_check_service(service, registry), _check_service(service, registry))

    def test_the_producer_is_deterministic(self) -> None:
        producer = _producer()
        document = _document()
        first = producer._serialise(producer.build_registry(document))
        second = producer._serialise(producer.build_registry(document))
        self.assertEqual(first, second)
        first_service = producer._serialise(producer.build_service(document))
        second_service = producer._serialise(producer.build_service(document))
        self.assertEqual(first_service, second_service)

    def test_the_committed_records_are_the_current_build(self) -> None:
        producer = _producer()
        document = _document()
        self.assertEqual(
            REGISTRY_PATH.read_bytes(), producer._serialise(producer.build_registry(document))
        )
        self.assertEqual(
            SERVICE_PATH.read_bytes(), producer._serialise(producer.build_service(document))
        )


class CliTests(unittest.TestCase):
    def test_registry_exits_zero_and_prints_the_code(self) -> None:
        code, output = _run_cli(["registry"])
        self.assertEqual(code, 0, output)
        self.assertIn("codes=NONE", output)
        for component in _registry()["components"]:
            self.assertIn(f"component={component['id']}", output)

    def test_audit_exits_zero_and_reports_the_finding(self) -> None:
        code, output = _run_cli(["audit"])
        self.assertEqual(code, 0, output)
        self.assertIn("codes=NONE", output)
        self.assertIn("finding=SCF-1 state=RECORDED clause=B.3.3 observed=2026-10-22", output)
        self.assertIn("witnesses=5 available=0", output)
        self.assertIn("trust=6 unmet=6", output)

    def test_claims_exits_zero_and_states_every_false_service_claim(self) -> None:
        code, output = _run_cli(["claims"])
        self.assertEqual(code, 0, output)
        self.assertIn("codes=NONE", output)
        self.assertIn("claim=CLM-01 kind=service established=False", output)
        self.assertIn("witnessSet operators=0 keys=0 quorum=None independent=False", output)

    def test_a_tampered_registry_exits_one_and_prints_the_code(self) -> None:
        registry = _registry()
        _component(registry, "rekor-tiles-v2.4.2")["artefact"]["digest"] = "sha256:" + "b" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "REGISTRY.json"
            path.write_text(json.dumps(registry), encoding="utf-8")
            code, output = _run_cli(["registry", "--registry", str(path)])
        self.assertEqual(code, 1, output)
        self.assertIn(f"code={pa.PA_REFUSED_INVENTED_DIGEST}", output)

    def test_a_missing_record_exits_one_and_prints_the_code(self) -> None:
        code, output = _run_cli(["registry", "--registry", "/nonexistent/REGISTRY.json"])
        self.assertEqual(code, 1, output)
        self.assertIn(f"code={pa.PA_REFUSED_MISSING_MEMBER}", output)

    def test_a_malformed_invocation_exits_two_and_prints_the_code(self) -> None:
        code, output = _run_cli(["not-a-command"])
        self.assertEqual(code, 2, output)
        self.assertIn(f"code={pa.PA_REFUSED_USAGE}", output)
        code, output = _run_cli([])
        self.assertEqual(code, 2, output)
        self.assertIn(f"code={pa.PA_REFUSED_USAGE}", output)

    def test_every_refusal_code_is_in_the_table(self) -> None:
        for code in ALL_CODES - {pa.PA_REFUSED_USAGE}:
            self.assertIn(code, pa.REFUSALS)
            self.assertTrue(pa.REFUSALS[code]["condition"])
            self.assertTrue(pa.REFUSALS[code]["prevents"])


class DocumentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DOC.read_text(encoding="utf-8")

    def test_the_document_exists_and_is_not_empty(self) -> None:
        self.assertGreater(len(self.text.splitlines()), 80)

    def test_the_document_names_every_refusal_code(self) -> None:
        for code in ALL_CODES:
            self.assertIn(code, self.text, code)

    def test_the_document_names_every_component(self) -> None:
        for component in _registry()["components"]:
            self.assertIn(component["id"], self.text, component["id"])

    def test_the_document_names_the_finding_tensions_witnesses_and_trust(self) -> None:
        self.assertIn("SCF-1", self.text)
        for tension in ("T1", "T2", "T3"):
            self.assertIn(tension, self.text)
        for witness in pa.REQUIRED_WITNESSES:
            self.assertIn(witness, self.text)
        for trust in pa.REQUIRED_TRUST:
            self.assertIn(trust, self.text)

    def test_the_document_states_not_run(self) -> None:
        self.assertIn("NOT_RUN", self.text)
        self.assertIn("does not", self.text)

    def test_every_enforced_by_names_a_code_or_a_test(self) -> None:
        lines = [
            line.strip()
            for line in self.text.splitlines()
            if line.strip().lower().startswith("enforced by")
        ]
        self.assertTrue(lines)
        token = re.compile(r"`([^`]+)`")
        for line in lines:
            tokens = token.findall(line)
            self.assertTrue(tokens, line)
            for value in tokens:
                self.assertTrue(
                    value in ALL_CODES or value.startswith("test_"),
                    f"{line!r} names {value!r}, which is neither a code nor a test",
                )

    def test_the_document_states_the_pinned_versus_installed_distinction(self) -> None:
        self.assertIn("pinned", self.text.lower())
        self.assertIn("installed", self.text.lower())
        self.assertIn("0 installed", self.text)

    def test_the_document_states_the_non_claims(self) -> None:
        text = self.text.lower()
        self.assertIn("a registry is not a deployment", text)
        self.assertIn("a pinned version is not an admitted service", text)
        self.assertIn("this item runs no rekor", text)


def pa_ref_digest() -> str:
    producer = _producer()
    return producer.RECORDED_DIGEST


if __name__ == "__main__":
    unittest.main()
