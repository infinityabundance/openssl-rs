#!/usr/bin/env python3
"""Controls for forensics/tools/continuous_enforcement.py and the B8 records.

One control per refusal code, the publication claim that must be refused, the
honest NOT_ADMITTED claim that must be accepted, the closed schema enum, the
missing-field case, the enforcement-regression control, determinism, the CLI
exit codes and document synchronisation.

Run directly (`python3 forensics/tools/tests/test_continuous_enforcement.py`) or
with `python3 -m unittest discover -s forensics/tools/tests`.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import continuous_enforcement as ce  # noqa: E402
import release_gate  # noqa: E402

TOOL = TOOLS / "continuous_enforcement.py"
DOCUMENT = REPO / "docs" / "CONTINUOUS-ENFORCEMENT.md"
NONCLAIMS = REPO / "docs" / "TRANSPARENCY-NON-CLAIMS.md"
EVIDENCE = REPO / "evidence" / "b8"
PRODUCER = EVIDENCE / "build_evidence.py"

DIGEST = "a" * 64


def claim_document(*claims: dict[str, Any]) -> dict[str, Any]:
    return {"claims": list(claims)}


def transparency_claim(state: str, authority: str = "repository-policy", **extra: Any) -> dict[str, Any]:
    block: dict[str, Any] = {"state": state}
    block.update(extra)
    return {
        "id": "B8-TEST-001",
        "authority": {"kind": authority},
        "transparency": block,
    }


def write(path: Path, value: Any) -> Path:
    path.write_text(json.dumps(value, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path


class ProfileChecks(unittest.TestCase):
    """The profile records must exist and agree with the addendum."""

    def test_committed_profile_passes(self) -> None:
        self.assertEqual(ce.check_registry(), [])
        self.assertEqual(ce.check_publication(), [])

    def test_profile_absent_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            findings = ce.check_registry(Path(temporary) / "absent.json")
            self.assertEqual([finding.code for finding in findings],
                             ["CE_REFUSED_PROFILE_ABSENT"])

    def test_registry_stale_refused(self) -> None:
        document = ce.load_json(ce.REGISTRY_PATH)
        document["components"][0]["version"] = "v9.9.9"
        with tempfile.TemporaryDirectory() as temporary:
            findings = ce.check_registry(write(Path(temporary) / "stale.json", document))
        self.assertEqual([finding.code for finding in findings],
                         ["CE_REFUSED_REGISTRY_STALE"])
        self.assertIn("v9.9.9", findings[0].detail)

    def test_registry_internal_disagreement_refused(self) -> None:
        document = ce.load_json(ce.REGISTRY_PATH)
        document["summary"]["installed"] = 3
        with tempfile.TemporaryDirectory() as temporary:
            findings = ce.check_registry(write(Path(temporary) / "disagree.json", document))
        self.assertEqual([finding.code for finding in findings],
                         ["CE_REFUSED_REGISTRY_STALE"])


class ClaimChecks(unittest.TestCase):
    """A claim may not assert more transparency than B4 records."""

    def claims(self, document: dict[str, Any]) -> tuple[list[ce.Finding], dict[str, Any]]:
        with tempfile.TemporaryDirectory() as temporary:
            path = write(Path(temporary) / "claims.json", document)
            return ce.check_claims(path)

    def test_publication_claim_refused(self) -> None:
        findings, _ = self.claims(claim_document(transparency_claim(
            "PUBLISHED",
            profile="public-good-rekor-v2",
            statementDigest=DIGEST,
            bundleDigest=DIGEST,
            publishedAt="2026-11-24T00:00:00Z",
        )))
        self.assertIn("CE_REFUSED_PUBLICATION_CLAIM", [finding.code for finding in findings])

    def test_profile_not_admitted_refused(self) -> None:
        findings, _ = self.claims(claim_document(transparency_claim(
            "ADMITTED",
            profile="public-good-rekor-v2",
            statementDigest=DIGEST,
            bundleDigest=DIGEST,
        )))
        self.assertIn("CE_REFUSED_PROFILE_NOT_ADMITTED", [finding.code for finding in findings])

    def test_schema_field_absent_refused(self) -> None:
        findings, _ = self.claims(claim_document(
            transparency_claim("MAYBE", note="free text"),
        ))
        codes = [finding.code for finding in findings]
        self.assertIn("CE_REFUSED_SCHEMA_FIELD_ABSENT", codes)
        detail = " ".join(finding.detail for finding in findings)
        self.assertIn("note", detail)

    def test_unbound_claim_refused(self) -> None:
        findings, _ = self.claims(claim_document(transparency_claim(
            "ADMITTED", profile="public-good-rekor-v2"
        )))
        self.assertIn("CE_REFUSED_UNBOUND_CLAIM", [finding.code for finding in findings])

    def test_missing_field_where_required_refused(self) -> None:
        document = claim_document({
            "id": "B8-TEST-002",
            "authority": {"kind": "public-transparency-log"},
        })
        findings, population = self.claims(document)
        self.assertEqual([finding.code for finding in findings],
                         ["CE_REFUSED_SCHEMA_FIELD_ABSENT"])
        self.assertEqual(population["claimsWithTransparency"], 0)

    def test_honest_not_admitted_accepted(self) -> None:
        findings, population = self.claims(claim_document(transparency_claim(
            "NOT_ADMITTED", profile="public-good-rekor-v2"
        )))
        self.assertEqual(findings, [])
        self.assertEqual(population["claimsWithTransparency"], 1)
        self.assertEqual(population["byState"], {"NOT_ADMITTED": 1})

    def test_a_normal_authority_does_not_require_the_field(self) -> None:
        findings, population = self.claims(claim_document({
            "id": "B8-TEST-003",
            "authority": {"kind": "repository-policy"},
        }))
        self.assertEqual(findings, [])
        self.assertEqual(population["claimsWithTransparency"], 0)

    def test_committed_claims_carry_no_field(self) -> None:
        findings, population = ce.check_claims()
        self.assertEqual(findings, [])
        self.assertEqual(population["claimCount"], 35)
        self.assertEqual(population["claimsWithTransparency"], 0)


class NonClaimsChecks(unittest.TestCase):
    """The public non-claims are an input, not a comment."""

    def test_committed_non_claims_pass(self) -> None:
        self.assertEqual(ce.check_nonclaims(), [])

    def test_nonclaims_absent_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            findings = ce.check_nonclaims(Path(temporary) / "absent.md")
        self.assertEqual([finding.code for finding in findings],
                         ["CE_REFUSED_NONCLAIMS_ABSENT"])

    def test_missing_property_refused(self) -> None:
        text = re.sub(r"(?i)no trusted timestamp", "", NONCLAIMS.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "non-claims.md"
            path.write_text(text, encoding="utf-8")
            findings = ce.check_nonclaims(path)
        self.assertEqual([finding.code for finding in findings],
                         ["CE_REFUSED_NONCLAIMS_ABSENT"])
        self.assertIn("no trusted timestamp", findings[0].detail)

    def test_missing_clause_refused(self) -> None:
        text = NONCLAIMS.read_text(encoding="utf-8").replace("§B.29", "B.29")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "non-claims.md"
            path.write_text(text, encoding="utf-8")
            findings = ce.check_nonclaims(path)
        self.assertEqual([finding.code for finding in findings],
                         ["CE_REFUSED_NONCLAIMS_ABSENT"])


class SchemaChecks(unittest.TestCase):
    """The schema field is defined, closed and conditionally required."""

    def setUp(self) -> None:
        self.schema = ce.load_json(ce.SCHEMA_PATH)

    def test_schema_enum_is_closed(self) -> None:
        fields, states = ce.transparency_definition(self.schema)
        self.assertEqual(list(states), ["NOT_ADMITTED", "ADMITTED", "PUBLISHED"])
        self.assertEqual(set(fields), {
            "state", "profile", "statementDigest", "bundleDigest", "publishedAt",
        })
        block = self.schema["$defs"]["transparency"]
        self.assertIs(block["additionalProperties"], False)
        self.assertEqual(block["properties"]["profile"]["enum"],
                         ["public-good-rekor-v2"])

    def test_schema_requires_field_for_transparency_authority(self) -> None:
        self.assertEqual(ce.transparency_required_authority(self.schema),
                         "public-transparency-log")
        self.assertIn("public-transparency-log",
                      self.schema["$defs"]["authority"]["properties"]["kind"]["enum"])

    def test_state_requirements_are_declared(self) -> None:
        block = self.schema["$defs"]["transparency"]
        requirements = {}
        for rule in block["allOf"]:
            state = rule["if"]["properties"]["state"]["const"]
            requirements[state] = rule["then"]["required"]
        self.assertEqual(requirements["ADMITTED"],
                         ["profile", "statementDigest", "bundleDigest"])
        self.assertEqual(requirements["PUBLISHED"],
                         ["profile", "statementDigest", "bundleDigest", "publishedAt"])

    def test_existing_claims_validate_unchanged(self) -> None:
        document = ce.load_json(ce.CLAIMS_PATH)
        self.assertEqual(len(document["claims"]), 35)
        self.assertFalse(any("transparency" in claim for claim in document["claims"]))


class EnforcementChecks(unittest.TestCase):
    """A gate item or a checked code that disappears is a regression."""

    def setUp(self) -> None:
        self.gate_text = ce.GATE_PATH.read_text(encoding="utf-8")
        self.record = {"refusalCodes": list(ce.REFUSAL_CODES)}
        self.document = DOCUMENT.read_text(encoding="utf-8")

    def test_committed_wiring_passes(self) -> None:
        self.assertEqual(ce.check_enforcement(), [])

    def test_enforcement_regression_refused(self) -> None:
        findings = ce.check_enforcement(
            gate_text=self.gate_text.replace(
                "def check_transparency(", "def transparency_removed("
            ),
            enforcement_record=self.record,
            document_text=self.document,
        )
        self.assertEqual([finding.code for finding in findings],
                         ["CE_REFUSED_ENFORCEMENT_REGRESSION"])
        self.assertIn("check_transparency", findings[0].detail)

    def test_a_removed_gate_item_is_refused(self) -> None:
        findings = ce.check_enforcement(
            gate_text=self.gate_text.replace("def check_policy(", "def policy_removed("),
            enforcement_record=self.record,
            document_text=self.document,
        )
        self.assertEqual([finding.code for finding in findings],
                         ["CE_REFUSED_ENFORCEMENT_REGRESSION"])
        self.assertIn("gate-9", findings[0].artefact)

    def test_a_removed_code_is_refused(self) -> None:
        findings = ce.check_enforcement(
            gate_text=self.gate_text,
            enforcement_record={"refusalCodes": list(ce.REFUSAL_CODES)[1:]},
            document_text=self.document,
        )
        self.assertEqual([finding.code for finding in findings],
                         ["CE_REFUSED_ENFORCEMENT_REGRESSION"])
        self.assertIn(ce.REFUSAL_CODES[0], findings[0].detail)

    def test_a_document_that_forgets_a_code_is_refused(self) -> None:
        findings = ce.check_enforcement(
            gate_text=self.gate_text,
            enforcement_record=self.record,
            document_text=self.document.replace("CE_REFUSED_UNBOUND_CLAIM", "removed"),
        )
        self.assertEqual([finding.code for finding in findings],
                         ["CE_REFUSED_ENFORCEMENT_REGRESSION"])
        self.assertIn("CE_REFUSED_UNBOUND_CLAIM", findings[0].detail)

    def test_a_missing_enforcement_record_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            findings = ce.check_enforcement(
                gate_text=self.gate_text,
                enforcement=Path(temporary) / "absent.json",
                document_text=self.document,
            )
        self.assertEqual([finding.code for finding in findings],
                         ["CE_REFUSED_ENFORCEMENT_REGRESSION"])

    def test_release_gate_wires_item_ten(self) -> None:
        self.assertIn("def check_transparency(", self.gate_text)
        self.assertIn("result = check_transparency(root)", self.gate_text)
        self.assertIn("10. transparency", self.gate_text)


class ControlsAndCli(unittest.TestCase):
    """Every code has a control; the CLI has three exit codes."""

    def test_every_code_has_a_control(self) -> None:
        record = ce.controls_record()
        observed = {row["observedCode"] for row in record["controls"]}
        self.assertTrue(record["coversEveryCode"])
        self.assertTrue(set(ce.REFUSAL_CODES) <= observed)

    def test_committed_controls_record_matches_the_run(self) -> None:
        committed = ce.load_json(EVIDENCE / "CONTROLS.json")
        fresh = ce.controls_record()
        self.assertEqual(committed, fresh)

    def run_tool(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            cwd=str(REPO), text=True, capture_output=True, timeout=300,
        )

    def test_cli_exit_codes(self) -> None:
        passing = self.run_tool("check")
        self.assertEqual(passing.returncode, 0, passing.stdout + passing.stderr)
        self.assertIn("code=CE_OK", passing.stdout)

        usage = self.run_tool("check", "--not-a-flag")
        self.assertEqual(usage.returncode, 2)
        self.assertIn(ce.CODE_USAGE, usage.stdout)

        with tempfile.TemporaryDirectory() as temporary:
            refusing = self.run_tool(
                "check", "--registry", str(Path(temporary) / "absent.json"), "--json"
            )
        self.assertEqual(refusing.returncode, 1)
        payload = json.loads(refusing.stdout)
        self.assertEqual(payload["verdict"], "REFUSED")
        self.assertEqual(payload["code"], "CE_REFUSED_PROFILE_ABSENT")

    def test_json_payload_is_sorted_and_complete(self) -> None:
        run = self.run_tool("check", "--json")
        payload = json.loads(run.stdout)
        self.assertEqual(sorted(payload), ["code", "population", "refusals", "schema", "verdict"])
        self.assertEqual(payload["verdict"], "PASS")


class ProducerAndRecords(unittest.TestCase):
    """The producer reproduces bytes and the records agree with it."""

    def run_producer(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(PRODUCER), *arguments],
            cwd=str(REPO), text=True, capture_output=True, timeout=300,
        )

    def test_the_producer_is_byte_identical_and_reproduces_the_records(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one = self.run_producer("--out", first)
            two = self.run_producer("--out", second)
            self.assertEqual(one.returncode, 0, one.stdout + one.stderr)
            self.assertEqual(two.returncode, 0, two.stdout + two.stderr)
            for name in ("ENFORCEMENT.json", "SCHEMA.json", "PENDING.json", "CONTROLS.json"):
                left = (Path(first) / name).read_bytes()
                right = (Path(second) / name).read_bytes()
                self.assertEqual(left, right, f"{name} is not deterministic")
                self.assertEqual(left, (EVIDENCE / name).read_bytes(),
                                 f"{name} differs from the committed record")

    def test_the_producer_check_exits_zero(self) -> None:
        run = self.run_producer("--check")
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("code=CE_OK", run.stdout)

    def test_enforcement_record(self) -> None:
        record = ce.load_json(EVIDENCE / "ENFORCEMENT.json")
        self.assertEqual(record["gateItem"]["number"], 10)
        self.assertEqual(record["gateItem"]["function"], "check_transparency")
        self.assertEqual(record["refusalCodes"], list(ce.REFUSAL_CODES))
        self.assertEqual(record["refusalCounts"]["before"]["total"], 35)
        self.assertEqual(record["refusalCounts"]["after"]["total"],
                         record["refusalCounts"]["before"]["total"]
                         + record["refusalCounts"]["transparencyItem"]["findings"])
        self.assertEqual(len(record["gateItems"]), len(ce.GATE_ITEMS))

    def test_schema_record_population_is_zero_and_vacuous(self) -> None:
        record = ce.load_json(EVIDENCE / "SCHEMA.json")
        self.assertEqual(record["population"]["claims"], 35)
        self.assertEqual(record["population"]["carrying"], 0)
        self.assertEqual(record["population"]["claimsRewritten"], 0)
        self.assertEqual(record["population"]["absenceCheck"], "VACUOUS")
        self.assertEqual(record["stateEnum"], ["NOT_ADMITTED", "ADMITTED", "PUBLISHED"])
        self.assertEqual(record["profileEnum"], ["public-good-rekor-v2"])

    def test_pending_record_names_both_applications(self) -> None:
        record = ce.load_json(EVIDENCE / "PENDING.json")
        states = {row["id"]: row["state"] for row in record["applications"]}
        self.assertEqual(states["agents-continuous-enforcement"],
                         "PENDING_MAINTAINER_APPLICATION")
        self.assertEqual(states["ci-transparency-job"], "PENDING_CREDENTIAL")
        for row in record["applications"]:
            self.assertTrue((REPO / row["path"]).is_file(), row["path"])
            self.assertTrue(row["reason"])
            self.assertEqual(len(row["sha256"]), 64)


class DocumentSynchronisation(unittest.TestCase):
    """Every code and every named test exists and runs."""

    def setUp(self) -> None:
        self.text = DOCUMENT.read_text(encoding="utf-8")

    def test_every_code_is_named(self) -> None:
        for code in ce.REFUSAL_CODES:
            self.assertIn(code, self.text)

    def test_every_named_test_exists(self) -> None:
        module = Path(__file__).read_text(encoding="utf-8")
        named = set(re.findall(r"`(test_[a-z0-9_]+)`", self.text))
        self.assertTrue(named)
        for name in sorted(named):
            self.assertIn(f"def {name}(", module, f"{name} is named but not defined")

    def test_the_pending_states_are_named(self) -> None:
        self.assertIn("PENDING_MAINTAINER_APPLICATION", self.text)
        self.assertIn("PENDING_CREDENTIAL", self.text)
        self.assertIn("NOT_RUN", self.text)

    def test_the_enforcement_regression_rule_is_stated(self) -> None:
        normalised = " ".join(self.text.split())
        self.assertIn("CE_REFUSED_ENFORCEMENT_REGRESSION", normalised)
        self.assertIn("single-edit regression", normalised)

    def test_the_absence_check_is_called_vacuous(self) -> None:
        self.assertIn("vacuous", self.text.lower())


class ReleaseGateItem(unittest.TestCase):
    """The gate item is connected to the tool, not to a document."""

    def test_item_ten_calls_the_tool_and_maps_its_codes(self) -> None:
        results = release_gate.check_transparency(release_gate.ROOT)
        self.assertEqual(results.refusals, [])
        self.assertTrue(any("0 carry a transparency field" in line
                            for line in results.recorded), results.recorded)

    def test_a_publication_claim_is_refused_through_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = write(Path(temporary) / "claims.json", claim_document(
                transparency_claim(
                    "PUBLISHED",
                    profile="public-good-rekor-v2",
                    statementDigest=DIGEST,
                    bundleDigest=DIGEST,
                    publishedAt="2026-11-24T00:00:00Z",
                )
            ))
            results = release_gate.check_transparency(release_gate.ROOT, claims=path)
        self.assertIn("CE_REFUSED_PUBLICATION_CLAIM",
                      [item.rule for item in results.refusals])


if __name__ == "__main__":
    unittest.main()
