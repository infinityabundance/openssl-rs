#!/usr/bin/env python3
"""Controls for Rust, FFI and binary location fidelity.

Each control exercises one rule of `docs/LOCATION-FIDELITY.md`: the eight classes
are a closed registry; every recorded instance re-projects and checks; a recorded
emission carries no precision the native record does not support; each of the
twenty refusal codes fires for the substitution it names; the A1 emission scan is
clean over the recorded population; and the document, the registry and the
implementation agree.

A control mutates an emission in memory. It is not a source change and not a
defect report: a control that fires proves the refusal works, not that the
substituted form occurs anywhere in the tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import location_fidelity as lf  # noqa: E402

CLASSES_PATH = REPO_ROOT / "evidence" / "a4" / "CLASSES.json"
INSTANCES_PATH = REPO_ROOT / "evidence" / "a4" / "INSTANCES.json"
A1_SARIF = REPO_ROOT / "evidence" / "a1" / "SARIF.json"
DOCUMENT = REPO_ROOT / "docs" / "LOCATION-FIDELITY.md"
RECEIPT = REPO_ROOT / "evidence" / "a4" / "RECEIPT.md"

CLASS_IDS = {
    "inline-macro-expansion",
    "macro-rules-derive-output",
    "monomorphised-generic",
    "dynamic-dispatch",
    "no-mangle-export",
    "indirect-function-pointer-call",
    "inlined-optimised-code",
    "binary-symbol-only",
}
TEXT_KEYS = ("startLine", "startColumn", "endLine", "endColumn", "charOffset", "charLength")
BINARY_PRECISIONS = {
    "byte-offset-in-artifact",
    "function-offset-and-extent",
    "call-site-offset-in-artifact",
}


# --------------------------------------------------------------------------
# Fixture helpers
# --------------------------------------------------------------------------

def instances_document() -> dict:
    return json.loads(INSTANCES_PATH.read_text(encoding="utf-8"))


def recorded(identifier: str) -> dict:
    for item in instances_document()["instances"]:
        if item["id"] == identifier:
            return item
    raise KeyError(identifier)


def record(identifier: str) -> dict:
    return copy.deepcopy(recorded(identifier)["nativeRecord"])


def emission(identifier: str) -> dict:
    return copy.deepcopy(recorded(identifier)["emitted"])


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def refusal_code(action) -> str:
    try:
        action()
    except lf.Refusal as refusal:
        return refusal.code
    raise AssertionError("the action was accepted; a refusal was required")


def documented_class_ids() -> set[str]:
    """The class ids that appear as the first cell of a row in the class table."""

    text = DOCUMENT.read_text(encoding="utf-8")
    return set(re.findall(r"^\| `([a-z][a-z0-9-]+)` \|", text, re.MULTILINE))


def sarif_document(precision: str, region: dict, *, address=None, line_info=None) -> dict:
    properties = {"locationPrecision": precision}
    if line_info is not None:
        properties["lineInfoAvailable"] = line_info
    physical = {
        "artifactLocation": {"uri": "libcrypto.so.3"},
        "region": region,
    }
    if address is not None:
        physical["address"] = address
    return {
        "version": "2.1.0",
        "runs": [
            {
                "artifacts": [{"location": {"uri": "libcrypto.so.3"}}],
                "results": [
                    {
                        "ruleId": "A4-CONTROL",
                        "properties": {"a1": properties},
                        "locations": [{"physicalLocation": physical}],
                    }
                ],
            }
        ],
    }


# --------------------------------------------------------------------------
# The registry
# --------------------------------------------------------------------------

class RegistryTests(unittest.TestCase):
    def test_the_eight_ids_are_exactly_the_registered_set(self):
        self.assertEqual(set(lf.BY_ID), CLASS_IDS)
        self.assertEqual(len(lf.CLASSES), 8)
        self.assertEqual(len(lf.BY_ID), 8)

    def test_class_ids_are_unique(self):
        ids = [rule.id for rule in lf.CLASSES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_classes_document_declares_no_a1_policy_change(self):
        document = lf.classes_document()
        self.assertEqual(document["a1PolicyChange"], "none")
        self.assertEqual(document["model"], lf.MODEL_ID)
        self.assertEqual(
            {entry["id"] for entry in document["classes"]}, CLASS_IDS
        )

    def test_the_document_and_the_registry_name_the_same_classes(self):
        self.assertEqual(documented_class_ids(), set(lf.BY_ID))

    def test_every_registered_refusal_is_a_documented_code(self):
        self.assertEqual(len(lf.REFUSALS), 20)
        text = DOCUMENT.read_text(encoding="utf-8")
        for code in lf.REFUSALS:
            with self.subTest(code=code):
                self.assertIn(code, text)

    def test_the_document_names_its_neighbours(self):
        text = DOCUMENT.read_text(encoding="utf-8")
        self.assertIn("docs/SARIF-PROFILE.md", text)
        self.assertIn("docs/FINDING-IDENTITY.md", text)

    def test_every_class_names_a_recorded_instance(self):
        recorded_ids = {item["id"] for item in instances_document()["instances"]}
        for rule in lf.CLASSES:
            with self.subTest(class_id=rule.id):
                self.assertTrue(rule.instance_ids)
                self.assertTrue(set(rule.instance_ids) <= recorded_ids)

    def test_every_recorded_instance_uses_a_registered_class(self):
        for item in instances_document()["instances"]:
            with self.subTest(instance=item["id"]):
                self.assertIn(item["class"], lf.BY_ID)
                self.assertEqual(item["nativeRecord"]["class"], item["class"])
                self.assertEqual(item["status"], "real")


# --------------------------------------------------------------------------
# Round trip over the recorded instances
# --------------------------------------------------------------------------

class RoundTripTests(unittest.TestCase):
    def test_every_recorded_instance_reprojects(self):
        for item in instances_document()["instances"]:
            with self.subTest(instance=item["id"]):
                self.assertEqual(
                    canonical(lf.project(item["nativeRecord"])),
                    canonical(item["emitted"]),
                )

    def test_every_recorded_emission_checks_against_its_record(self):
        for item in instances_document()["instances"]:
            with self.subTest(instance=item["id"]):
                lf.check(item["nativeRecord"], item["emitted"])

    def test_verify_instances_reports_the_recorded_counts(self):
        report = lf.verify_instances(instances_document(), REPO_ROOT)
        self.assertEqual(report["model"], lf.MODEL_ID)
        self.assertEqual(report["instances"], 9)
        self.assertEqual(report["provenance"], 20)
        self.assertEqual(report["mutations"], 34)
        self.assertEqual(sum(report["byClass"].values()), 9)
        self.assertEqual(report["byClass"]["inlined-optimised-code"], 2)

    def test_every_recorded_mutation_names_a_registered_refusal(self):
        for item in instances_document()["instances"]:
            for mutation in item["mutations"]:
                with self.subTest(instance=item["id"], path=mutation["path"]):
                    self.assertIn(mutation["refusal"], lf.REFUSALS)


# --------------------------------------------------------------------------
# The five required refusal controls
# --------------------------------------------------------------------------

class RequiredRefusalTests(unittest.TestCase):
    def test_a_definition_line_substituted_for_an_instantiation(self):
        # L2 records the macro definition at 562. A record that distinguishes the
        # instantiation (567) from the definition (562) must not emit 562 as the
        # instantiation's own line.
        item = record("L2-define-new-free")
        item["native"]["line"] = 567
        item["native"]["definitionLine"] = 562
        projected = lf.project(item)
        projected["location"]["physicalLocation"]["region"]["startLine"] = 562
        self.assertEqual(
            refusal_code(lambda: lf.check(item, projected)),
            lf.R_DEFINITION_AS_INSTANCE,
        )

    def test_instantiation_line_recorded_on_a_macro_definition_refuses(self):
        item = record("L2-define-new-free")
        projected = lf.project(item)
        projected["properties"]["instantiationLineRecorded"] = True
        self.assertEqual(
            refusal_code(lambda: lf.check(item, projected)),
            lf.R_DEFINITION_AS_INSTANCE,
        )

    def test_a_source_line_on_a_machine_code_finding(self):
        projected = emission("L8-bn-mod-inverse")
        projected["location"]["physicalLocation"]["region"]["startLine"] = 1
        self.assertEqual(
            refusal_code(lambda: lf.check(record("L8-bn-mod-inverse"), projected)),
            lf.R_MACHINE_CODE_LINE,
        )

    def test_an_extent_absent_from_the_native_record(self):
        projected = emission("L4-bsearch-dyn-call")
        projected["location"]["physicalLocation"]["region"]["byteLength"] = 0x2
        self.assertEqual(
            refusal_code(lambda: lf.check(record("L4-bsearch-dyn-call"), projected)),
            lf.R_UNRECORDED_EXTENT,
        )

    def test_an_end_line_on_a_source_emission(self):
        projected = emission("L1-cmp-ctx-cb-to-ptr")
        projected["location"]["physicalLocation"]["region"]["endLine"] = 759
        self.assertEqual(
            refusal_code(lambda: lf.check(record("L1-cmp-ctx-cb-to-ptr"), projected)),
            lf.R_UNRECORDED_EXTENT,
        )

    def test_a_file_absent_from_the_candidate_identity(self):
        item = record("L1-cmp-ctx-cb-to-ptr")
        item["subject"]["candidateFiles"] = []
        self.assertEqual(
            refusal_code(lambda: lf.project(item)),
            lf.R_FILE_NOT_IN_CANDIDATE,
        )

    def test_an_emitted_uri_that_is_not_the_record_uri(self):
        projected = emission("L5-cmp-ctx-export")
        projected["location"]["physicalLocation"]["artifactLocation"]["uri"] = "other.so"
        self.assertEqual(
            refusal_code(lambda: lf.check(record("L5-cmp-ctx-export"), projected)),
            lf.R_FILE_NOT_IN_CANDIDATE,
        )

    def test_an_inlined_finding_with_a_fabricated_call_site(self):
        projected = emission("L7-store-close-it")
        projected["location"]["physicalLocation"]["callSite"] = 0x36F8D3
        self.assertEqual(
            refusal_code(lambda: lf.check(record("L7-store-close-it"), projected)),
            lf.R_INLINED_CALL_SITE,
        )

    def test_a_record_carrying_a_call_site_refuses_at_projection(self):
        item = record("L7-store-close-it")
        item["native"]["callSite"] = 0x36F8D3
        self.assertEqual(
            refusal_code(lambda: lf.project(item)),
            lf.R_INLINED_CALL_SITE,
        )


# --------------------------------------------------------------------------
# The remaining refusal controls
# --------------------------------------------------------------------------

class OtherRefusalTests(unittest.TestCase):
    def test_an_unregistered_class(self):
        item = record("L1-cmp-ctx-cb-to-ptr")
        item["class"] = "not-a-location-class"
        self.assertEqual(
            refusal_code(lambda: lf.project(item)), lf.R_UNKNOWN_CLASS
        )

    def test_a_record_with_no_subject(self):
        item = record("L1-cmp-ctx-cb-to-ptr")
        item.pop("subject")
        self.assertEqual(
            refusal_code(lambda: lf.project(item)), lf.R_MISSING_SUBJECT
        )

    def test_a_binary_finding_with_no_artefact_digest(self):
        item = record("L8-bn-mod-inverse")
        for key in ("digest", "digestScope", "algorithm"):
            item["subject"].pop(key)
        self.assertEqual(
            refusal_code(lambda: lf.project(item)), lf.R_MISSING_ARTIFACT_DIGEST
        )

    def test_a_symbol_only_finding_with_no_symbol(self):
        item = record("L8-bn-mod-inverse")
        for key in ("address", "byteOffset", "symbol"):
            item["native"].pop(key)
        self.assertEqual(
            refusal_code(lambda: lf.project(item)), lf.R_MISSING_SYMBOL
        )

    def test_a_binary_finding_with_no_address_or_offset(self):
        item = record("L5-cmp-ctx-export")
        for key in ("address", "byteOffset"):
            item["native"].pop(key)
        self.assertEqual(
            refusal_code(lambda: lf.project(item)), lf.R_MISSING_ADDRESS
        )

    def test_a_line_absent_from_the_native_record(self):
        projected = emission("L1-cmp-ctx-cb-to-ptr")
        projected["location"]["physicalLocation"]["region"]["startLine"] = 760
        self.assertEqual(
            refusal_code(lambda: lf.check(record("L1-cmp-ctx-cb-to-ptr"), projected)),
            lf.R_FABRICATED_LINE,
        )

    def test_a_column_emitted_as_a_sarif_column(self):
        projected = emission("L1-cmp-ctx-cb-to-ptr")
        projected["location"]["physicalLocation"]["region"]["startColumn"] = 5
        self.assertEqual(
            refusal_code(lambda: lf.check(record("L1-cmp-ctx-cb-to-ptr"), projected)),
            lf.R_COLUMN_NOT_EMITTED,
        )

    def test_a_missing_recorded_call_site_on_a_dynamic_call(self):
        projected = emission("L6-store-loader-closefn")
        projected["location"]["physicalLocation"]["region"].pop("byteOffset")
        self.assertEqual(
            refusal_code(lambda: lf.check(record("L6-store-loader-closefn"), projected)),
            lf.R_UNRECORDED_CALL_SITE,
        )

    def test_a_dynamic_record_without_a_call_site_refuses_at_projection(self):
        item = record("L6-store-loader-closefn")
        item["native"].pop("callSite")
        self.assertEqual(
            refusal_code(lambda: lf.project(item)), lf.R_UNRECORDED_CALL_SITE
        )

    def test_a_call_site_offset_not_in_the_record(self):
        projected = emission("L6-store-loader-closefn")
        projected["location"]["physicalLocation"]["region"]["byteOffset"] = 0x36F8D4
        self.assertEqual(
            refusal_code(lambda: lf.check(record("L6-store-loader-closefn"), projected)),
            lf.R_FABRICATED_CALL_SITE,
        )

    def test_an_address_not_in_the_record(self):
        projected = emission("L5-cmp-ctx-export")
        projected["location"]["physicalLocation"]["address"]["absoluteAddress"] = 0x27AC50
        self.assertEqual(
            refusal_code(lambda: lf.check(record("L5-cmp-ctx-export"), projected)),
            lf.R_FABRICATED_ADDRESS,
        )

    def test_a_function_address_and_offset_that_disagree_at_projection(self):
        item = record("L5-cmp-ctx-export")
        item["native"]["byteOffset"] = 0x27ABD1
        self.assertEqual(
            refusal_code(lambda: lf.project(item)), lf.R_FABRICATED_ADDRESS
        )

    def test_a_symbol_the_record_does_not_name(self):
        projected = emission("L5-cmp-ctx-export")
        projected["location"]["physicalLocation"]["address"]["name"] = (
            "OSSL_CMP_CTX_set_http_cb"
        )
        self.assertEqual(
            refusal_code(lambda: lf.check(record("L5-cmp-ctx-export"), projected)),
            lf.R_FABRICATED_SYMBOL,
        )

    def test_a_record_condition_carrying_a_location_at_projection(self):
        item = {
            "class": "binary-symbol-only",
            "subject": {"kind": "record"},
            "native": {"recordCondition": True, "line": 5},
        }
        self.assertEqual(
            refusal_code(lambda: lf.project(item)),
            lf.R_RECORD_CONDITION_WITH_LOCATION,
        )

    def test_a_record_condition_emission_carrying_a_location(self):
        item = {
            "class": "binary-symbol-only",
            "subject": {"kind": "record"},
            "native": {"recordCondition": True},
        }
        projected = lf.project(item)
        projected["location"] = {
            "physicalLocation": {"artifactLocation": {"uri": "libcrypto.so.3"}}
        }
        self.assertEqual(
            refusal_code(lambda: lf.check(item, projected)),
            lf.R_RECORD_CONDITION_WITH_LOCATION,
        )

    def test_an_emission_of_a_different_class(self):
        projected = emission("L1-cmp-ctx-cb-to-ptr")
        projected["class"] = "dynamic-dispatch"
        self.assertEqual(
            refusal_code(lambda: lf.check(record("L1-cmp-ctx-cb-to-ptr"), projected)),
            lf.R_EMISSION_INVALID,
        )

    def test_an_emission_that_is_not_the_projection(self):
        projected = emission("L1-cmp-ctx-cb-to-ptr")
        projected["properties"]["nativeLineOrigin"] = "direct"
        self.assertEqual(
            refusal_code(lambda: lf.check(record("L1-cmp-ctx-cb-to-ptr"), projected)),
            lf.R_EMISSION_INVALID,
        )


# --------------------------------------------------------------------------
# Precision is never fabricated
# --------------------------------------------------------------------------

class PrecisionTests(unittest.TestCase):
    def test_binary_precisions_carry_no_source_text_key_anywhere(self):
        seen = set()
        for item in instances_document()["instances"]:
            emission_document = item["emitted"]
            precision = emission_document["properties"]["locationPrecision"]
            if precision not in BINARY_PRECISIONS:
                continue
            seen.add(precision)
            location = emission_document["location"]
            for key in TEXT_KEYS:
                with self.subTest(instance=item["id"], key=key):
                    self.assertFalse(
                        lf._contains_key(location, key),
                        f"{item['id']} emits {key} at {precision}",
                    )
        self.assertIn("function-offset-and-extent", seen)
        self.assertIn("call-site-offset-in-artifact", seen)

    def test_a_line_precision_region_is_exactly_a_start_line(self):
        checked = 0
        for item in instances_document()["instances"]:
            if item["emitted"]["properties"]["locationPrecision"] != "line":
                continue
            region = item["emitted"]["location"]["physicalLocation"]["region"]
            with self.subTest(instance=item["id"]):
                self.assertEqual(set(region), {"startLine"})
            checked += 1
        self.assertGreater(checked, 0)

    def test_a_recorded_column_is_preserved_as_a_native_property(self):
        projected = emission("L1-cmp-ctx-cb-to-ptr")
        properties = projected["properties"]
        self.assertEqual(properties["column"], 5)
        self.assertEqual(properties["columnUnit"], "not-recorded")
        self.assertNotIn("startColumn", projected["location"])

    def test_a_binary_emission_never_claims_line_information(self):
        for item in instances_document()["instances"]:
            emission_document = item["emitted"]
            if emission_document["properties"]["locationPrecision"] not in BINARY_PRECISIONS:
                continue
            with self.subTest(instance=item["id"]):
                self.assertFalse(emission_document["properties"]["lineInfoAvailable"])


# --------------------------------------------------------------------------
# Provenance and integrity
# --------------------------------------------------------------------------

class ProvenanceTests(unittest.TestCase):
    def test_a_tampered_record_digest_refuses(self):
        document = copy.deepcopy(instances_document())
        document["instances"][0]["provenance"][0]["recordSha256"] = "0" * 64
        self.assertEqual(
            refusal_code(lambda: lf.verify_instances(document, REPO_ROOT)),
            lf.R_PROVENANCE,
        )

    def test_a_moved_json_pointer_refuses(self):
        document = copy.deepcopy(instances_document())
        target = next(
            item for item in document["instances"] if item["id"] == "L8-bn-mod-inverse"
        )
        target["provenance"][0]["pointer"] = "/primitives"
        self.assertEqual(
            refusal_code(lambda: lf.verify_instances(document, REPO_ROOT)),
            lf.R_PROVENANCE,
        )

    def test_a_tampered_recorded_emission_refuses(self):
        document = copy.deepcopy(instances_document())
        document["instances"][0]["emitted"]["properties"]["locationPrecision"] = (
            "record-condition"
        )
        self.assertEqual(
            refusal_code(lambda: lf.verify_instances(document, REPO_ROOT)),
            lf.R_INSTANCE,
        )

    def test_a_wrong_model_refuses(self):
        document = copy.deepcopy(instances_document())
        document["model"] = "a4/older"
        self.assertEqual(
            refusal_code(lambda: lf.verify_instances(document, REPO_ROOT)),
            lf.R_INSTANCE,
        )

    def test_every_observation_is_bound_to_the_candidate_digest(self):
        candidate = instances_document()["candidate"]["libcrypto"]["sha256"]
        for item in instances_document()["instances"]:
            for observation in item["observations"]:
                with self.subTest(instance=item["id"]):
                    self.assertEqual(observation["artefact"]["sha256"], candidate)


# --------------------------------------------------------------------------
# The A1 emission scan
# --------------------------------------------------------------------------

class SarifScanTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(A1_SARIF.read_text(encoding="utf-8"))

    def test_the_recorded_emission_has_no_violation(self):
        self.assertEqual(lf.scan_sarif(self.document), [])

    def test_the_scan_covers_every_result(self):
        self.assertEqual(len(self.document["runs"]), 6)
        total = sum(len(run.get("results") or []) for run in self.document["runs"])
        self.assertEqual(total, 4245)

    def test_a_binary_precision_with_a_line_is_reported(self):
        document = sarif_document(
            "byte-offset-in-artifact",
            {"byteOffset": 16, "startLine": 3},
            address={"absoluteAddress": 16, "kind": "instruction"},
            line_info=False,
        )
        self.assertIn("LF_SARIF_BINARY_LINE", _codes(lf.scan_sarif(document)))

    def test_a_record_condition_with_a_location_is_reported(self):
        document = sarif_document("record-condition", {"startLine": 1}, line_info=False)
        self.assertIn(
            "LF_SARIF_RECORD_CONDITION_LOCATION", _codes(lf.scan_sarif(document))
        )

    def test_a_line_region_with_an_extra_key_is_reported(self):
        document = sarif_document("line", {"startLine": 1, "endLine": 1}, line_info=True)
        self.assertIn("LF_SARIF_LINE_SHAPE", _codes(lf.scan_sarif(document)))


def _codes(violations: list[dict]) -> set[str]:
    return {violation["code"] for violation in violations}


# --------------------------------------------------------------------------
# Determinism and the command line
# --------------------------------------------------------------------------

class DeterminismTests(unittest.TestCase):
    def test_two_projections_are_equal(self):
        item = record("L6-store-loader-closefn")
        self.assertEqual(canonical(lf.project(item)), canonical(lf.project(item)))

    def test_check_accepts_every_projection(self):
        for item in instances_document()["instances"]:
            with self.subTest(instance=item["id"]):
                lf.check(item["nativeRecord"], lf.project(item["nativeRecord"]))


class CommandLineTests(unittest.TestCase):
    def test_project_refuses_an_unknown_class_with_no_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "record.json"
            path.write_text(
                json.dumps(
                    {
                        "class": "not-a-location-class",
                        "subject": {"kind": "source", "uri": "src/a.rs"},
                    }
                ),
                encoding="utf-8",
            )
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = lf.main(["project", str(path)])
            self.assertEqual(code, 2)
            self.assertEqual(out.getvalue(), "")
            self.assertIn(lf.R_UNKNOWN_CLASS, err.getvalue())

    def test_check_accepts_a_valid_pair(self):
        item = record("L4-bsearch-dyn-call")
        projected = lf.project(item)
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "record.json"
            emission_path = Path(tmp) / "emission.json"
            record_path.write_text(json.dumps(item), encoding="utf-8")
            emission_path.write_text(json.dumps(projected), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = lf.main(["check", str(record_path), str(emission_path)])
            self.assertEqual(code, 0)
            self.assertEqual(out.getvalue().strip(), "accepted")
            self.assertEqual(err.getvalue(), "")


# --------------------------------------------------------------------------
# Deliverable hygiene
# --------------------------------------------------------------------------

class DeliverableTests(unittest.TestCase):
    def test_no_first_person_in_the_a4_prose(self):
        first_person = re.compile(
            r"\b(I|We|Our|My|Mine|Ours|Me|Us|we|our|my|mine|ours|me|us)\b"
        )
        for path in (DOCUMENT, RECEIPT):
            if not path.exists():
                continue
            with self.subTest(path=str(path)):
                self.assertEqual(
                    first_person.findall(path.read_text(encoding="utf-8")), []
                )

    def test_the_recorded_classes_document_is_well_formed(self):
        document = json.loads(CLASSES_PATH.read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], lf.CLASS_SCHEMA)
        self.assertEqual(document["model"], lf.MODEL_ID)


if __name__ == "__main__":
    unittest.main(verbosity=2)
