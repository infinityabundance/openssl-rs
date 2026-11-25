#!/usr/bin/env python3
"""Controls for the B4 publication classifier, bundle and verifier.

One control per refusal code, plus the rules the item exists to enforce: a
private member is refused, a member with a private reference is refused, an
unclassified path is refused, a bundle that omits release-critical material is
refused, the real bundle verifies from a fresh directory with a stripped
environment, a mutated member is refused, the producer is deterministic, the
command line exits 0/1/2, and the normative document stays in step with the
tool.

A control mutates a synthetic bundle in a temporary directory.  It is not a
source change and not a defect report: a control that fires proves the refusal
works, not that the substituted form occurs anywhere in the tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(TOOLS))

import publication as pb  # noqa: E402

EVIDENCE = REPO_ROOT / "evidence" / "b4"
BUNDLE = EVIDENCE / "BUNDLE"
CLASSIFICATION = EVIDENCE / "CLASSIFICATION.json"
PUBLICATION = EVIDENCE / "PUBLICATION.json"
CONTROLS = EVIDENCE / "CONTROLS.json"
VERIFICATION = EVIDENCE / "VERIFICATION.json"
PRODUCER = EVIDENCE / "build_evidence.py"
DOCUMENT = REPO_ROOT / "docs" / "PUBLIC-TRANSPARENCY.md"

_spec = importlib.util.spec_from_file_location("b4_build_evidence", PRODUCER)
assert _spec is not None and _spec.loader is not None
b4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(b4)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _policy() -> dict:
    return _load(CLASSIFICATION)["policy"]


def _bundle_copy(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination)
    return destination


def _codes(action) -> str:
    try:
        result = action()
    except pb.Refusal as refusal:
        return refusal.code
    if isinstance(result, dict):
        return str(result.get("code", "PB_OK"))
    return "PB_OK"


class PolicyTests(unittest.TestCase):
    def test_the_default_is_not_to_publish(self) -> None:
        policy = _policy()
        self.assertEqual(policy["default"], pb.UNCLASSIFIED)

    def test_the_policy_defines_exactly_four_classes(self) -> None:
        self.assertEqual(set(_policy()["classes"]), set(pb.CLASSES))

    def test_an_unclassified_path_is_not_publishable(self) -> None:
        klass, _rule, _reason = pb.classify_path(_policy(), "src/bn/mont.rs")
        self.assertEqual(klass, pb.UNCLASSIFIED)

    def test_a_private_pattern_outranks_an_exact_public_rule(self) -> None:
        policy = {
            "default": pb.UNCLASSIFIED,
            "classes": {name: {} for name in pb.CLASSES},
            "rules": [
                {
                    "id": "promoted",
                    "kind": "exact",
                    "path": "evidence/promoted.pem",
                    "class": pb.PUBLIC_RELEASE_CRITICAL,
                    "reason": "control-only",
                }
            ],
            "privatePatterns": [
                {"id": "pem", "pattern": "*.pem", "reason": "control-only"}
            ],
            "releaseCritical": [],
        }
        klass, rule, _reason = pb.classify_path(policy, "evidence/promoted.pem")
        self.assertEqual(klass, pb.PRIVATE_NEVER_PUBLISHED)
        self.assertEqual(rule, "pem")

    def test_every_elided_rule_records_a_reason(self) -> None:
        for rule in _policy()["rules"]:
            self.assertTrue(rule["reason"].strip(), rule["id"])

    def test_the_release_critical_set_names_the_a8_material(self) -> None:
        sources = {entry["sourcePath"] for entry in _policy()["releaseCritical"]}
        self.assertIn("evidence/a9/STATEMENTS/a8-shard-000.json", sources)
        self.assertIn("evidence/b1/PUBLICATION.json", sources)
        self.assertIn("evidence/a5/ADMISSION.json", sources)
        self.assertIn("evidence/a17/FREEZE-forward.json", sources)


class RefusalControlTests(unittest.TestCase):
    """One live control per refusal code, built from a synthetic bundle."""

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="b4-test-"))
        self.repo = self.work / "repo"
        b4._mini_repo(self.repo)
        self.valid = self.work / "valid"
        pb.build(b4.MINI_POLICY, self.repo, self.valid, b4.MINI_SOURCES)

    def tearDown(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)

    def _extra(self, member: str, source: str) -> list[dict]:
        return b4.MINI_SOURCES + [
            {
                "member": member,
                "source": source,
                "role": "control-only",
                "classification": pb.PUBLIC_SUPPORTING,
            }
        ]

    def test_the_canary_is_accepted(self) -> None:
        self.assertEqual(_codes(lambda: pb.verify_bundle(self.valid, b4.MINI_POLICY)), "PB_OK")

    def test_unclassified_member_is_refused(self) -> None:
        out = self.work / "unclassified"
        code = _codes(
            lambda: pb.build(
                b4.MINI_POLICY, self.repo, out, self._extra("members/u.json", "mini/unknown.json")
            )
        )
        self.assertEqual(code, "PB_REFUSED_UNCLASSIFIED")
        self.assertFalse(out.exists())

    def test_private_member_is_refused(self) -> None:
        out = self.work / "private"
        code = _codes(
            lambda: pb.build(
                b4.MINI_POLICY,
                self.repo,
                out,
                self._extra("members/s.secret", "mini/sensitive.secret"),
            )
        )
        self.assertEqual(code, "PB_REFUSED_PRIVATE_MATERIAL")
        self.assertFalse(out.exists())

    def test_internal_member_is_refused(self) -> None:
        out = self.work / "internal"
        code = _codes(
            lambda: pb.build(
                b4.MINI_POLICY, self.repo, out, self._extra("members/i.json", "mini/internal.json")
            )
        )
        self.assertEqual(code, "PB_REFUSED_INTERNAL_MATERIAL")
        self.assertFalse(out.exists())

    def test_private_reference_is_refused(self) -> None:
        leaky = self.work / "leaky"
        b4._mini_repo(leaky, private_reference=True)
        out = self.work / "leaky-bundle"
        code = _codes(
            lambda: pb.build(
                b4.MINI_POLICY, leaky, out, self._extra("members/leaky.md", "mini/leaky.md")
            )
        )
        self.assertEqual(code, "PB_REFUSED_PRIVATE_REFERENCE")
        self.assertFalse(out.exists())

    def test_absolute_path_is_refused(self) -> None:
        absolute = self.work / "absolute"
        b4._mini_repo(absolute, absolute=True)
        out = self.work / "absolute-bundle"
        code = _codes(
            lambda: pb.build(
                b4.MINI_POLICY,
                absolute,
                out,
                self._extra("members/absolute.json", "mini/absolute.json"),
            )
        )
        self.assertEqual(code, "PB_REFUSED_ABSOLUTE_PATH")
        self.assertFalse(out.exists())

    def test_a_file_absent_from_the_manifest_is_refused(self) -> None:
        bundle = _bundle_copy(self.valid, self.work / "extra")
        (bundle / "extra.txt").write_text("not declared\n", encoding="utf-8")
        self.assertEqual(
            _codes(lambda: pb.verify_bundle(bundle, b4.MINI_POLICY)),
            "PB_REFUSED_UNBOUND_MEMBER",
        )

    def test_a_digest_that_does_not_bind_the_member_is_refused(self) -> None:
        bundle = _bundle_copy(self.valid, self.work / "digest")
        manifest_path = bundle / pb.MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["members"][0]["sha256"] = "0" * 64
        manifest["manifestDigest"] = pb.digest_body(manifest, "manifestDigest")
        manifest_path.write_bytes(pb.pretty(manifest))
        self.assertEqual(
            _codes(lambda: pb.verify_bundle(bundle, b4.MINI_POLICY)),
            "PB_REFUSED_UNBOUND_MEMBER",
        )

    def test_omitting_release_critical_material_is_refused(self) -> None:
        out = self.work / "missing"
        code = _codes(
            lambda: pb.build(b4.MINI_POLICY, self.repo, out, b4.MINI_SOURCES[1:])
        )
        self.assertEqual(code, "PB_REFUSED_RELEASE_MEMBER_MISSING")
        self.assertFalse(out.exists())

    def test_a_classification_disagreement_is_refused(self) -> None:
        bundle = _bundle_copy(self.valid, self.work / "disagree")
        manifest_path = bundle / pb.MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for row in manifest["members"]:
            if row["path"] == "members/public.json":
                row["classification"] = pb.PUBLIC_SUPPORTING
        manifest["manifestDigest"] = pb.digest_body(manifest, "manifestDigest")
        manifest_path.write_bytes(pb.pretty(manifest))
        self.assertEqual(
            _codes(lambda: pb.verify_bundle(bundle, b4.MINI_POLICY)),
            "PB_REFUSED_CLASSIFICATION_MISMATCH",
        )

    def test_a_publication_without_a_service_is_refused(self) -> None:
        self.assertEqual(
            _codes(lambda: pb.publication_claim(publish=True)),
            "PB_REFUSED_NO_PUBLIC_SERVICE",
        )

    def test_an_external_claim_that_was_not_run_is_refused(self) -> None:
        self.assertEqual(
            _codes(lambda: pb.publication_claim(external_verified=True)),
            "PB_REFUSED_EXTERNAL_NOT_RUN",
        )

    def test_an_invalid_manifest_is_refused(self) -> None:
        bundle = _bundle_copy(self.valid, self.work / "invalid")
        (bundle / pb.MANIFEST_NAME).write_text("{\n", encoding="utf-8")
        self.assertEqual(
            _codes(lambda: pb.verify_bundle(bundle, b4.MINI_POLICY)),
            "PB_REFUSED_MANIFEST_INVALID",
        )

    def test_a_tampered_manifest_digest_is_refused(self) -> None:
        bundle = _bundle_copy(self.valid, self.work / "tampered")
        manifest_path = bundle / pb.MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["bundleId"] = "rewritten"
        manifest_path.write_bytes(pb.pretty(manifest))
        self.assertEqual(
            _codes(lambda: pb.verify_bundle(bundle, b4.MINI_POLICY)),
            "PB_REFUSED_MANIFEST_INVALID",
        )

    def test_a_missing_bundle_is_refused(self) -> None:
        self.assertEqual(
            _codes(lambda: pb.verify_bundle(self.work / "absent", b4.MINI_POLICY)),
            "PB_REFUSED_IO",
        )

    def test_the_control_record_covers_every_code_and_every_control_fires(self) -> None:
        controls = _load(CONTROLS)
        codes = {row["code"] for row in controls["controls"]}
        self.assertEqual(codes, set(pb.REFUSALS))
        self.assertTrue(controls["coversEveryCode"])
        for row in controls["controls"]:
            self.assertTrue(row["controlOnly"], row["id"])
            self.assertTrue(row["fired"], row["id"])
        self.assertTrue(controls["canary"]["accepted"])


class RealBundleTests(unittest.TestCase):
    def test_the_real_bundle_verifies(self) -> None:
        result = pb.verify_bundle(BUNDLE, _policy())
        self.assertEqual(result["code"], "PB_OK")
        self.assertTrue(result["publishable"])
        self.assertEqual(result["externalVerification"], "PENDING")
        self.assertEqual(result["members"], 8)
        self.assertEqual(result["releaseCritical"], 4)

    def test_the_manifest_binds_every_member(self) -> None:
        manifest = _load(BUNDLE / pb.MANIFEST_NAME)
        self.assertEqual(
            manifest["manifestDigest"], pb.digest_body(manifest, "manifestDigest")
        )
        self.assertEqual(len(manifest["members"]), 8)
        for row in manifest["members"]:
            data = (BUNDLE / row["path"]).read_bytes()
            self.assertEqual(len(data), row["bytes"], row["path"])
            self.assertEqual(pb.sha256_bytes(data), row["sha256"], row["path"])
            self.assertIn(row["classification"], pb.PUBLISHABLE)

    def test_no_member_carries_a_private_reference(self) -> None:
        manifest = _load(BUNDLE / pb.MANIFEST_NAME)
        for row in manifest["members"]:
            data = (BUNDLE / row["path"]).read_bytes()
            self.assertIsNone(pb.scan_member_text(row["path"], data), row["path"])

    def test_the_fixture_label_is_declared_and_present(self) -> None:
        manifest = _load(BUNDLE / pb.MANIFEST_NAME)
        labels = manifest["subjectLabels"]
        self.assertEqual(labels["members/b1-publication.json"], ["FIXTURE-1"])
        text = (BUNDLE / "members/b1-publication.json").read_text(encoding="utf-8")
        self.assertIn("FIXTURE-1", text)

    def test_the_five_required_artefacts_are_members(self) -> None:
        manifest = _load(BUNDLE / pb.MANIFEST_NAME)
        sources = {row["sourcePath"] for row in manifest["members"]}
        for required in (
            "evidence/a9/STATEMENTS/a8-shard-000.json",
            "evidence/a10/ENVELOPES/a8-shard-000.json",
            "evidence/b1/PUBLICATION.json",
            "evidence/a5/ADMISSION.json",
            "evidence/a17/FREEZE-forward.json",
        ):
            self.assertIn(required, sources)

    def test_a_mutated_member_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b4-mutate-") as temporary:
            bundle = _bundle_copy(BUNDLE, Path(temporary) / "bundle")
            target = bundle / "members/a5-admission.json"
            target.write_bytes(target.read_bytes() + b" \n")
            self.assertEqual(
                _codes(lambda: pb.verify_bundle(bundle, _policy())),
                "PB_REFUSED_UNBOUND_MEMBER",
            )

    def test_the_bundled_verifier_is_the_generated_program(self) -> None:
        self.assertEqual((BUNDLE / pb.ENTRY_POINT).read_bytes(), pb.ENTRY_POINT_SOURCE.encode())
        self.assertEqual((BUNDLE / pb.ENTRY_SHELL).read_bytes(), pb.ENTRY_SHELL_SOURCE.encode())
        source = (BUNDLE / pb.ENTRY_POINT).read_text(encoding="utf-8")
        self.assertNotIn("import publication", source)
        self.assertNotIn("sys.path", source)

    def test_the_bundle_verifies_in_a_stripped_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b4-venue-") as temporary:
            run = Path(temporary) / "package"
            shutil.copytree(BUNDLE, run)
            home = Path(temporary) / "home"
            home.mkdir()
            environment = {
                "PATH": str(Path(sys.executable).resolve().parent),
                "HOME": str(home),
                "TMPDIR": str(home),
                "LANG": "C",
                "LC_ALL": "C",
            }
            completed = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(run / "verify.py")],
                cwd=str(run),
                env=environment,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            line = json.loads(completed.stdout.strip())
            self.assertEqual(line["code"], "PB_OK")
            self.assertEqual(line["external"], "NOT_RUN")
            self.assertNotIn(str(REPO_ROOT), completed.stdout)

    def test_building_twice_is_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b4-determinism-") as temporary:
            one = Path(temporary) / "one"
            two = Path(temporary) / "two"
            pb.build(_policy(), REPO_ROOT, one)
            pb.build(_policy(), REPO_ROOT, two)
            a = {
                str(path.relative_to(one)): path.read_bytes()
                for path in one.rglob("*")
                if path.is_file()
            }
            b = {
                str(path.relative_to(two)): path.read_bytes()
                for path in two.rglob("*")
                if path.is_file()
            }
            self.assertEqual(sorted(a), sorted(b))
            for path in a:
                self.assertEqual(a[path], b[path], path)

    def test_the_committed_bundle_is_the_build_of_the_policy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b4-rebuild-") as temporary:
            rebuilt = Path(temporary) / "bundle"
            pb.build(_policy(), REPO_ROOT, rebuilt)
            committed = {
                str(path.relative_to(BUNDLE)): path.read_bytes()
                for path in BUNDLE.rglob("*")
                if path.is_file()
            }
            produced = {
                str(path.relative_to(rebuilt)): path.read_bytes()
                for path in rebuilt.rglob("*")
                if path.is_file()
            }
            self.assertEqual(sorted(committed), sorted(produced))
            for path in committed:
                self.assertEqual(committed[path], produced[path], path)


class RecordTests(unittest.TestCase):
    def test_the_classification_counts_are_internally_consistent(self) -> None:
        record = _load(CLASSIFICATION)
        counts = record["counts"]
        scan = record["scan"]
        self.assertEqual(
            counts["classified"],
            sum(counts["byClass"][name] for name in pb.CLASSES),
        )
        self.assertEqual(
            counts["classified"] + counts["unclassified"],
            scan["populationSource"]["population"],
        )
        self.assertEqual(counts["private"], counts["byClass"][pb.PRIVATE_NEVER_PUBLISHED])
        self.assertLessEqual(
            scan["referenceScan"]["privateReferenceArtefacts"],
            scan["populationSource"]["population"],
        )

    def test_the_scan_reports_its_bound(self) -> None:
        bound = _load(CLASSIFICATION)["scan"]["bound"]
        for key in (
            "maxFiles",
            "maxBytesPerMember",
            "maxBytesTotal",
            "reached",
            "contentScanned",
            "contentNotScanned",
            "truncatedMembers",
            "bytesRead",
        ):
            self.assertIn(key, bound)

    def test_the_publication_record_claims_nothing(self) -> None:
        record = _load(PUBLICATION)
        self.assertFalse(record["admittedService"])
        self.assertIsNone(record["endpoint"])
        self.assertEqual(record["published"], 0)
        self.assertEqual(record["externalVerification"], "PENDING")
        self.assertFalse(record["profile"]["admitted"])

    def test_the_venue_record_is_not_an_external_result(self) -> None:
        record = _load(VERIFICATION)
        self.assertEqual(record["outcome"], "PUBLIC_BUNDLE_VERIFIED_IN_VENUE")
        self.assertEqual(record["venue"], "in-venue")
        self.assertEqual(record["external"], "NOT_RUN")
        self.assertTrue(record["verified"])
        self.assertTrue(record["tempRootOutsideProject"])
        self.assertEqual(record["audit"]["outsideReads"], 0)
        self.assertEqual(record["audit"]["networkEvents"], 0)
        self.assertFalse(record["strippedEnvironment"]["inheritedVariables"])


class CommandLineTests(unittest.TestCase):
    def test_scan_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b4-cli-") as temporary:
            out = Path(temporary) / "scan.json"
            self.assertEqual(pb.main(["scan", "--out", str(out)]), pb.EXIT_OK)
            self.assertTrue(out.is_file())

    def test_classify_exits_zero_and_prints_the_class(self) -> None:
        self.assertEqual(
            pb.main(["classify", "evidence/a9/STATEMENTS/a8-shard-000.json"]),
            pb.EXIT_OK,
        )

    def test_verify_exits_zero_on_the_real_bundle(self) -> None:
        self.assertEqual(
            pb.main(
                [
                    "verify",
                    "--bundle",
                    str(BUNDLE),
                    "--policy",
                    str(CLASSIFICATION),
                ]
            ),
            pb.EXIT_OK,
        )

    def test_verify_exits_one_on_a_missing_bundle(self) -> None:
        self.assertEqual(
            pb.main(["verify", "--bundle", str(EVIDENCE / "not-a-bundle")]),
            pb.EXIT_REFUSED,
        )

    def test_a_usage_error_exits_two(self) -> None:
        self.assertEqual(pb.main([]), pb.EXIT_USAGE)


class DocumentTests(unittest.TestCase):
    def test_the_document_names_every_refusal_code_once_in_the_table(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        for code in pb.REFUSALS:
            self.assertIn(f"| `{code}` |", text, code)

    def test_the_document_names_no_code_the_tool_does_not_emit(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        documented = set(re.findall(r"PB_REFUSED_[A-Z_]+", text))
        self.assertEqual(documented, set(pb.REFUSALS))

    def test_the_document_names_the_four_classes(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        for name in pb.CLASSES:
            self.assertIn(name, text)

    def test_the_document_records_the_real_counts(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        counts = _load(CLASSIFICATION)["counts"]
        scan = _load(CLASSIFICATION)["scan"]
        self.assertIn(str(counts["classified"]), text)
        self.assertIn(str(scan["populationSource"]["population"]), text)
        self.assertIn(str(scan["bound"]["truncatedMembers"]), text)
        self.assertIn(str(scan["referenceScan"]["privateReferenceArtefacts"]), text)

    def test_the_document_records_the_bundle_digests(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        bundle = _load(CLASSIFICATION)["bundle"]
        self.assertIn(bundle["manifestDigest"], text)
        self.assertIn(bundle["policyDigest"], text)

    def test_the_document_states_the_real_result_and_the_non_claims(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        self.assertIn("admittedService: false", text)
        self.assertIn("published: 0", text)
        self.assertIn("externalVerification: PENDING", text)
        lowered = text.lower()
        self.assertIn("a publishable bundle is not a published one", lowered)
        self.assertIn("does not make the claim true", lowered)

    def test_the_document_has_a_not_run_section(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^#+ `?NOT_RUN`?")

    def test_every_enforced_by_names_a_code_or_a_test(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        for line in text.splitlines():
            if "enforced by" in line.lower():
                self.assertTrue(
                    "PB_REFUSED_" in line or "test_" in line or "control" in line.lower(),
                    line,
                )


if __name__ == "__main__":
    unittest.main()
