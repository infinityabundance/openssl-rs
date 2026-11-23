#!/usr/bin/env python3
"""Tests for forensics/tools/preservation.py and the ETP-T13 records.

Run directly (`python3 forensics/tools/tests/test_preservation.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.

The suite pins the five claims this item makes:

* repository object identity and content digests are separate systems, and a
  record naming an object format the repository does not report is refused;
* a reader accepts two tracked versions of one schema family and refuses a
  version it does not know, without falling back to the nearest known one;
* a digest renewal binds two algorithms over identical bytes and is refused when
  the bytes differ;
* a truncated archive, a byte-flipped member, a missing member and a manifest
  whose digest disagrees with the bytes are each refused;
* the archive fixture is deterministic, so a corruption control changes exactly
  one thing.

Each refusal is asserted by its named rule, and a positive control accompanies
the negative ones so a validator that refuses everything cannot pass.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
sys.path.insert(0, str(TOOLS))

import preservation  # noqa: E402

EVIDENCE = REPO_ROOT / "evidence" / "etp-t13"


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(REPO_ROOT), *args],
                                   text=True).strip()


class ObjectIdentityTests(unittest.TestCase):
    """Repository object identity is read from the repository, not inferred."""

    def test_object_format_comes_from_git(self) -> None:
        observed = preservation.repository_object_format(REPO_ROOT)
        self.assertEqual(observed, git("rev-parse", "--show-object-format"))
        self.assertIn(observed, preservation.OBJECT_FORMATS)

    def test_format_and_length_agree(self) -> None:
        commit = git("rev-parse", "HEAD")
        metadata = preservation.commit_metadata(REPO_ROOT, commit)
        expected = preservation.OBJECT_FORMATS[metadata["object_format"]][
            "oid_hex_length"]
        self.assertEqual(len(commit), expected)
        self.assertEqual(metadata["object_id_hex_length"], expected)
        self.assertEqual(metadata["identity_system"], "repository_object_identity")

    def test_mismatched_object_format_is_refused(self) -> None:
        record = {"commit": "a" * 40, "object_format": "sha256",
                  "object_id_hex_length": 40}
        with self.assertRaises(preservation.Refusal) as caught:
            preservation.require_object_format(record, "sha1")
        self.assertEqual(caught.exception.rule,
                         "PM_IDENTITY_OBJECT_FORMAT_MISMATCH")

    def test_object_id_length_is_refused(self) -> None:
        record = {"commit": "a" * 64, "object_format": "sha1",
                  "object_id_hex_length": 64}
        with self.assertRaises(preservation.Refusal) as caught:
            preservation.require_object_format(record, "sha1")
        self.assertEqual(caught.exception.rule,
                         "PM_IDENTITY_OBJECT_FORMAT_MISMATCH")

    def test_unknown_object_format_is_refused(self) -> None:
        record = {"commit": "a" * 40, "object_format": "md5"}
        with self.assertRaises(preservation.Refusal) as caught:
            preservation.require_object_format(record, "sha1")
        self.assertEqual(caught.exception.rule,
                         "PM_IDENTITY_OBJECT_FORMAT_UNKNOWN")

    def test_matching_identity_is_accepted(self) -> None:
        record = {"commit": "a" * 40, "object_format": "sha1",
                  "object_id_hex_length": 40}
        preservation.require_object_format(record, "sha1")

    def test_conflation_is_refused(self) -> None:
        with self.assertRaises(preservation.Refusal) as caught:
            preservation.refuse_conflation(
                {"object_id_algorithm": "sha256", "commit": "a" * 40}, "sha1")
        self.assertEqual(caught.exception.rule, "PM_IDENTITY_CONFLATION")

    def test_conflict_free_identity_is_accepted(self) -> None:
        preservation.refuse_conflation(
            {"object_id_algorithm": "sha1", "commit": "a" * 40}, "sha1")

    def test_object_id_and_content_digest_differ(self) -> None:
        path = "evidence/etp0/CLAIMS.json"
        commit = git("rev-parse", "HEAD")
        raw = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "show", f"{commit}:{path}"])
        object_id = git("rev-parse", f"{commit}:{path}")
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(len(object_id), 40)
        self.assertEqual(len(digest), 64)
        self.assertNotEqual(object_id, digest)


class CrossVersionReaderTests(unittest.TestCase):
    """Two known versions are read; an unknown version is refused."""

    FAMILY = preservation.CROSS_VERSION_FAMILY

    def v1(self) -> dict:
        return {"schema": f"{self.FAMILY}/v1", "family": "f",
                "source_identity": {}, "verdict": "x", "closure": {"a": 1}}

    def v2(self) -> dict:
        return {"schema": f"{self.FAMILY}/v2", "family": "f",
                "graph": {"nodes": []}, "precision": {}, "refusals": []}

    def test_first_version_accepted(self) -> None:
        result = preservation.read_versioned_document(self.v1(), "v1.json")
        self.assertEqual(result["version"], "v1")
        self.assertEqual(result["shape"], "flat-closure")

    def test_second_version_accepted(self) -> None:
        result = preservation.read_versioned_document(self.v2(), "v2.json")
        self.assertEqual(result["version"], "v2")
        self.assertEqual(result["shape"], "graph")

    def test_unknown_major_version_is_refused(self) -> None:
        document = self.v2()
        document["schema"] = f"{self.FAMILY}/v3"
        with self.assertRaises(preservation.Refusal) as caught:
            preservation.read_versioned_document(document, "v3.json")
        self.assertEqual(caught.exception.rule, "PM_SCHEMA_UNKNOWN_VERSION")

    def test_unknown_minor_version_is_not_nearest(self) -> None:
        document = self.v2()
        document["schema"] = f"{self.FAMILY}/v1.5"
        with self.assertRaises(preservation.Refusal) as caught:
            preservation.read_versioned_document(document, "v1.5.json")
        self.assertEqual(caught.exception.rule, "PM_SCHEMA_UNKNOWN_VERSION")

    def test_v2_document_is_not_read_as_v1(self) -> None:
        document = {"schema": f"{self.FAMILY}/v2", "family": "f",
                    "source_identity": {}, "verdict": "x", "closure": {}}
        with self.assertRaises(preservation.Refusal) as caught:
            preservation.read_versioned_document(document, "v2.json")
        self.assertIn(caught.exception.rule,
                      ("PM_SCHEMA_VERSION_SHAPE", "PM_SCHEMA_UNKNOWN_VERSION"))

    def test_tracked_documents_of_both_versions_are_accepted(self) -> None:
        commit = git("rev-parse", "HEAD")
        paths = ["forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                 "consumer-closure-C2.json",
                 "court/freeze-b76/e7-b76c-after.json"]
        for path in paths:
            raw = subprocess.check_output(
                ["git", "-C", str(REPO_ROOT), "show", f"{commit}:{path}"])
            result = preservation.read_versioned_document(
                json.loads(raw), path)
            self.assertIn(result["version"], ("v1", "v2"))


class DigestRenewalTests(unittest.TestCase):
    """A renewal binds old and new over identical bytes."""

    def record(self) -> tuple[dict, bytes]:
        raw = b"archived evidence bytes\n"
        record = {
            "subject": "evidence/x.bin",
            "subject_content_sha256": hashlib.sha256(raw).hexdigest(),
            "old": {"algorithm": "sha256",
                    "digest": preservation.digest_bytes("sha256", raw)},
            "new": {"algorithm": "sha384",
                    "digest": preservation.digest_bytes("sha384", raw)},
            "bytes_identical": True,
        }
        return record, raw

    def test_identical_bytes_accepted(self) -> None:
        record, raw = self.record()
        preservation.verify_renewal(record, raw)

    def test_differing_bytes_refused(self) -> None:
        record, raw = self.record()
        with self.assertRaises(preservation.Refusal) as caught:
            preservation.verify_renewal(record, raw + b"x")
        self.assertEqual(caught.exception.rule, "PM_RENEWAL_BYTES_CHANGED")

    def test_rewritten_old_binding_refused(self) -> None:
        record, raw = self.record()
        record["old"]["digest"] = "0" * 64
        with self.assertRaises(preservation.Refusal) as caught:
            preservation.verify_renewal(record, raw)
        self.assertEqual(caught.exception.rule, "PM_RENEWAL_BYTES_CHANGED")

    def test_renewal_over_a_tracked_subject(self) -> None:
        commit = git("rev-parse", "HEAD")
        for path in preservation.RENEWAL_SUBJECTS:
            record = preservation.make_renewal_record(REPO_ROOT, commit, path)
            raw = subprocess.check_output(
                ["git", "-C", str(REPO_ROOT), "show", f"{commit}:{path}"])
            preservation.verify_renewal(record, raw)
            self.assertNotEqual(record["old"]["algorithm"],
                                record["new"]["algorithm"])
            self.assertTrue(record["bytes_identical"])

    def test_unadmitted_renewal_algorithm_refused(self) -> None:
        _, raw = self.record()
        with self.assertRaises(preservation.Refusal) as caught:
            preservation.digest_bytes("crc32", raw)
        self.assertEqual(caught.exception.rule,
                         "PM_DIGEST_ALGORITHM_UNADMITTED")


class ArchiveControlTests(unittest.TestCase):
    """Every named corruption class is refused, and the fixture is stable."""

    def setUp(self) -> None:
        self.manifest = preservation.build_archive_manifest()
        self.archive = preservation.build_archive_fixture()

    def assert_refused(self, archive: bytes, manifest: dict, rule: str) -> None:
        with self.assertRaises(preservation.Refusal) as caught:
            preservation.verify_archive_bytes(archive, manifest)
        self.assertEqual(caught.exception.rule, rule)

    def test_healthy_archive_accepted(self) -> None:
        result = preservation.verify_archive_bytes(self.archive, self.manifest)
        self.assertEqual(result["members"], 3)
        self.assertEqual(result["digest_algorithm"], "sha256")

    def test_truncated_archive_refused(self) -> None:
        self.assert_refused(self.archive[: len(self.archive) // 2],
                            self.manifest, "PM_ARCHIVE_TRUNCATED")

    def test_byte_flipped_member_refused(self) -> None:
        members = dict(preservation.ARCHIVE_FIXTURE_MEMBERS)
        members["records/NOTE.txt"] = b"a second archived membeR\n"
        self.assert_refused(preservation.build_archive_fixture(members),
                            self.manifest, "PM_ARCHIVE_MEMBER_DIGEST")

    def test_missing_member_refused(self) -> None:
        members = dict(preservation.ARCHIVE_FIXTURE_MEMBERS)
        del members["records/FORMATS.json"]
        self.assert_refused(preservation.build_archive_fixture(members),
                            self.manifest, "PM_ARCHIVE_MEMBER_MISSING")

    def test_manifest_digest_disagreement_refused(self) -> None:
        manifest = preservation.build_archive_manifest()
        manifest["members"][0]["sha256"] = "0" * 64
        self.assert_refused(self.archive, manifest, "PM_ARCHIVE_MEMBER_DIGEST")

    def test_unlisted_member_refused(self) -> None:
        members = dict(preservation.ARCHIVE_FIXTURE_MEMBERS)
        members["records/EXTRA.txt"] = b"not in the manifest\n"
        self.assert_refused(preservation.build_archive_fixture(members),
                            self.manifest, "PM_ARCHIVE_MEMBER_UNLISTED")

    def test_manifest_algorithm_must_be_named(self) -> None:
        manifest = preservation.build_archive_manifest()
        del manifest["digest_algorithm"]
        self.assert_refused(self.archive, manifest,
                            "PM_DIGEST_ALGORITHM_UNNAMED")

    def test_fixture_is_deterministic(self) -> None:
        self.assertEqual(self.archive, preservation.build_archive_fixture())
        self.assertEqual(json.dumps(self.manifest, sort_keys=True),
                         json.dumps(preservation.build_archive_manifest(),
                                    sort_keys=True))

    def test_named_controls_all_fire(self) -> None:
        controls = preservation.archive_controls()
        for control in controls:
            self.assertTrue(control["passed"],
                            f"{control['control']}: {control['detail']}")
        names = {control["control"] for control in controls}
        self.assertTrue({
            "truncated_archive_refused", "byte_flipped_member_refused",
            "missing_member_refused", "manifest_digest_disagreement_refused",
        } <= names)


class RecordShapeTests(unittest.TestCase):
    """The committed records are readable and keep the systems apart."""

    def load(self, name: str) -> dict:
        return json.loads((EVIDENCE / name).read_text(encoding="utf-8"))

    def test_records_declare_versions(self) -> None:
        expected = {
            "FORMATS.json": "openssl-rs/etp-t13/formats/1",
            "DIGESTS.json": "openssl-rs/etp-t13/digests/1",
            "ARCHIVAL.json": "openssl-rs/etp-t13/archival/1",
            "IDENTITY-SYSTEMS.json": "openssl-rs/etp-t13/identity-systems/1",
        }
        for name, schema in expected.items():
            self.assertEqual(self.load(name)["schema"], schema)

    def test_identity_record_names_the_repository_format(self) -> None:
        record = self.load("IDENTITY-SYSTEMS.json")
        observed = preservation.repository_object_format(REPO_ROOT)
        self.assertEqual(record["systems"]["repository_object_identity"]
                         ["object_format"], observed)
        self.assertEqual(record["candidate"]["object_format"], observed)
        self.assertEqual(len(record["distinctness_evidence"]["object_id"]),
                         preservation.OBJECT_FORMATS[observed]["oid_hex_length"])
        self.assertEqual(
            record["systems"]["signature_and_attestation"]["status"], "ABSENT")

    def test_digest_record_separates_object_ids(self) -> None:
        record = self.load("DIGESTS.json")
        population = record["population"]
        self.assertIn("repository_object_ids", population)
        self.assertGreater(population["repository_object_ids"]["occurrences"], 0)
        for algorithm in population["named"]["by_algorithm"]:
            self.assertIn(algorithm, preservation.ADMITTED_IDS)

    def test_renewal_records_cover_identical_bytes(self) -> None:
        record = self.load("DIGESTS.json")
        commit = record["candidate"]["commit"]
        for entry in record["renewal_records"]:
            raw = subprocess.check_output(
                ["git", "-C", str(REPO_ROOT), "show",
                 f"{commit}:{entry['subject']}"])
            preservation.verify_renewal(entry, raw)

    def test_cross_version_demonstration_is_recorded(self) -> None:
        cross = self.load("FORMATS.json")["cross_version_reader"]
        self.assertGreaterEqual(len(cross["known_versions"]), 2)
        self.assertTrue(cross["unknown_version_refusal"]["demonstrated"])
        accepted = {row["version"] for row in cross["accepted_examples"]
                    if "refusal" not in row}
        self.assertTrue(set(cross["known_versions"]) <= accepted)

    def test_archival_record_states_no_external_durability(self) -> None:
        record = self.load("ARCHIVAL.json")
        self.assertEqual(record["external_durability"]["status"], "NONE")
        self.assertEqual(record["external_durability"]["etp6_role"],
                         "BUNDLE_NOT_ARCHIVE")
        self.assertEqual(record["external_durability"]["external_archives"], [])
        for row in record["classes"]:
            self.assertFalse(row["externally_durable"])

    def test_verifier_reconstructability_is_recorded(self) -> None:
        record = self.load("ARCHIVAL.json")["verifier_reconstructability"]
        self.assertTrue(record["tools"])
        self.assertIn("requirement", record["interpreter"])
        self.assertTrue(record["not_recorded"])


class SelfTestTests(unittest.TestCase):
    """Every admission rule has a passing control."""

    def test_all_controls_pass(self) -> None:
        controls = preservation.self_test()
        for control in controls:
            self.assertTrue(control["passed"],
                            f"{control['control']}: {control['detail']}")

    def test_every_rule_is_covered(self) -> None:
        covered = {control["rule"] for control in preservation.self_test()
                   if control.get("rule")}
        self.assertEqual(set(preservation.ADMISSION_RULES) - covered, set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
