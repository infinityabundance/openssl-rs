#!/usr/bin/env python3
"""Controls for the PFP-54 retrieval manifest.

The manifest declares the audited subject unavailable rather than inventing a
retrieval path. That declaration is only honest if the digests it binds are the
digests of the committed bytes: this test recomputes every committed-file digest
from disk, and checks the two digests whose bytes are gone against the
`build-inputs.txt` record the build itself wrote.

Run:

    python3 -m unittest forensics.tools.tests.test_retrieval_manifest
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CAMPAIGN = REPO_ROOT / "evidence" / "performance-frontier" / "campaigns" / "PFP-54"
MANIFEST = CAMPAIGN / "retrieval-manifest.json"
REGISTER = REPO_ROOT / "forensics" / "performance" / "KERNELS.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class RetrievalManifest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = load(MANIFEST)
        self.record = {}
        for line in (CAMPAIGN / "raw" / "build-inputs.txt").read_text(
            encoding="utf-8"
        ).splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                self.record[key] = value

    def test_the_subject_is_declared_unavailable_not_validated(self) -> None:
        self.assertEqual(
            self.manifest["subject_availability"], "UNAVAILABLE_DECLARED"
        )
        self.assertTrue(self.manifest["why"].strip())

    def test_the_committed_file_digests_are_recomputed(self) -> None:
        self.assertEqual(
            self.manifest["build_input_sha256"],
            sha256(CAMPAIGN / "raw" / "build-inputs.txt"),
        )
        self.assertEqual(
            self.manifest["audit_report_sha256"],
            sha256(CAMPAIGN / "raw" / "audit-a5354547.md"),
        )
        self.assertEqual(
            self.manifest["reproduction_recipe_sha256"],
            sha256(CAMPAIGN / "build.sh"),
        )

    def test_the_gone_bytes_match_the_build_record(self) -> None:
        self.assertEqual(self.manifest["subject_sha256"], self.record["shipped_sha256"])
        self.assertEqual(self.manifest["debug_sha256"], self.record["debug_sha256"])
        self.assertEqual(
            self.manifest["build_input_source_commit"], self.record["source_commit"]
        )

    def test_every_artefact_audit_entry_declares_this_manifest(self) -> None:
        document = load(REGISTER)
        found = 0
        for kernel in document["kernels"]:
            for entry in kernel["assurance"]:
                if entry["class"] != "ARTEFACT_AUDITED":
                    continue
                artefact = entry["subject"]["artefact"]
                retrieval = artefact["retrieval"]
                self.assertEqual(artefact["sha256"], self.manifest["subject_sha256"])
                self.assertEqual(retrieval["kind"], "unavailable")
                self.assertEqual(
                    retrieval["recipe"], self.manifest["reproduction_recipe_path"]
                )
                self.assertTrue(retrieval["why"].strip())
                self.assertTrue(
                    entry["scope"].startswith(
                        "instruction inventory at the shipped digest; "
                        "secret-dependence NOT_ASSESSED"
                    )
                )
                found += 1
        self.assertEqual(found, 5)


if __name__ == "__main__":
    unittest.main()
