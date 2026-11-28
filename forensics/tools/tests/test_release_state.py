#!/usr/bin/env python3
"""Controls for `forensics/tools/release_state.py`.

The release-state checker refuses four internal contradictions that a
document/evidence comparison cannot see.  One negative control per refusal code
mutates the corrected 0.0.51 receipts until that code fires; the positive
control proves the committed receipts pass; and the supersede pair proves an
explicitly marked correction is non-asserting while an unqualified copy of the
same claim is refused.

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
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import release_state as rs  # noqa: E402

ATLAS = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh"
# The tests must describe the newest release, not a pinned one: the baseline is a
# single current record, and `check_root` applies it only to the newest version.
# Pinning a version made these tests stale the moment the next release shipped.
VERSION = rs.versions(ROOT)[-1]


def load(name: str) -> dict:
    return json.loads((ATLAS / name).read_text(encoding="utf-8"))


def real_publish() -> dict:
    return load(f"publish-{VERSION}.json")


def real_build() -> dict:
    return load(f"build-{VERSION}.json")


def real_baseline() -> dict:
    return load("test-baseline.json")


def real_readme() -> str:
    return (ROOT / "README.md").read_text(encoding="utf-8")


def run(publish: dict, build: dict | None = None, baseline: dict | None = None,
        readme: str = "") -> list[rs.Finding]:
    return rs.check_version(VERSION, publish, build, baseline, readme)


def codes(findings: list[rs.Finding]) -> set[str]:
    return {finding.code for finding in findings}


class PositiveControl(unittest.TestCase):
    def test_corrected_receipts_pass(self) -> None:
        findings = run(real_publish(), real_build(), real_baseline(), real_readme())
        self.assertEqual(findings, [])

    def test_every_committed_receipt_passes(self) -> None:
        self.assertEqual(rs.check_root(ROOT), [])

    def test_the_six_codes_are_distinct(self) -> None:
        self.assertEqual(len(rs.CODES), 6)
        self.assertEqual(len(set(rs.CODES)), 6)


class NegativeControls(unittest.TestCase):
    def test_code_1_published_beside_prepublication_claim(self) -> None:
        publish = real_publish()
        publish["release_process"]["disclosure"] = (
            "This receipt is pre-publish. No upload has occurred; status PENDING."
        )
        self.assertIn(rs.RS_PUBLISHED_WITH_PREPUBLICATION_CLAIM,
                      codes(run(publish, real_build(), real_baseline(), real_readme())))

    def test_code_1_packaging_note_says_no_publish(self) -> None:
        publish = real_publish()
        publish["packaging"]["crate_path_note"] = (
            "No `cargo publish` has run for 0.0.51; the checksum is deliberately PENDING."
        )
        self.assertIn(rs.RS_PUBLISHED_WITH_PREPUBLICATION_CLAIM,
                      codes(run(publish, real_build(), real_baseline(), real_readme())))

    def test_code_1_stale_build_receipt_still_says_pending_publish(self) -> None:
        build = copy.deepcopy(real_build())
        build["status"] = "BUILT (pending publish)"
        build["release_commit"] = "a" * 40  # claim a released identity
        build["published_as"] = (
            f"pending: atlas-refresh/publish-{VERSION}.json (checksum PENDING)"
        )
        build["crate_package"] = {
            "status": "PENDING",
            "note": f"No crate package was produced or uploaded for {VERSION}.",
        }
        self.assertIn(rs.RS_PUBLISHED_WITH_PREPUBLICATION_CLAIM,
                      codes(run(real_publish(), build, real_baseline(), real_readme())))

    def test_code_2_verified_with_pending_recomputed_hash(self) -> None:
        publish = real_publish()
        publish["registry_verification"]["download_sha256_recomputed"] = "PENDING"
        self.assertIn(rs.RS_VERIFIED_WITHOUT_RECOMPUTED_HASH,
                      codes(run(publish, real_build(), real_baseline(), real_readme())))

    def test_code_2_verified_with_mismatched_hash(self) -> None:
        publish = real_publish()
        publish["registry_verification"]["download_sha256_recomputed"] = "0" * 64
        self.assertIn(rs.RS_VERIFIED_WITHOUT_RECOMPUTED_HASH,
                      codes(run(publish, real_build(), real_baseline(), real_readme())))

    def test_code_2_verified_but_download_not_run(self) -> None:
        publish = real_publish()
        publish["registry_verification"]["download_verification"] = (
            "NOT_RUN — no upload has happened"
        )
        self.assertIn(rs.RS_VERIFIED_WITHOUT_RECOMPUTED_HASH,
                      codes(run(publish, real_build(), real_baseline(), real_readme())))

    def test_code_3_equivalence_claim_without_released_digest(self) -> None:
        publish = real_publish()
        publish["source_identity"] = {
            "commit": publish["source_identity"]["commit"],
            "note": "The packaging tree is identical to the release tree.",
        }
        self.assertIn(rs.RS_TREE_EQUIVALENCE_UNPROVEN,
                      codes(run(publish, None, None, real_readme())))

    def test_code_3_released_build_names_a_different_commit(self) -> None:
        build = real_build()
        build["status"] = "RELEASED"
        build["release_commit"] = "e" * 40
        build["source_identity"]["measured_source_commit"] = "e" * 40
        build["source_identity"]["release_tree_digest_recomputed_at"] = "e" * 40
        publish = real_publish()
        publish["source_identity"]["note"] = "Published from commit a0aca565."
        self.assertIn(rs.RS_TREE_EQUIVALENCE_UNPROVEN,
                      codes(run(publish, build, None, real_readme())))

    def test_code_3_build_digest_not_recomputed_at_the_release(self) -> None:
        build = real_build()
        build["source_identity"]["release_tree_digest_recomputed_at"] = (
            "working tree at 9bc9c387f8e3380fcbaa180148023be80ddd4885 "
            "(no release commit exists yet)"
        )
        self.assertIn(rs.RS_TREE_EQUIVALENCE_UNPROVEN,
                      codes(run(real_publish(), build, None, real_readme())))

    def test_code_4_readme_asserts_a_published_version_is_unreleased(self) -> None:
        readme = (
            f"**Release position.** {VERSION} is published on crates.io. "
            f"No {VERSION} release push or upload has occurred and the checksum was "
            "PENDING.\n"
        )
        self.assertIn(rs.RS_DOC_CONTRADICTS_LIFECYCLE,
                      codes(run(real_publish(), real_build(), real_baseline(), readme)))

    def test_code_5_declared_lifecycle_exceeds_evidence(self) -> None:
        publish = real_publish()
        del publish["registry_verification"]["download_sha256_recomputed"]
        del publish["registry_verification"]["download_verification"]
        self.assertIn(rs.RS_LIFECYCLE_UNEARNED,
                      codes(run(publish, real_build(), real_baseline(), real_readme())))

    def test_code_5_a_well_formed_digest_is_required(self) -> None:
        publish = real_publish()
        publish["registry_verification"]["checksum"] = "matching-but-not-a-sha256"
        publish["registry_verification"]["download_sha256_recomputed"] = (
            "matching-but-not-a-sha256"
        )
        found = codes(run(publish, real_build(), real_baseline(), real_readme()))
        self.assertTrue(
            rs.RS_LIFECYCLE_UNEARNED in found
            or rs.RS_VERIFIED_WITHOUT_RECOMPUTED_HASH in found
        )

    def test_code_6_instrument_ledger_denies_an_evidenced_upload(self) -> None:
        publish = real_publish()
        publish["instruments_not_run_at_this_identity"].append(
            "crates.io upload and download-checksum verification (not run; no upload performed)"
        )
        self.assertIn(rs.RS_INSTRUMENT_DENIES_EVIDENCED_EVENT,
                      codes(run(publish, real_build(), real_baseline(), real_readme())))

    def test_code_6_a_marked_correction_entry_is_non_asserting(self) -> None:
        publish = real_publish()
        publish["instruments_not_run_at_this_identity"].append(
            "Superseded: crates.io upload was not run"
        )
        findings = codes(run(publish, real_build(), real_baseline(), real_readme()))
        self.assertNotIn(rs.RS_INSTRUMENT_DENIES_EVIDENCED_EVENT, findings)

    def test_registry_note_denying_observation_is_refused(self) -> None:
        publish = real_publish()
        publish["registry_verification"]["note"] = (
            "No registry payload has been observed for 0.0.51."
        )
        self.assertIn(rs.RS_PUBLISHED_WITH_PREPUBLICATION_CLAIM,
                      codes(run(publish, real_build(), real_baseline(), real_readme())))


class SupersedeRule(unittest.TestCase):
    """A marked correction is non-asserting; the unqualified claim is refused."""

    ASSERTION = (
        f"{VERSION} has not been pushed and the checksum was PENDING."
    )

    def test_superseded_claim_passes(self) -> None:
        readme = (
            f"{VERSION} is published on crates.io.\n\n"
            f"*Superseded text (2026-11-28): {self.ASSERTION} That was true when "
            "written and is false now.*\n"
        )
        findings = run(real_publish(), real_build(), real_baseline(), readme)
        self.assertEqual(findings, [])

    def test_unqualified_identical_claim_fails(self) -> None:
        readme = f"{VERSION} is published on crates.io. {self.ASSERTION}\n"
        findings = run(real_publish(), real_build(), real_baseline(), readme)
        self.assertIn(rs.RS_DOC_CONTRADICTS_LIFECYCLE, codes(findings))

    def test_marked_paragraph_is_non_asserting(self) -> None:
        readme = (
            f"{VERSION} is published on crates.io.\n\n"
            f"> **Superseded 2026-11-28.** {self.ASSERTION} The old text is kept "
            "as a correction record.\n"
        )
        self.assertEqual(run(real_publish(), real_build(), real_baseline(), readme), [])

    def test_generated_block_is_not_prose(self) -> None:
        readme = (
            f"{VERSION} is published on crates.io.\n"
            "<!-- BEGIN GENERATED: release -->\n"
            f"{VERSION} is unreleased and the checksum is PENDING.\n"
            "<!-- END GENERATED: release -->\n"
        )
        self.assertEqual(run(real_publish(), real_build(), real_baseline(), readme), [])


class ReleaseBlockSelfReference(unittest.TestCase):
    """The rendered Release row may not name a commit or a checksum.

    A release commit cannot be known while the release is being packaged, and a
    checksum is computed over the bytes that contain the sentence.  Both are
    post-packaging facts and belong in the receipts.
    """

    def test_release_row_names_no_commit_and_no_checksum(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "render_docs_under_test", TOOLS / "render_docs.py"
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        text = module.Evidence(ROOT).release_text()
        self.assertIsNone(re.search(r"\b[0-9a-fA-F]{40}\b", text), text)
        self.assertIsNone(re.search(r"\b[0-9a-fA-F]{64}\b", text), text)
        self.assertNotIn("from commit", text.lower())
        self.assertIn("build-", text)
        self.assertIn("publish-", text)


class Wiring(unittest.TestCase):
    def test_docs_consistency_runs_the_release_state_check(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "docs_consistency_under_test", TOOLS / "docs_consistency.py"
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.assertIs(module.release_state, rs)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = module.main(["--list"])
        self.assertEqual(code, 0)
        self.assertIn("release_state_consistency", buffer.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
