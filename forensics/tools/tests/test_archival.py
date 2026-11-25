#!/usr/bin/env python3
"""Controls for ``forensics/tools/archival.py`` and the B6 records.

One control per refusal code, each with a restoration replay; the archive both
ways (reconstruction from a copy outside the repository succeeds, one flipped
byte and one discarded member refuse); state version monotonicity and the two
replay refusals; the three facts together -- the inclusion proof still verifies
while the state is WITHDRAWN and a present-tense use is refused; producer
determinism; the command line's exit codes; and the normative document staying
in step with the tool.

These are controls, not a conformity result.  A refusal that fires proves the
check works; it does not prove that any real archive is complete, that FIXTURE-2
is an admitted log, or that the withdrawal is authenticated.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
sys.dont_write_bytecode = True
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import archival  # noqa: E402
import corrections  # noqa: E402
import tlog  # noqa: E402

EVIDENCE = REPO_ROOT / "evidence" / "b6"
ARCHIVE = EVIDENCE / "ARCHIVE"
CURRENT_STATE = EVIDENCE / "CURRENT-STATE.json"
DEMONSTRATION = EVIDENCE / "DEMONSTRATION.json"
CONTROLS = EVIDENCE / "CONTROLS.json"
FIXTURE = EVIDENCE / "FIXTURE-2.json"
ARCHIVE_RECORD = EVIDENCE / "ARCHIVE.json"
PRODUCER = EVIDENCE / "build_evidence.py"
DOCUMENT = REPO_ROOT / "docs" / "ARCHIVAL-REVOCATION.md"
QUEUE = REPO_ROOT / "docs" / "ETP-TODO.md"
TOOL = TOOLS / "archival.py"

SUBJECT = "ETP0-CLM-032/verdict"
EARLIER_MEMBER = ARCHIVE / "members/state/current-state-21.json"
CURRENT_MEMBER = ARCHIVE / "members/state/current-state-22.json"


def _document(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _builder():
    spec = importlib.util.spec_from_file_location("b6_build_evidence", PRODUCER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _copy_archive(destination: Path) -> Path:
    target = destination / "ARCHIVE"
    shutil.copytree(ARCHIVE, target)
    return target


class RefusalTable(unittest.TestCase):
    """Every code has one control, every control is control-only, all fired."""

    def setUp(self) -> None:
        self.controls = _document(CONTROLS)["controls"]

    def test_every_refusal_code_has_exactly_one_control(self) -> None:
        fired = [row["code"] for row in self.controls if row["code"] != archival.CODE_OK]
        self.assertEqual(sorted(fired), sorted(archival.REFUSALS))
        self.assertEqual(len(fired), len(set(fired)), "a code has two controls")

    def test_the_positive_control_passes(self) -> None:
        positives = [row for row in self.controls if row["code"] == archival.CODE_OK]
        self.assertEqual(len(positives), 1)
        self.assertTrue(positives[0]["restoration"]["accepted"])
        self.assertEqual(
            positives[0]["restoration"]["current"], archival.STATE_WITHDRAWN
        )

    def test_every_control_is_control_only_and_fired(self) -> None:
        for row in self.controls:
            self.assertTrue(row["controlOnly"], row["name"])
            self.assertTrue(row["fired"], row["name"])
            self.assertTrue(row["mutation"], row["name"])

    def test_every_control_has_a_restoration(self) -> None:
        for row in self.controls:
            self.assertIn("restoration", row, row["name"])
            self.assertIn("accepted", row["restoration"], row["name"])

    def test_codes_are_namespaced_and_distinct(self) -> None:
        for code in archival.ALL_CODES:
            self.assertTrue(code.startswith("RV_"), code)
        self.assertEqual(len(archival.ALL_CODES), len(set(archival.ALL_CODES)))

    def test_every_code_states_what_it_prevents(self) -> None:
        for code, entry in archival.REFUSALS.items():
            self.assertTrue(entry["condition"], code)
            self.assertTrue(entry["prevents"], code)


class ArchiveReconstruction(unittest.TestCase):
    """The archive is self-contained, and both failure directions refuse."""

    def test_the_committed_archive_reconstructs(self) -> None:
        result = archival.reconstruct(ARCHIVE)
        self.assertEqual(result["code"], archival.CODE_OK)
        self.assertEqual(result["subject"], SUBJECT)
        self.assertEqual(result["inclusion"]["leafIndex"], 1)
        self.assertEqual(result["inclusion"]["treeSize"], 5)
        self.assertEqual(result["state"]["state"], archival.STATE_WITHDRAWN)
        self.assertEqual(result["state"]["version"], 22)
        self.assertEqual(len(result["checks"]), 9)

    def test_member_digests_match_the_files(self) -> None:
        manifest = _document(ARCHIVE / "MANIFEST.json")
        self.assertEqual(manifest["manifestDigest"], archival.manifest_digest(manifest))
        for member in manifest["members"]:
            data = (ARCHIVE / member["path"]).read_bytes()
            self.assertEqual(len(data), member["bytes"], member["id"])
            self.assertEqual(archival.sha256_bytes(data), member["sha256"], member["id"])

    def test_the_archive_record_matches_a_fresh_reconstruction(self) -> None:
        recorded = _document(ARCHIVE_RECORD)["reconstruction"]
        self.assertEqual(recorded, archival.reconstruct(ARCHIVE))

    def test_reconstruction_reads_only_the_archive_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b6-reconstruct-") as temporary:
            archive = _copy_archive(Path(temporary))
            elsewhere = Path(temporary) / "no-such-repository"
            original = archival.REPO_ROOT
            archival.REPO_ROOT = elsewhere
            try:
                result = archival.reconstruct(archive)
            finally:
                archival.REPO_ROOT = original
            self.assertEqual(result["code"], archival.CODE_OK)
            self.assertEqual(
                result["manifestDigest"],
                _document(ARCHIVE / "MANIFEST.json")["manifestDigest"],
            )

    def test_one_flipped_byte_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b6-flip-") as temporary:
            archive = _copy_archive(Path(temporary))
            member = archive / "members/statements/fixture-withdrawn-claim.json"
            data = bytearray(member.read_bytes())
            data[-2] ^= 0x01
            member.write_bytes(bytes(data))
            with self.assertRaises(archival.Refusal) as caught:
                archival.reconstruct(archive)
            self.assertEqual(
                caught.exception.code, archival.RV_REFUSED_RECONSTRUCTION_MISMATCH
            )

    def test_a_discarded_member_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b6-missing-") as temporary:
            archive = _copy_archive(Path(temporary))
            (archive / "members/a19/binding.json").unlink()
            with self.assertRaises(archival.Refusal) as caught:
                archival.reconstruct(archive)
            self.assertEqual(caught.exception.code, archival.RV_REFUSED_ARCHIVE_MISSING)

    def test_a_manifest_not_covering_its_bytes_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b6-manifest-") as temporary:
            archive = _copy_archive(Path(temporary))
            path = archive / "MANIFEST.json"
            manifest = _document(path)
            manifest["archiveId"] = "edited"
            path.write_text(
                json.dumps(manifest, indent=1, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(archival.Refusal) as caught:
                archival.reconstruct(archive)
            self.assertEqual(
                caught.exception.code, archival.RV_REFUSED_ARCHIVE_INVALID
            )

    def test_a_member_path_outside_the_archive_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b6-escape-") as temporary:
            archive = _copy_archive(Path(temporary))
            path = archive / "MANIFEST.json"
            manifest = _document(path)
            manifest["members"][0]["path"] = "../outside.json"
            manifest["manifestDigest"] = archival.manifest_digest(manifest)
            path.write_text(
                json.dumps(manifest, indent=1, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(archival.Refusal) as caught:
                archival.reconstruct(archive)
            self.assertEqual(
                caught.exception.code, archival.RV_REFUSED_ARCHIVE_INVALID
            )

    def test_the_checkpoint_is_the_fixture_size_five_head(self) -> None:
        result = archival.reconstruct(ARCHIVE)
        self.assertEqual(result["checkpoint"]["origin"], "FIXTURE-2")
        self.assertEqual(result["checkpoint"]["size"], 5)
        self.assertTrue(result["checkpoint"]["notATrustRoot"])
        fixture = _document(FIXTURE)
        self.assertEqual(result["checkpoint"]["root"], fixture["publication"]["rootHash"])

    def test_the_fixture_record_names_the_same_proof(self) -> None:
        fixture = _document(FIXTURE)
        proof = [bytes.fromhex(value) for value in fixture["publication"]["inclusionProof"]]
        statement = (ARCHIVE / "members/statements/fixture-withdrawn-claim.json").read_bytes()
        root = bytes.fromhex(fixture["publication"]["rootHash"])
        tlog.verify_inclusion(statement, fixture["publication"]["leafIndex"], 5, proof, root)


class CurrentState(unittest.TestCase):
    """The state is derived, versioned, bound to A19, and anti-rollback holds."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.events = archival.load_events()
        cls.earlier = _document(EARLIER_MEMBER)
        cls.current = _document(CURRENT_MEMBER)

    def test_the_committed_state_is_the_derivation(self) -> None:
        derived_earlier = archival.derive_state(self.events, upto=21)
        derived_current = archival.derive_state(
            self.events, upto=22, previous=derived_earlier
        )
        self.assertEqual(
            json.loads(json.dumps(derived_earlier)), self.earlier
        )
        self.assertEqual(
            json.loads(json.dumps(derived_current)), self.current
        )

    def test_the_state_is_the_committed_current_state_file(self) -> None:
        self.assertEqual(_document(CURRENT_STATE), self.current)

    def test_the_version_is_the_a19_event_count(self) -> None:
        self.assertEqual(self.earlier["version"], 21)
        self.assertEqual(self.current["version"], len(self.events["events"]))
        self.assertGreater(self.current["version"], self.earlier["version"])
        self.assertEqual(self.current["previous"]["version"], self.earlier["version"])
        self.assertEqual(self.current["previous"]["digest"], self.earlier["digest"])

    def test_every_entry_binds_to_the_a19_log(self) -> None:
        archival.validate_state(self.current, self.events)
        archival.check_propagation(self.current, self.events)

    def test_the_accepted_states_are_counted(self) -> None:
        states = [entry["state"] for entry in self.current["subjects"]]
        self.assertEqual(states.count(archival.STATE_ACTIVE), 0)
        self.assertEqual(states.count(archival.STATE_CORRECTED), 6)
        self.assertEqual(states.count(archival.STATE_WITHDRAWN), 5)
        self.assertEqual(len(states), 11)

    def test_the_claim_is_active_then_withdrawn(self) -> None:
        self.assertEqual(
            archival.current(self.earlier, SUBJECT)["state"], archival.STATE_ACTIVE
        )
        self.assertEqual(
            archival.current(self.current, SUBJECT)["state"], archival.STATE_WITHDRAWN
        )
        self.assertEqual(
            archival.current(self.current, SUBJECT)["supersededBy"], "A19-E22"
        )

    def test_the_correction_digest_is_the_retraction_event(self) -> None:
        retraction = next(
            event
            for event in self.events["events"]
            if event["eventId"] == "A19-E22"
        )
        self.assertEqual(
            archival.current(self.current, SUBJECT)["correctionDigest"],
            corrections.event_digest(retraction),
        )

    def test_a_withdrawal_with_no_correction_is_refused(self) -> None:
        unbound = copy.deepcopy(self.current)
        for entry in unbound["subjects"]:
            if entry["subject"] == SUBJECT:
                entry["correctionDigest"] = None
        unbound.pop("digest")
        unbound["digest"] = archival.state_digest(unbound)
        with self.assertRaises(archival.Refusal) as caught:
            archival.validate_state(unbound, self.events)
        self.assertEqual(
            caught.exception.code, archival.RV_REFUSED_REVOCATION_UNBOUND
        )

    def test_a_correction_pointing_at_a_missing_event_is_refused(self) -> None:
        forged = copy.deepcopy(self.current)
        for entry in forged["subjects"]:
            if entry["subject"] == SUBJECT:
                entry["supersededBy"] = "A19-E99"
        forged.pop("digest")
        forged["digest"] = archival.state_digest(forged)
        with self.assertRaises(archival.Refusal) as caught:
            archival.validate_state(forged, self.events)
        self.assertEqual(
            caught.exception.code, archival.RV_REFUSED_REVOCATION_UNBOUND
        )

    def test_an_unpropagated_correction_is_refused(self) -> None:
        with self.assertRaises(archival.Refusal) as caught:
            archival.check_propagation(self.earlier, self.events)
        self.assertEqual(
            caught.exception.code, archival.RV_REFUSED_CORRECTION_UNPROPAGATED
        )

    def test_a_hand_edited_state_is_refused(self) -> None:
        edited = copy.deepcopy(self.current)
        edited["version"] = 23
        with self.assertRaises(archival.Refusal) as caught:
            archival.validate_state(edited)
        self.assertEqual(caught.exception.code, archival.RV_REFUSED_STATE_INVALID)

    def test_a_version_may_not_decrease(self) -> None:
        self.assertEqual(
            archival.check_monotonic(self.earlier, self.current)["code"],
            archival.CODE_OK,
        )
        with self.assertRaises(archival.Refusal) as caught:
            archival.check_monotonic(self.current, self.earlier)
        self.assertEqual(
            caught.exception.code, archival.RV_REFUSED_ROLLBACK_OF_STATE
        )

    def test_a_replayed_state_is_refused(self) -> None:
        with self.assertRaises(archival.Refusal) as caught:
            archival.admit(self.earlier, self.current, log=self.events)
        self.assertEqual(
            caught.exception.code, archival.RV_REFUSED_REPLAY_AS_CURRENT
        )

    def test_the_current_state_is_idempotent(self) -> None:
        result = archival.admit(self.current, self.current, log=self.events)
        self.assertEqual(result["outcome"], "UNCHANGED")

    def test_a_same_version_conflict_is_refused(self) -> None:
        conflicting = copy.deepcopy(self.current)
        conflicting["asOf"] = "2026-11-24T00:00:00Z"
        conflicting.pop("digest")
        conflicting["digest"] = archival.state_digest(conflicting)
        with self.assertRaises(archival.Refusal) as caught:
            archival.admit(conflicting, self.current, log=self.events)
        self.assertEqual(caught.exception.code, archival.RV_REFUSED_STATE_CONFLICT)

    def test_a_skipped_version_is_refused(self) -> None:
        leap = copy.deepcopy(self.current)
        leap["version"] = 23
        leap.pop("digest")
        leap["digest"] = archival.state_digest(leap)
        with self.assertRaises(archival.Refusal) as caught:
            archival.admit(leap, self.current, log=self.events)
        self.assertEqual(caught.exception.code, archival.RV_REFUSED_STATE_INVALID)

    def test_a_derivation_out_of_range_is_refused(self) -> None:
        with self.assertRaises(archival.Refusal) as caught:
            archival.derive_state(self.events, upto=0)
        self.assertEqual(caught.exception.code, archival.RV_REFUSED_USAGE)


class TheThreeFacts(unittest.TestCase):
    """Inclusion valid, state withdrawn, present-tense use refused -- together."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.current = _document(CURRENT_MEMBER)
        cls.earlier = _document(EARLIER_MEMBER)

    def test_inclusion_remains_valid_for_the_withdrawn_subject(self) -> None:
        inclusion = archival.inclusion_lookup(ARCHIVE, SUBJECT)
        self.assertEqual(inclusion["code"], archival.CODE_OK)
        self.assertTrue(inclusion["verified"])
        self.assertEqual(inclusion["leafIndex"], 1)

    def test_the_state_is_withdrawn_at_the_same_moment(self) -> None:
        self.assertEqual(
            archival.current(self.current, SUBJECT)["state"],
            archival.STATE_WITHDRAWN,
        )

    def test_the_present_tense_use_is_refused_and_names_the_event(self) -> None:
        with self.assertRaises(archival.Refusal) as caught:
            archival.present_tense(self.current, SUBJECT)
        self.assertEqual(
            caught.exception.code, archival.RV_REFUSED_WITHDRAWN_ACCEPTED
        )
        self.assertIn("A19-E22", caught.exception.message)

    def test_an_unknown_subject_is_refused(self) -> None:
        with self.assertRaises(archival.Refusal) as caught:
            archival.present_tense(self.current, "no/such/subject")
        self.assertEqual(caught.exception.code, archival.RV_REFUSED_SUBJECT_UNKNOWN)

    def test_the_three_facts_are_recorded_together(self) -> None:
        facts = _document(DEMONSTRATION)["facts"]
        self.assertEqual(facts["inclusionStillValid"]["code"], archival.CODE_OK)
        self.assertTrue(facts["inclusionStillValid"]["root"])
        self.assertEqual(
            facts["currentIsWithdrawn"]["state"], archival.STATE_WITHDRAWN
        )
        self.assertEqual(
            facts["presentTenseRefused"]["code"],
            archival.RV_REFUSED_WITHDRAWN_ACCEPTED,
        )

    def test_the_replay_is_recorded_with_both_refusals(self) -> None:
        replay = _document(DEMONSTRATION)["replay"]
        self.assertEqual(replay["earlierVersion"]["state"], archival.STATE_ACTIVE)
        self.assertEqual(
            replay["replayedAsCurrent"]["code"],
            archival.RV_REFUSED_REPLAY_AS_CURRENT,
        )
        self.assertEqual(
            replay["versionDecrease"]["code"], archival.RV_REFUSED_ROLLBACK_OF_STATE
        )

    def test_the_discarded_proof_loses_inclusion_not_the_withdrawal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b6-proof-") as temporary:
            archive = _copy_archive(Path(temporary))
            (archive / "members/log/inclusion-proof.json").unlink()
            with self.assertRaises(archival.Refusal) as caught:
                archival.inclusion_lookup(archive, SUBJECT)
            self.assertEqual(
                caught.exception.code, archival.RV_REFUSED_INCLUSION_LOST
            )
            # The state is untouched by the discarded proof: the claim is still
            # withdrawn, and the withdrawal does not depend on the archive.
            self.assertEqual(
                archival.current(self.current, SUBJECT)["state"],
                archival.STATE_WITHDRAWN,
            )


class Determinism(unittest.TestCase):
    """Two builds write the same bytes, and the committed records are that build."""

    def test_building_twice_is_byte_identical(self) -> None:
        builder = _builder()
        with tempfile.TemporaryDirectory(prefix="b6-determinism-") as temporary:
            one = Path(temporary) / "one"
            two = Path(temporary) / "two"
            builder.build(REPO_ROOT, one)
            builder.build(REPO_ROOT, two)
            files_one = {
                str(path.relative_to(one)): path.read_bytes()
                for path in sorted(one.rglob("*"))
                if path.is_file()
            }
            files_two = {
                str(path.relative_to(two)): path.read_bytes()
                for path in sorted(two.rglob("*"))
                if path.is_file()
            }
            self.assertEqual(sorted(files_one), sorted(files_two))
            for name in files_one:
                self.assertEqual(files_one[name], files_two[name], name)

    def test_the_committed_records_are_the_build(self) -> None:
        builder = _builder()
        with tempfile.TemporaryDirectory(prefix="b6-rebuild-") as temporary:
            rebuilt = Path(temporary) / "b6"
            builder.build(REPO_ROOT, rebuilt)
            for name in (
                "ARCHIVE.json",
                "CURRENT-STATE.json",
                "DEMONSTRATION.json",
                "CONTROLS.json",
                "FIXTURE-2.json",
            ):
                self.assertEqual(
                    (EVIDENCE / name).read_bytes(),
                    (rebuilt / name).read_bytes(),
                    name,
                )
            for path in sorted(rebuilt.joinpath("ARCHIVE").rglob("*")):
                if path.is_file():
                    relative = path.relative_to(rebuilt)
                    self.assertEqual(
                        (EVIDENCE / relative).read_bytes(), path.read_bytes(), str(relative)
                    )

    def test_the_producer_check_exits_zero(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-B", str(PRODUCER), "--check"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("code=RV_OK", completed.stdout)


class CommandLine(unittest.TestCase):
    """Exit 0 for RV_OK, 1 for a refusal, 2 for a usage error; codes are printed."""

    def run_tool(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(TOOL), *arguments],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def test_current(self) -> None:
        completed = self.run_tool("current")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("code=RV_OK version=22", completed.stdout)
        self.assertIn("withdrawn=5", completed.stdout)

    def test_current_for_the_subject(self) -> None:
        completed = self.run_tool("current", "--subject", SUBJECT)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("subjectState=WITHDRAWN", completed.stdout)
        self.assertIn("supersededBy=A19-E22", completed.stdout)

    def test_inclusion(self) -> None:
        completed = self.run_tool("inclusion")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("code=RV_OK", completed.stdout)
        self.assertIn("leafIndex=1", completed.stdout)
        self.assertIn("verified=True", completed.stdout)

    def test_reconstruct(self) -> None:
        completed = self.run_tool("reconstruct")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("code=RV_OK", completed.stdout)
        self.assertIn("checks=9", completed.stdout)

    def test_use_is_refused(self) -> None:
        completed = self.run_tool("use", "--subject", SUBJECT)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("code=RV_REFUSED_WITHDRAWN_ACCEPTED", completed.stdout)

    def test_admit_refuses_the_replay(self) -> None:
        completed = self.run_tool(
            "admit",
            "--candidate",
            str(EARLIER_MEMBER),
            "--accepted",
            str(CURRENT_STATE),
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("code=RV_REFUSED_REPLAY_AS_CURRENT", completed.stdout)

    def test_compare_refuses_the_decrease(self) -> None:
        completed = self.run_tool(
            "compare",
            "--previous",
            str(CURRENT_STATE),
            "--next",
            str(EARLIER_MEMBER),
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("code=RV_REFUSED_ROLLBACK_OF_STATE", completed.stdout)

    def test_derive(self) -> None:
        completed = self.run_tool("derive", "--upto", "21")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("code=RV_OK version=21", completed.stdout)
        self.assertIn("active=1", completed.stdout)

    def test_an_unreadable_state_is_an_io_refusal(self) -> None:
        completed = self.run_tool(
            "current", "--state", str(EVIDENCE / "CONTROL-ONLY/absent.json")
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("code=RV_REFUSED_IO", completed.stdout)

    def test_a_missing_command_is_a_usage_error(self) -> None:
        completed = self.run_tool("no-such-command")
        self.assertEqual(completed.returncode, 2)


class DocumentSynchronisation(unittest.TestCase):
    """The normative document and the queue row stay in step with the tool."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8")

    def test_every_code_is_documented(self) -> None:
        for code in archival.ALL_CODES:
            self.assertIn(code, self.text, code)

    def test_the_refusal_table_has_one_row_per_code(self) -> None:
        rows = {
            line.split("`")[1]
            for line in self.text.splitlines()
            if line.startswith("| `RV_")
        }
        self.assertEqual(rows, set(archival.ALL_CODES))

    def test_every_control_is_named(self) -> None:
        controls = _document(CONTROLS)["controls"]
        for row in controls:
            self.assertIn(row["name"], self.text, row["name"])

    def test_the_three_facts_and_the_replay_are_described(self) -> None:
        for phrase in (
            "inclusion proof remains valid",
            "present-tense",
            "replayed",
            "version may not decrease",
        ):
            self.assertIn(phrase, self.text, phrase)

    def test_the_document_names_its_non_claims(self) -> None:
        self.assertIn("## 8. Non-claims", self.text)
        for phrase in (
            "An archive is not an independent copy",
            "A fixture log is not a public log",
            "A withdrawal does not make the original untrue; it makes it not current",
        ):
            self.assertIn(phrase, self.text, phrase)

    def test_the_queue_row_is_at_this_base(self) -> None:
        row = next(
            line
            for line in QUEUE.read_text(encoding="utf-8").splitlines()
            if line.startswith("| B6 |")
        )
        self.assertIn("base `19b710192`", row)
        self.assertTrue("`DONE`" in row or "`PARTIAL`" in row, row)


if __name__ == "__main__":
    unittest.main()
