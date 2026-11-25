#!/usr/bin/env python3
"""Controls for forensics/tools/sigstore_bundle.py and the A16 records.

One control per refusal code; the certificate-window boundary at each edge and
one second outside it; the payload-digest binding; a wrong tlog kind; an
inclusion proof absent, present-but-unverified and present-and-accepted under a
stub; that no verifier yields ``BUNDLE_UNVERIFIABLE_OFFLINE`` and never
``BUNDLE_VERIFIED_OFFLINE``; the structural no-network/no-client rule; the
deterministic producer; the command line; and document synchronisation.

Run directly (`python3 forensics/tools/tests/test_sigstore_bundle.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics/tools"
sys.path.insert(0, str(TOOLS))

import sigstore_bundle as sb  # noqa: E402
import harden as h  # noqa: E402

EVIDENCE = REPO / "evidence/a16"
BUILDER_PATH = EVIDENCE / "build_evidence.py"
INVENTORY = EVIDENCE / "INVENTORY.json"
TOOL = TOOLS / "sigstore_bundle.py"
DOCUMENT = REPO / "docs/SIGSTORE-BUNDLES.md"
# The current records are still frozen at b26552e21.  The next batch regenerates
# them from the commit that carries the candidate-blob generator and must set
# these two constants to that commit's full and nine-character hashes: the new
# records declare ``baseCommit == frozenAtCandidate == that commit`` and every
# member digest is read from its tree.
FULL_COMMIT = "b26552e21a7465405ad542edeaef7b9104c0298d"
SHORT_COMMIT = "b26552e21"
POPULATION_SELF = "evidence/a16/INVENTORY.json"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_builder() -> Any:
    spec = importlib.util.spec_from_file_location("a16_builder", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def committed_blob(commit: str, relative: str) -> bytes:
    result = subprocess.run(
        [
            "git",
            "-c",
            "safe.directory=*",
            "-C",
            str(REPO),
            "cat-file",
            "blob",
            f"{commit}:{relative}",
        ],
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def fresh_module() -> Any:
    return load_builder()


class StructuralNoNetwork(unittest.TestCase):
    """A8's structural rule: the validator imports no client and shells out to none."""

    def test_the_module_imports_no_network_or_process_module(self) -> None:
        tree = ast.parse(TOOL.read_text(encoding="utf-8"))
        roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                roots.add((node.module or "").split(".")[0])
        self.assertEqual(roots & sb.FORBIDDEN_MODULES, set())

    def test_the_module_source_has_no_findings(self) -> None:
        self.assertEqual(sb.network_or_client_findings(sb.module_source()), [])

    def test_a_network_import_is_refused_structurally(self) -> None:
        findings = sb.network_or_client_findings("import socket\n")
        self.assertTrue(findings)
        self.assertEqual(
            {finding["code"] for finding in findings},
            {sb.SB_REFUSED_NETWORK_OR_CLIENT},
        )
        self.assertIn("socket", {finding["detail"] for finding in findings})

    def test_a_sigstore_client_invocation_is_refused_structurally(self) -> None:
        source = "import subprocess\nsubprocess.run(['cosign', 'verify'])\n"
        findings = sb.network_or_client_findings(source)
        kinds = {finding["kind"] for finding in findings}
        self.assertIn("import", kinds)
        self.assertIn("client", kinds)
        self.assertEqual(
            {finding["code"] for finding in findings},
            {sb.SB_REFUSED_NETWORK_OR_CLIENT},
        )

    def test_a_shell_call_is_refused_structurally(self) -> None:
        findings = sb.network_or_client_findings("import os\nos.system('rekor-cli log')\n")
        self.assertIn(
            "shell", {finding["kind"] for finding in findings}
        )


class ControlsRecord(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.record = load_json(EVIDENCE / "CONTROLS.json")

    def test_every_control_is_control_only(self) -> None:
        self.assertTrue(self.record["note"].startswith("Every fixture is control-only"))
        for control in self.record["controls"]:
            self.assertTrue(control["controlOnly"], control["id"])
        self.assertTrue(self.record["positive"]["controlOnly"])
        for boundary in self.record["boundaries"]:
            self.assertTrue(boundary["controlOnly"], boundary["id"])

    def test_every_refusal_code_has_a_control(self) -> None:
        codes = {control["code"] for control in self.record["controls"]}
        self.assertEqual(codes, set(sb.REFUSALS))
        self.assertEqual(len(codes), len(sb.CODE_ORDER))

    def test_every_control_observed_its_expected_code(self) -> None:
        for control in self.record["controls"]:
            observed = control["observed"]
            self.assertIn(control["code"], observed["codes"], control["id"])
            if "outcome" not in observed:
                continue
            statuses = {
                check["code"]: check["status"]
                for check in observed.get("checks", [])
                if check["code"] == control["code"]
            }
            if observed["outcome"] == sb.OUTCOME_INVALID:
                self.assertIn("fail", statuses.values(), control["id"])
            elif observed["outcome"] == sb.OUTCOME_UNVERIFIABLE:
                self.assertIn("not-run", statuses.values(), control["id"])

    def test_the_positive_control_reaches_verified(self) -> None:
        positive = self.record["positive"]
        self.assertEqual(positive["observed"]["outcome"], sb.OUTCOME_VERIFIED)
        self.assertEqual(positive["observed"]["codes"], [])
        self.assertTrue(
            all(check["status"] == "pass" for check in positive["observed"]["checks"])
        )

    def test_the_boundary_cases_are_exact(self) -> None:
        boundaries = {case["id"]: case for case in self.record["boundaries"]}
        self.assertEqual(len(boundaries), 4)
        for edge in ("at-not-before", "at-not-after"):
            self.assertEqual(boundaries[edge]["observed"]["outcome"], sb.OUTCOME_VERIFIED)
        for outside in (
            "one-second-before-not-before",
            "one-second-after-not-after",
        ):
            case = boundaries[outside]
            self.assertEqual(case["observed"]["outcome"], sb.OUTCOME_INVALID)
            self.assertIn(sb.SB_REFUSED_EXPIRED_CERT, case["observed"]["codes"])

    def test_the_real_inventory_is_zero(self) -> None:
        inventory = load_json(EVIDENCE / "INVENTORY.json")
        self.assertEqual(inventory["bundles"], 0)
        self.assertEqual(inventory["transparencyLogs"], 0)
        self.assertEqual(inventory["certificates"], 0)
        self.assertEqual(inventory["a10Envelopes"], 4)
        self.assertIn("not Sigstore bundles", inventory["a10EnvelopeNote"])


class ValidatorBehaviour(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = load_builder()

    def run_base(self, **options: Any) -> dict[str, Any]:
        verifiers = dict(self.builder.ALL_ACCEPT)
        verifiers.update(options.pop("verifiers", {}))
        for name in options.pop("absent", ()):
            verifiers.pop(name, None)
        return sb.validate_bundle(
            self.builder.encode(self.builder.base_document()),
            options.pop("artefact", self.builder.PAYLOAD),
            policy=options.pop("policy", self.builder.POLICY),
            **verifiers,
            **options,
        )

    def test_the_base_bundle_verifies_under_stub_verifiers(self) -> None:
        report = self.run_base()
        self.assertEqual(report["outcome"], sb.OUTCOME_VERIFIED)
        self.assertEqual(report["codes"], [])
        self.assertTrue(report["certificate"]["issuer"] == self.builder.EXPECTED_ISSUER)
        self.assertEqual(
            report["certificate"]["identities"],
            [{"type": "dns", "value": self.builder.EXPECTED_IDENTITY}],
        )

    def test_the_window_is_inclusive_at_both_edges(self) -> None:
        for integrated in (
            self.builder._epoch(self.builder.NOT_BEFORE),
            self.builder._epoch(self.builder.NOT_AFTER),
        ):
            document = self.builder.base_document()
            document["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = (
                integrated
            )
            report = sb.validate_bundle(
                self.builder.encode(document),
                self.builder.PAYLOAD,
                policy=self.builder.POLICY,
                **self.builder.ALL_ACCEPT,
            )
            self.assertEqual(report["outcome"], sb.OUTCOME_VERIFIED, integrated)

    def test_one_second_outside_the_window_is_refused(self) -> None:
        for integrated in (
            self.builder._epoch(self.builder.NOT_BEFORE) - 1,
            self.builder._epoch(self.builder.NOT_AFTER) + 1,
        ):
            document = self.builder.base_document()
            document["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = (
                integrated
            )
            report = sb.validate_bundle(
                self.builder.encode(document),
                self.builder.PAYLOAD,
                policy=self.builder.POLICY,
                **self.builder.ALL_ACCEPT,
            )
            self.assertEqual(report["outcome"], sb.OUTCOME_INVALID)
            self.assertEqual(report["codes"], [sb.SB_REFUSED_EXPIRED_CERT])

    def test_the_payload_digest_binds_the_artefact(self) -> None:
        report = self.run_base(artefact=self.builder.OTHER_ARTEFACT)
        self.assertEqual(report["outcome"], sb.OUTCOME_INVALID)
        self.assertEqual(report["codes"], [sb.SB_REFUSED_PAYLOAD_DIGEST])
        self.assertEqual(
            report["payloadSha256"], hashlib.sha256(self.builder.PAYLOAD).hexdigest()
        )

    def test_a_wrong_tlog_kind_is_refused(self) -> None:
        document = self.builder.base_document()
        document["verificationMaterial"]["tlogEntries"][0]["kindVersion"] = {
            "kind": "hashedrekord",
            "version": "0.0.1",
        }
        report = sb.validate_bundle(
            self.builder.encode(document),
            self.builder.PAYLOAD,
            policy=self.builder.POLICY,
            **self.builder.ALL_ACCEPT,
        )
        self.assertEqual(report["codes"], [sb.SB_REFUSED_TLOG_KIND])

    def test_inclusion_absent_present_unverifiable_and_verified(self) -> None:
        document = self.builder.base_document()
        document["verificationMaterial"]["tlogEntries"][0].pop("inclusionProof")
        absent = sb.validate_bundle(
            self.builder.encode(document),
            self.builder.PAYLOAD,
            policy=self.builder.POLICY,
            **self.builder.ALL_ACCEPT,
        )
        self.assertEqual(absent["outcome"], sb.OUTCOME_INVALID)
        self.assertEqual(absent["codes"], [sb.SB_REFUSED_INCLUSION_PROOF])

        rejecting = dict(self.builder.ALL_ACCEPT)
        rejecting["log_verify"] = self.builder._reject
        rejected = sb.validate_bundle(
            self.builder.encode(self.builder.base_document()),
            self.builder.PAYLOAD,
            policy=self.builder.POLICY,
            **rejecting,
        )
        self.assertEqual(rejected["outcome"], sb.OUTCOME_INVALID)
        self.assertEqual(rejected["codes"], [sb.SB_REFUSED_INCLUSION_PROOF])

        verified = self.run_base()
        self.assertEqual(verified["outcome"], sb.OUTCOME_VERIFIED)

    def test_no_log_verifier_is_unverifiable_and_never_verified(self) -> None:
        report = self.run_base(absent=("log_verify",))
        self.assertEqual(report["outcome"], sb.OUTCOME_UNVERIFIABLE)
        self.assertNotEqual(report["outcome"], sb.OUTCOME_VERIFIED)
        self.assertIn(sb.SB_REFUSED_LOG_KEY_ABSENT, report["codes"])

    def test_no_verifier_at_all_is_unverifiable_and_never_verified(self) -> None:
        report = sb.validate_bundle(
            self.builder.encode(self.builder.base_document()),
            self.builder.PAYLOAD,
            policy=self.builder.POLICY,
        )
        self.assertEqual(report["outcome"], sb.OUTCOME_UNVERIFIABLE)
        self.assertIn(sb.SB_REFUSED_CERT_ROOT_ABSENT, report["codes"])
        self.assertIn(sb.SB_REFUSED_SIGNATURE, report["codes"])
        self.assertIn(sb.SB_REFUSED_LOG_KEY_ABSENT, report["codes"])
        self.assertIn(sb.SB_REFUSED_TIMESTAMP_ROOT_ABSENT, report["codes"])

    def test_policy_absent_is_unverifiable(self) -> None:
        report = sb.validate_bundle(
            self.builder.encode(self.builder.base_document()),
            self.builder.PAYLOAD,
            policy=None,
            **self.builder.ALL_ACCEPT,
        )
        self.assertEqual(report["outcome"], sb.OUTCOME_UNVERIFIABLE)
        self.assertIn(sb.SB_REFUSED_POLICY_ABSENT, report["codes"])

    def test_a_duplicate_key_is_refused_by_the_strict_loader(self) -> None:
        raw = b'{"mediaType":"first",' + self.builder.encode(
            self.builder.base_document()
        )[1:]
        report = sb.validate_bundle(
            raw, self.builder.PAYLOAD, policy=self.builder.POLICY, **self.builder.ALL_ACCEPT
        )
        self.assertEqual(report["outcome"], sb.OUTCOME_INVALID)
        self.assertEqual(report["codes"], [sb.SB_REFUSED_DUPLICATE_KEY])

    def test_public_key_only_material_is_refused_for_this_profile(self) -> None:
        document = self.builder.base_document()
        material = document["verificationMaterial"]
        material.pop("x509CertificateChain")
        material["publicKey"] = {"rawBytes": self.builder._b64(b"\x01" * 32)}
        report = sb.validate_bundle(
            self.builder.encode(document),
            self.builder.PAYLOAD,
            policy=self.builder.POLICY,
            **self.builder.ALL_ACCEPT,
        )
        self.assertEqual(report["codes"], [sb.SB_REFUSED_MATERIAL])

    def test_a_malformed_certificate_is_refused(self) -> None:
        document = self.builder.base_document()
        document["verificationMaterial"]["x509CertificateChain"]["certificates"] = [
            {"rawBytes": self.builder._b64(b"\x30\x03\x02\x01")}
        ]
        report = sb.validate_bundle(
            self.builder.encode(document),
            self.builder.PAYLOAD,
            policy=self.builder.POLICY,
            **self.builder.ALL_ACCEPT,
        )
        self.assertEqual(report["codes"], [sb.SB_REFUSED_CERT_CHAIN])

    def test_an_absent_path_is_not_run(self) -> None:
        report = sb.validate_paths(
            REPO / "control-only/absent.sigstore.json",
            REPO / "control-only/absent.artefact",
        )
        self.assertEqual(report["outcome"], sb.OUTCOME_NOT_RUN)
        self.assertEqual(report["codes"], [sb.SB_REFUSED_INPUT_ABSENT])

    def test_the_certificate_parser_extracts_the_claimed_fields(self) -> None:
        info = sb.parse_certificate(self.builder.certificate())
        self.assertEqual(info["issuer"], self.builder.EXPECTED_ISSUER)
        self.assertEqual(info["notBefore"], "2026-01-01T00:00:00Z")
        self.assertEqual(info["notAfter"], "2026-12-31T00:00:00Z")
        self.assertEqual(
            info["identities"], [{"type": "dns", "value": self.builder.EXPECTED_IDENTITY}]
        )


class CommandLine(unittest.TestCase):
    def run_tool(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            capture_output=True,
            text=True,
            cwd=REPO,
            env={"PYTHONDONTWRITEBYTECODE": "1"},
        )

    def test_profile_prints_the_profile(self) -> None:
        result = self.run_tool("profile")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("profile: code=SB_OK", result.stdout)
        self.assertIn(sb.MEDIA_TYPE_V03, result.stdout)

    def test_inventory_prints_zero_and_not_run(self) -> None:
        result = self.run_tool("inventory")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bundles=0", result.stdout)
        self.assertIn("transparencyLogs=0", result.stdout)
        self.assertIn("certificates=0", result.stdout)
        self.assertIn(f"outcome={sb.OUTCOME_NOT_RUN}", result.stdout)

    def test_validate_without_a_log_key_is_unverifiable(self) -> None:
        builder = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "control.sigstore.json"
            artefact = root / "control.artefact"
            bundle.write_bytes(builder.encode(builder.base_document()))
            artefact.write_bytes(builder.PAYLOAD)
            result = self.run_tool(
                "validate",
                str(bundle),
                str(artefact),
                "--issuer",
                builder.EXPECTED_ISSUER,
                "--identity",
                builder.EXPECTED_IDENTITY,
                "--identity-type",
                "dns",
            )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"outcome={sb.OUTCOME_UNVERIFIABLE}", result.stdout)
        self.assertIn(sb.SB_REFUSED_CERT_ROOT_ABSENT, result.stdout)
        self.assertIn(sb.SB_REFUSED_LOG_KEY_ABSENT, result.stdout)
        self.assertNotIn(f"outcome={sb.OUTCOME_VERIFIED}", result.stdout)

    def test_validate_refuses_an_absent_input_with_not_run(self) -> None:
        result = self.run_tool(
            "validate", "control-only/absent.json", "control-only/absent.artefact"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(sb.SB_REFUSED_INPUT_ABSENT, result.stdout)
        self.assertIn(f"outcome={sb.OUTCOME_NOT_RUN}", result.stdout)

    def test_usage_errors_exit_two(self) -> None:
        self.assertEqual(self.run_tool().returncode, 2)
        self.assertEqual(self.run_tool("not-a-command").returncode, 2)


class DeterminismAndRecords(unittest.TestCase):
    def test_the_producer_is_deterministic_in_process(self) -> None:
        first = load_builder()
        second = load_builder()
        left = first.build(FULL_COMMIT)
        right = second.build(FULL_COMMIT)
        for name in ("INVENTORY.json", "PROFILE.json", "CONTROLS.json"):
            self.assertEqual(first._dump(left[name]), second._dump(right[name]), name)

    def test_two_runs_are_byte_identical_and_match_committed(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for out in (first, second):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(BUILDER_PATH),
                        "--out",
                        out,
                        "--source-commit",
                        FULL_COMMIT,
                    ],
                    capture_output=True,
                    text=True,
                    cwd=REPO,
                    env={"PYTHONDONTWRITEBYTECODE": "1"},
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("INVENTORY.json", "PROFILE.json", "CONTROLS.json"):
                left = (Path(first) / name).read_bytes()
                right = (Path(second) / name).read_bytes()
                committed = (EVIDENCE / name).read_bytes()
                self.assertEqual(left, right, f"two runs differ: {name}")
                self.assertEqual(left, committed, f"committed differs: {name}")

    def test_every_record_parses_and_is_bound(self) -> None:
        schemas = {
            "INVENTORY.json": sb.INVENTORY_SCHEMA,
            "PROFILE.json": sb.PROFILE_SCHEMA,
            "CONTROLS.json": sb.CONTROLS_SCHEMA,
        }
        for name, schema in schemas.items():
            document = load_json(EVIDENCE / name)
            self.assertEqual(document["schema"], schema, name)
            self.assertEqual(document["sourceIdentity"]["baseCommit"], FULL_COMMIT, name)
            self.assertEqual(
                document["sourceIdentity"]["baseCommitShort"], SHORT_COMMIT, name
            )
            self.assertEqual(
                document["sourceIdentity"]["tool"]["sha256"],
                hashlib.sha256(
                    committed_blob(FULL_COMMIT, "forensics/tools/sigstore_bundle.py")
                ).hexdigest(),
                name,
            )

    def test_the_source_identity_reads_the_candidate_tool(self) -> None:
        builder = load_builder()
        identity = builder.source_identity(FULL_COMMIT)
        self.assertEqual(identity["baseCommit"], FULL_COMMIT)
        self.assertEqual(
            identity["tool"]["sha256"],
            hashlib.sha256(
                committed_blob(FULL_COMMIT, "forensics/tools/sigstore_bundle.py")
            ).hexdigest(),
        )
        for entry in identity["delegatedTools"]:
            self.assertEqual(
                entry["sha256"],
                hashlib.sha256(committed_blob(FULL_COMMIT, entry["path"])).hexdigest(),
                entry["path"],
            )

    def test_the_superseded_freeze_is_preserved(self) -> None:
        builder = load_builder()
        prior = {
            "population": {
                "frozenAtCandidate": "a" * 40,
                "files": 2,
                "members": [
                    {"path": "evidence/ONE.json"},
                    {"path": "evidence/a16/PROFILE.json"},
                ],
            }
        }
        entries = builder._superseded_entries(
            prior, FULL_COMMIT, FULL_COMMIT, ["evidence/ONE.json"]
        )
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["frozenAtCandidate"], "a" * 40)
        self.assertEqual(entries[0]["memberCount"], 2)
        self.assertIn("evidence/a16/PROFILE.json", entries[0]["reason"])
        self.assertEqual(
            {row["path"] for row in entries[0]["recordDigests"]},
            set(builder.RECORD_PATHS),
        )
        # Repeating the same freeze at the same candidate preserves no duplicate.
        same = {
            "population": {
                "frozenAtCandidate": FULL_COMMIT,
                "files": 1,
                "members": [{"path": "evidence/ONE.json"}],
            }
        }
        self.assertEqual(
            builder._superseded_entries(
                same, FULL_COMMIT, FULL_COMMIT, ["evidence/ONE.json"]
            ),
            [],
        )

    def test_the_profile_record_matches_the_tool(self) -> None:
        record = load_json(EVIDENCE / "PROFILE.json")
        self.assertEqual(record["profile"], sb.bundle_profile())


class FrozenPopulation(unittest.TestCase):
    """The population is a declared member list, not a live count.

    A17's six new records once made the live ``evidence/**/*.json`` count 413
    while the committed record said 407, so the record no longer reproduced.  The
    population is the tracked evidence JSON at the declared candidate, bound to a
    digest per member, less the item's own inventory record and a **declared,
    closed exclusion** (the three A11 records, which digest this item's records
    and so cannot be digested back).  The exclusion is recorded with its reason
    and reported as ``NEW_SINCE_RECORD``; it is never absorbed into the count and
    cannot be widened.  Later files are ``NEW_SINCE_RECORD`` too.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.record = load_json(INVENTORY)
        cls.population = cls.record["population"]
        cls.members = cls.population["members"]
        cls.certificates = cls.record["certificatePopulation"]["members"]

    def test_the_population_is_bound_to_a_declared_candidate(self) -> None:
        self.assertEqual(self.population["binding"], h.POPULATION_FROZEN)
        self.assertEqual(self.population["frozenAtCandidate"], FULL_COMMIT)
        self.assertEqual(self.population["files"], len(self.members))
        self.assertEqual(self.record["populationFiles"], len(self.members))
        self.assertEqual(
            self.record["certificatePopulation"]["binding"], h.POPULATION_FROZEN
        )
        self.assertEqual(self.record["certificateFiles"], len(self.certificates))

    def test_every_member_is_an_explicit_path_and_digest(self) -> None:
        paths = [member["path"] for member in self.members]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(len(set(paths)), len(paths))
        for member in self.members:
            self.assertRegex(member["sha256"], r"^[0-9a-f]{64}$")
            self.assertIsInstance(member["bytes"], int)
        self.assertNotIn(POPULATION_SELF, paths)

    def test_the_frozen_population_reproduces_at_this_tree(self) -> None:
        current = sb.verify_population(self.members)
        self.assertEqual(
            [(row["path"], row["sha256"]) for row in current],
            [(member["path"], member["sha256"]) for member in self.members],
        )

    def test_the_frozen_population_is_the_candidate_population(self) -> None:
        builder = load_builder()
        paths, certificate_paths = builder.candidate_population(FULL_COMMIT)
        self.assertEqual([member["path"] for member in self.members], paths)
        self.assertEqual(sb.freeze_population(paths), self.members)
        self.assertEqual(
            [member["path"] for member in self.certificates], certificate_paths
        )
        # The cut is declared, closed and exactly the three A11 records.
        excluded = self.population["excluded"]
        self.assertEqual(
            excluded["paths"],
            [
                "evidence/a11/CONTROLS.json",
                "evidence/a11/DIFFERENTIAL.json",
                "evidence/a11/SCAN.json",
            ],
        )
        self.assertEqual(excluded["paths"], list(sb.POPULATION_EXCLUDED_PATHS))
        self.assertEqual(excluded["result"], h.RESULT_NEW_SINCE_RECORD)
        self.assertIn("mutual digest binding", excluded["reason"])

    def test_the_declared_exclusion_is_reported_not_absorbed(self) -> None:
        member_paths = {member["path"] for member in self.members}
        growth = {
            entry["path"]: entry
            for entry in sb.growth_report(self.members, self.certificates)
        }
        for path in sb.POPULATION_EXCLUDED_PATHS:
            with self.subTest(path=path):
                self.assertNotIn(path, member_paths)
                self.assertIn(path, growth)
                self.assertEqual(growth[path]["result"], h.RESULT_NEW_SINCE_RECORD)
                self.assertRegex(growth[path]["sha256"], r"^[0-9a-f]{64}$")
        # Nothing else is excluded: the growth report carries every glob match
        # that is not a member, and the frozen count does not include any of them.
        self.assertEqual(self.record["populationFiles"], len(self.members))

    def test_an_excluded_path_cannot_be_frozen_back_in(self) -> None:
        for path in sb.POPULATION_EXCLUDED_PATHS:
            with self.subTest(path=path):
                with self.assertRaises(h.Refusal) as caught:
                    sb.freeze_population([path])
                self.assertEqual(
                    caught.exception.code, h.PH_REFUSED_POPULATION_DRIFT
                )

    def test_readmitting_this_items_profile_record_is_refused_by_identity(self) -> None:
        builder = load_builder()
        paths, _ = builder.candidate_population(FULL_COMMIT)
        self.assertNotIn("evidence/a16/PROFILE.json", paths)
        self.assertNotIn("evidence/a16/CONTROLS.json", paths)
        self.assertNotIn(POPULATION_SELF, paths)
        with self.assertRaises(h.Refusal) as caught:
            sb.freeze_population(list(paths) + ["evidence/a16/PROFILE.json"])
        self.assertEqual(caught.exception.code, h.PH_REFUSED_POPULATION_DRIFT)
        self.assertIn("evidence/a16/PROFILE.json", caught.exception.message)

        # A record that re-admits the record as a member is unsatisfiable: it is
        # refused by the record gate, naming the re-admitted path.
        record = dict(self.record)
        population = dict(record["population"])
        members = [dict(member) for member in population["members"]]
        profile = next(
            member
            for member in self.members
            if member["path"] == "evidence/a16/PROFILE.json"
        )
        members.append(dict(profile))
        population["members"] = members
        population["files"] = len(members)
        record["population"] = population
        record["populationFiles"] = len(members)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "INVENTORY.json"
            path.write_bytes(json.dumps(record, sort_keys=True).encode("utf-8"))
            with self.assertRaises(h.Refusal) as caught:
                sb.declared_population(path)
        self.assertEqual(caught.exception.code, h.PH_REFUSED_POPULATION_DRIFT)
        self.assertIn("evidence/a16/PROFILE.json", caught.exception.message)

    def test_the_record_declares_the_identity_exclusion_separately(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mirror = Path(directory)
            (mirror / "evidence").mkdir()
            (mirror / "evidence/ONE.json").write_bytes(b'{"a": 1}\n')
            members = sb.freeze_population(["evidence/ONE.json"], repo_root=mirror)
            record = sb.inventory(
                members, (), frozen_at_candidate="control-only", repo_root=mirror
            )
        self.assertEqual(
            record["population"]["identityExcluded"]["paths"],
            list(sb.POPULATION_IDENTITY_EXCLUDED),
        )
        self.assertEqual(
            record["population"]["excluded"]["paths"],
            list(sb.POPULATION_EXCLUDED_PATHS),
        )

    def test_a_record_that_drops_the_exclusion_is_refused(self) -> None:
        population = dict(self.population)
        population.pop("excluded", None)
        drifted = dict(self.record)
        drifted["population"] = population
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / "INVENTORY.json"
            record.write_bytes(json.dumps(drifted).encode("utf-8"))
            with self.assertRaises(h.Refusal) as caught:
                sb.declared_population(record)
        self.assertEqual(caught.exception.code, h.PH_REFUSED_POPULATION_DRIFT)
        self.assertIn("exclusion", caught.exception.message)

    def test_growth_is_reported_and_never_absorbed(self) -> None:
        growth = sb.growth_report(self.members, self.certificates)
        member_paths = {member["path"] for member in self.members}
        self.assertTrue(growth, "the tree has grown since the candidate")
        for entry in growth:
            self.assertNotIn(entry["path"], member_paths)
            self.assertEqual(entry["result"], h.RESULT_NEW_SINCE_RECORD)
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(self.record["populationFiles"], len(self.members))

    def test_a_new_bundle_after_the_freeze_is_new_since_record(self) -> None:
        builder = load_builder()
        with tempfile.TemporaryDirectory() as directory:
            mirror = Path(directory) / "mirror"
            (mirror / "evidence").mkdir(parents=True)
            (mirror / "evidence/OLD.json").write_bytes(b'{"a": 1}\n')
            bundle_path = "evidence/NEW.sigstore.json"
            bundle_bytes = builder.encode(builder.base_document())
            (mirror / bundle_path).write_bytes(bundle_bytes)
            members = sb.freeze_population(["evidence/OLD.json"], repo_root=mirror)
            live = ["evidence/OLD.json", bundle_path]
            frozen_record = sb.inventory(
                members, (), frozen_at_candidate="control-only", repo_root=mirror
            )
            self.assertEqual(frozen_record["bundles"], 0)
            self.assertEqual(frozen_record["populationFiles"], 1)
            growth = sb.growth_report(
                members, (), repo_root=mirror, live_paths=live
            )
            self.assertEqual([entry["path"] for entry in growth], [bundle_path])
            entry = growth[0]
            self.assertEqual(entry["result"], h.RESULT_NEW_SINCE_RECORD)
            self.assertEqual(
                entry["sha256"], hashlib.sha256(bundle_bytes).hexdigest()
            )
            refrozen = sb.freeze_population(live, repo_root=mirror)
            refrozen_record = sb.inventory(
                refrozen, (), frozen_at_candidate="control-only", repo_root=mirror
            )
            self.assertEqual(refrozen_record["bundles"], 1)

    def test_a_changed_member_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mirror = Path(directory)
            (mirror / "evidence").mkdir()
            member = mirror / "evidence/ONE.json"
            member.write_bytes(b'{"a": 1}\n')
            members = sb.freeze_population(["evidence/ONE.json"], repo_root=mirror)
            member.write_bytes(b'{"a": 2}\n')
            with self.assertRaises(h.Refusal) as caught:
                sb.verify_population(members, repo_root=mirror)
            self.assertEqual(caught.exception.code, h.PH_REFUSED_POPULATION_DRIFT)

    def test_a_removed_member_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mirror = Path(directory)
            (mirror / "evidence").mkdir()
            (mirror / "evidence/ONE.json").write_bytes(b'{"a": 1}\n')
            members = sb.freeze_population(["evidence/ONE.json"], repo_root=mirror)
            (mirror / "evidence/ONE.json").unlink()
            with self.assertRaises(h.Refusal) as caught:
                sb.verify_population(members, repo_root=mirror)
            self.assertEqual(caught.exception.code, h.PH_REFUSED_POPULATION_DRIFT)

    def test_a_record_without_a_frozen_population_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / "INVENTORY.json"
            record.write_bytes(json.dumps({"populationFiles": 3}).encode("utf-8"))
            with self.assertRaises(h.Refusal) as caught:
                sb.declared_population(record)
            self.assertEqual(caught.exception.code, h.PH_REFUSED_POPULATION_DRIFT)
            self.assertIn("live glob", caught.exception.message)

    def test_the_producer_refuses_to_invent_a_population_from_the_tree(self) -> None:
        builder = load_builder()
        with tempfile.TemporaryDirectory() as directory:
            original = builder.A16
            builder.A16 = Path(directory)
            try:
                with self.assertRaises(SystemExit) as caught:
                    builder._declared_population(None, FULL_COMMIT)
            finally:
                builder.A16 = original
            self.assertIn("live glob", str(caught.exception))

    def test_the_inventory_command_reports_growth_separately(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "inventory"],
            capture_output=True,
            text=True,
            cwd=REPO,
            env={"PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bundles=0", result.stdout)
        self.assertIn(
            f"population={self.record['populationFiles']} files", result.stdout
        )
        self.assertIn(h.RESULT_NEW_SINCE_RECORD, result.stderr)
        self.assertIn(
            f"files={self.record['populationFiles']}", result.stderr
        )


class DocumentSynchronisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8")

    def test_every_refusal_code_is_documented(self) -> None:
        for code in sb.CODE_ORDER:
            self.assertIn(code, self.text, code)

    def test_every_enforced_by_names_a_code_or_test(self) -> None:
        markers = (
            "SB_REFUSED_",
            "test_",
            "`sigstore_bundle.py`",
            "`build_evidence.py`",
            "`docs/SIGSTORE-BUNDLES.md`",
        )
        for line in self.text.splitlines():
            if "Enforced by" in line:
                self.assertTrue(
                    any(marker in line for marker in markers),
                    f"enforcement line names no code or test: {line!r}",
                )

    def test_the_document_states_the_real_inventory(self) -> None:
        self.assertIn("0 Sigstore bundles", self.text)
        self.assertIn("0 transparency logs", self.text)
        self.assertIn("0 certificates", self.text)
        self.assertIn("self-issued DSSE", self.text)

    def test_the_document_states_the_assumptions_and_non_claims(self) -> None:
        self.assertIn("not in the bundle", self.text)
        self.assertIn("BUNDLE_VERIFIED_OFFLINE", self.text)
        self.assertIn("does not mean", self.text)
        self.assertIn("no network", self.text)

    def test_the_document_has_a_not_run_section(self) -> None:
        self.assertIn("## `NOT_RUN`", self.text)

    def test_the_document_states_the_frozen_population_contract(self) -> None:
        self.assertIn("frozen member list", self.text)
        self.assertIn(h.RESULT_NEW_SINCE_RECORD, self.text)
        self.assertIn("re-freeze", self.text)
        self.assertIn("not a live glob", self.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
