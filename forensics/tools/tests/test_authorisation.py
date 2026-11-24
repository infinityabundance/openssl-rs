#!/usr/bin/env python3
"""Controls for forensics/tools/authorisation.py and the A14 records.

One control per refusal code, every separation constraint individually
violated, the ordering rule (an unverified signature is refused before its role
is read), scope and validity, duplicate signers and party aliases, the real
records producing 0 authorised actions, the synthetic positive control, the
deterministic producer, the command line and document synchronisation.

Run directly (`python3 forensics/tools/tests/test_authorisation.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import authorisation as auth  # noqa: E402

EVIDENCE = REPO / "evidence/a14"
BUILDER = EVIDENCE / "build_evidence.py"
DOCUMENT = REPO / "docs/ROLE-AUTHORISATION.md"
FULL_COMMIT = "4e9262bf34e937439ec92bc832b5a569b27267b8"
AT = "2026-11-24"


def assignment(
    identity: str,
    role: str,
    party: str | None = None,
    scope: str = "*",
    granted_at: str = "2026-01-01",
    expires_at: str | None = None,
    revoked_at: str | None = None,
) -> dict:
    return {
        "identity": identity,
        "party": party or f"P-{identity}",
        "role": role,
        "scope": [scope],
        "grantedAt": granted_at,
        "grantedBy": {"identity": None, "role": None, "recorded": False},
        "revokedAt": revoked_at,
        "expiresAt": expires_at,
        "evidence": f"control-only:{identity}/{role}",
    }


def signature(
    identity: str, role: str, scope: str = "*", verified: bool = True
) -> dict:
    return {"identity": identity, "role": role, "scope": [scope], "verified": verified}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_builder():
    spec = importlib.util.spec_from_file_location("a14_build_evidence", BUILDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def codes(result: dict) -> list[str]:
    return list(result["codes"])


class RefusalCodes(unittest.TestCase):
    """One control per refusal code, from synthetic control-only identities."""

    def setUp(self) -> None:
        self.assignments = [
            assignment("control-only-alice", "adjudicator", "P-CONTROL-ALICE"),
            assignment("control-only-bob", "release_authority", "P-CONTROL-BOB"),
            assignment("control-only-producer", "producer", "P-CONTROL-PRODUCER"),
        ]
        self.claim = {
            "scope": ["claim:control"],
            "evidenceProducer": "control-only-producer",
            "roleIdentities": {"producer": "control-only-producer"},
        }
        self.release = {
            "scope": ["release:control"],
            "evidenceProducer": "control-only-producer",
            "roleIdentities": {"producer": "control-only-producer"},
        }

    def assertCode(self, result: dict, code: str) -> None:
        self.assertEqual(result["outcome"], "REFUSED", result)
        self.assertIn(code, codes(result), result)

    def test_role_unknown(self) -> None:
        result = auth.authorise(
            "claim-promotion", [signature("control-only-alice", "root")],
            self.assignments, at=AT, context=self.claim,
        )
        self.assertCode(result, "RA_REFUSED_ROLE_UNKNOWN")

    def test_role_not_assigned(self) -> None:
        result = auth.authorise(
            "claim-promotion",
            [signature("control-only-producer", "adjudicator")],
            self.assignments, at=AT, context=self.claim,
        )
        self.assertCode(result, "RA_REFUSED_ROLE_NOT_ASSIGNED")

    def test_wrong_role(self) -> None:
        # A valid producer signature for an action that requires a release
        # authority is the wrong role, not an invalid signature.
        result = auth.authorise(
            "release",
            [signature("control-only-producer", "producer", "release:control")],
            self.assignments, at=AT, context=self.release,
        )
        self.assertCode(result, "RA_REFUSED_WRONG_ROLE")

    def test_self_authorisation(self) -> None:
        assignments = self.assignments + [
            assignment("control-only-producer", "adjudicator", "P-CONTROL-PRODUCER"),
        ]
        result = auth.authorise(
            "claim-promotion",
            [signature("control-only-producer", "adjudicator")],
            assignments, at=AT, context=self.claim,
        )
        self.assertCode(result, "RA_REFUSED_SELF_AUTHORISATION")

    def test_separation(self) -> None:
        assignments = self.assignments + [
            assignment("control-only-producer", "instrument_reviewer",
                       "P-CONTROL-PRODUCER"),
        ]
        result = auth.authorise(
            "instrument-qualification",
            [signature("control-only-producer", "instrument_reviewer")],
            assignments, at=AT,
            context={"scope": ["instrument:control"],
                     "roleIdentities": {"producer": "control-only-producer"}},
        )
        self.assertCode(result, "RA_REFUSED_SEPARATION")

    def test_identity_unrecorded(self) -> None:
        result = auth.authorise(
            "claim-promotion",
            [signature("control-only-mallory", "adjudicator")],
            self.assignments, at=AT, context=self.claim,
        )
        self.assertCode(result, "RA_REFUSED_IDENTITY_UNRECORDED")

    def test_signature_unverified(self) -> None:
        # The role is deliberately unknown; the refusal must still be the
        # unverified signature, because an unverified signature is refused before
        # its role is read.
        result = auth.authorise(
            "claim-promotion",
            [signature("control-only-alice", "root", verified=False)],
            self.assignments, at=AT, context=self.claim,
        )
        self.assertCode(result, "RA_REFUSED_SIGNATURE_UNVERIFIED")
        self.assertNotIn("RA_REFUSED_ROLE_UNKNOWN", codes(result))

    def test_scope_exceeded(self) -> None:
        result = auth.authorise(
            "claim-promotion",
            [signature("control-only-alice", "adjudicator", "claim:other")],
            self.assignments, at=AT, context=self.claim,
        )
        self.assertCode(result, "RA_REFUSED_SCOPE_EXCEEDED")

    def test_assignment_scope_narrower_than_action(self) -> None:
        assignments = [
            assignment("control-only-alice", "adjudicator", "P-CONTROL-ALICE",
                       scope="claim:other"),
        ]
        result = auth.authorise(
            "claim-promotion",
            [signature("control-only-alice", "adjudicator", "claim:control")],
            assignments, at=AT, context=self.claim,
        )
        self.assertCode(result, "RA_REFUSED_SCOPE_EXCEEDED")

    def test_expired(self) -> None:
        assignments = [
            assignment("control-only-alice", "adjudicator", "P-CONTROL-ALICE",
                       expires_at="2026-01-01"),
        ]
        result = auth.authorise(
            "claim-promotion",
            [signature("control-only-alice", "adjudicator")],
            assignments, at="2026-06-01", context=self.claim,
        )
        self.assertCode(result, "RA_REFUSED_EXPIRED")

    def test_revoked(self) -> None:
        assignments = [
            assignment("control-only-alice", "adjudicator", "P-CONTROL-ALICE",
                       revoked_at="2026-02-01"),
        ]
        result = auth.authorise(
            "claim-promotion",
            [signature("control-only-alice", "adjudicator")],
            assignments, at="2026-06-01", context=self.claim,
        )
        self.assertCode(result, "RA_REFUSED_REVOKED")

    def test_not_yet_granted(self) -> None:
        assignments = [
            assignment("control-only-alice", "adjudicator", "P-CONTROL-ALICE",
                       granted_at="2026-12-01"),
        ]
        result = auth.authorise(
            "claim-promotion",
            [signature("control-only-alice", "adjudicator")],
            assignments, at="2026-06-01", context=self.claim,
        )
        self.assertCode(result, "RA_REFUSED_ROLE_NOT_ASSIGNED")

    def test_insufficient_signers(self) -> None:
        result = auth.authorise(
            "release",
            [signature("control-only-bob", "release_authority", "release:control")],
            self.assignments, at=AT, context=self.release,
        )
        self.assertCode(result, "RA_REFUSED_INSUFFICIENT_SIGNERS")

    def test_duplicate_signer(self) -> None:
        assignments = self.assignments + [
            assignment("control-only-alice", "release_authority", "P-CONTROL-ALICE"),
        ]
        result = auth.authorise(
            "release",
            [
                signature("control-only-alice", "release_authority", "release:control"),
                signature("control-only-alice", "adjudicator", "release:control"),
            ],
            assignments, at=AT, context=self.release,
        )
        self.assertCode(result, "RA_REFUSED_DUPLICATE_SIGNER")

    def test_action_unknown(self) -> None:
        result = auth.authorise(
            "launch", [signature("control-only-alice", "adjudicator")],
            self.assignments, at=AT,
        )
        self.assertCode(result, "RA_REFUSED_ACTION_UNKNOWN")

    def test_no_signature_set_is_not_run(self) -> None:
        result = auth.authorise(
            "claim-promotion", None, self.assignments, at=AT, context=self.claim
        )
        self.assertEqual(result["outcome"], "NOT_RUN")
        self.assertEqual(codes(result), [])

    def test_declared_not_run_policy(self) -> None:
        policy = {
            "release": dict(auth.ACTIONS["release"], status="NOT_RUN",
                            notRunReason="control-only: not attempted"),
        }
        result = auth.authorise(
            "release", [], self.assignments, policy=policy, at=AT,
            context=self.release,
        )
        self.assertEqual(result["outcome"], "NOT_RUN")

    def test_unknown_identity_is_not_a_role_label(self) -> None:
        # An assignment with no evidence establishes no identity.
        assignments = [
            {"identity": "control-only-ghost", "role": "adjudicator",
             "scope": ["*"], "grantedAt": "2026-01-01", "evidence": ""},
        ]
        result = auth.authorise(
            "claim-promotion",
            [signature("control-only-ghost", "adjudicator")],
            assignments, at=AT, context=self.claim,
        )
        self.assertCode(result, "RA_REFUSED_IDENTITY_UNRECORDED")


class SeparationConstraints(unittest.TestCase):
    """Every declared separation is individually violated and refused."""

    def test_every_constraint_is_individually_violated(self) -> None:
        cases = 0
        for action, rule in auth.ACTIONS.items():
            required = set(rule["requiredRoles"])
            for constraint in rule["separation"]:
                left, right = constraint["roles"]
                parties = f"P-CONTROL-SAME-{action}-{left}-{right}"
                assignments = []
                signatures = []
                identities: dict[str, str] = {}
                for role in (left, right):
                    if role == "producer":
                        identities[role] = "control-only-producer"
                    else:
                        identities[role] = f"control-only-{role}"
                for role, identity in identities.items():
                    if role == "producer":
                        continue
                    assignments.append(assignment(identity, role, parties))
                    signatures.append(
                        signature(identity, role, f"control:{action}")
                    )
                assignments.append(
                    assignment("control-only-producer", "producer", parties)
                )
                # Fill any other required role with a distinct party so the only
                # violation under test is the separation itself.
                for role in required - set(identities):
                    identity = f"control-only-other-{role}"
                    assignments.append(assignment(identity, role, f"P-OTHER-{role}"))
                    signatures.append(signature(identity, role, f"control:{action}"))
                context = {
                    "scope": [f"control:{action}"],
                    "evidenceProducer": "control-only-producer",
                    "roleIdentities": {"producer": "control-only-producer"},
                }
                result = auth.authorise(
                    action, signatures, assignments, at=AT, context=context
                )
                self.assertEqual(result["outcome"], "REFUSED", (action, constraint, result))
                self.assertIn("RA_REFUSED_SEPARATION", codes(result),
                              (action, constraint, result))
                self.assertTrue(
                    any(f"{left} and {right}" in line for line in result["detail"]),
                    (action, constraint, result["detail"]),
                )
                cases += 1
        self.assertGreaterEqual(cases, 8, "every action's separations must be exercised")

    def test_alias_parties_are_one_signer(self) -> None:
        assignments = [
            assignment("control-only-alias-a", "release_authority", "P-CONTROL-ONE"),
            assignment("control-only-alias-b", "adjudicator", "P-CONTROL-ONE"),
            assignment("control-only-author", "producer", "P-CONTROL-AUTHOR"),
        ]
        context = {
            "scope": ["release:control"],
            "evidenceProducer": "control-only-author",
            "roleIdentities": {"producer": "control-only-author"},
        }
        result = auth.authorise(
            "release",
            [
                signature("control-only-alias-a", "release_authority", "release:control"),
                signature("control-only-alias-b", "adjudicator", "release:control"),
            ],
            assignments, at=AT, context=context,
        )
        self.assertEqual(result["outcome"], "REFUSED")
        self.assertEqual(result["signers"], 1)
        self.assertIn("RA_REFUSED_INSUFFICIENT_SIGNERS", codes(result))
        self.assertIn("RA_REFUSED_SEPARATION", codes(result))


class PositiveControl(unittest.TestCase):
    def test_distinct_synthetic_identities_reach_authorised(self) -> None:
        assignments = [
            assignment("control-only-release", "release_authority", "P-CONTROL-RELEASE"),
            assignment("control-only-adjudicator", "adjudicator", "P-CONTROL-ADJUDICATOR"),
            assignment("control-only-author", "producer", "P-CONTROL-AUTHOR"),
        ]
        context = {
            "scope": ["release:control"],
            "evidenceProducer": "control-only-author",
            "roleIdentities": {"producer": "control-only-author"},
        }
        result = auth.authorise(
            "release",
            [
                signature("control-only-release", "release_authority", "release:control"),
                signature("control-only-adjudicator", "adjudicator", "release:control"),
            ],
            assignments, at=AT, context=context,
        )
        self.assertEqual(result["outcome"], "AUTHORISED", result)
        self.assertEqual(codes(result), [])
        self.assertEqual(result["signers"], 2)


class RealRecords(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.roles = load_json(EVIDENCE / "ROLES.json")
        cls.authorisation = load_json(EVIDENCE / "AUTHORISATION.json")
        cls.controls = load_json(EVIDENCE / "CONTROLS.json")

    def test_no_real_action_is_authorised(self) -> None:
        self.assertEqual(self.authorisation["aggregate"]["authorised"], 0)
        self.assertEqual(self.authorisation["aggregate"]["recordedAuthorised"], 0)
        self.assertEqual(self.authorisation["aggregate"]["faceValueAuthorised"], 0)
        self.assertEqual(self.authorisation["aggregate"]["actions"], 6)
        for name, entry in self.authorisation["actions"].items():
            self.assertNotEqual(entry["recorded"]["outcome"], "AUTHORISED", name)
            self.assertNotEqual(entry["faceValue"]["outcome"], "AUTHORISED", name)

    def test_real_recorded_attempts_are_unverified(self) -> None:
        for name, entry in self.authorisation["actions"].items():
            self.assertIn("RA_REFUSED_SIGNATURE_UNVERIFIED",
                          entry["recorded"]["codes"], name)
            for item in entry["recorded"]["signatures"]:
                self.assertFalse(item["verified"], (name, item))
            for item in entry["faceValue"]["signatures"]:
                self.assertTrue(item["verified"], (name, item))

    def test_the_only_signing_root_is_same_party(self) -> None:
        root = self.roles["realState"]["onlySigningRoot"]
        self.assertTrue(root["symmetric"])
        self.assertEqual(root["trustDomain"], "same-party")
        self.assertFalse(root["external"])
        self.assertEqual(self.roles["realState"]["externalTrustDomains"], 0)

    def test_the_absent_roles_are_recorded_as_none(self) -> None:
        state = self.roles["realState"]
        self.assertEqual(state["externalReproducer"], "none")
        self.assertEqual(state["releaseAuthority"], "none")
        self.assertEqual(state["maintainer"], "none")
        self.assertEqual(state["instrumentReviewer"], "none")
        self.assertEqual(state["declaredIdentities"], 0)
        coverage = {item["role"]: item for item in self.roles["roleCoverage"]}
        self.assertEqual(coverage["maintainer"]["state"], "none")
        self.assertEqual(coverage["instrument_reviewer"]["state"], "none")

    def test_every_identity_is_the_same_party(self) -> None:
        parties = {
            item["identity"]: item["party"]
            for item in self.roles["assignments"]
        }
        self.assertEqual(parties["P-CAMPAIGN"], "P-PROJECT-UNDECLARED")
        self.assertEqual(parties["P-PRINCIPAL"], "P-PROJECT-UNDECLARED")

    def test_every_real_assignment_names_its_record(self) -> None:
        for item in self.roles["assignments"]:
            self.assertTrue(item["evidence"], item)
            self.assertTrue(item["identityRecordedAt"], item)
            self.assertFalse(item["declaredIdentity"], item)
            self.assertIsNone(item["grantedBy"]["identity"], item)

    def test_real_separations_are_recorded(self) -> None:
        expected = {
            "release": {"release_authority != producer",
                        "release_authority != adjudicator"},
            "claim-promotion": {"adjudicator != producer"},
            "consumer-graduation": {"adjudicator != producer",
                                    "external_reproducer != producer",
                                    "adjudicator != external_reproducer"},
            "revocation": {"revocation_authority != producer"},
        }
        for action, constraints in expected.items():
            failed = {
                item["constraint"] for item in self.authorisation["actions"][action]["separationFailed"]
                if item.get("evaluated")
            }
            self.assertEqual(failed, constraints, action)
            self.assertEqual(
                {item["party"][0] for item in self.authorisation["actions"][action]["separationFailed"]
                 if item.get("evaluated")},
                {"P-PROJECT-UNDECLARED"},
            )

    def test_roles_of_real_identities(self) -> None:
        roles = auth.roles_of("P-CAMPAIGN", at=AT,
                              assignments=self.roles["assignments"])
        self.assertEqual(
            {item["role"] for item in roles},
            {"producer", "adjudicator", "external_reproducer", "revocation_authority"},
        )
        self.assertTrue(all(item["party"] == "P-PROJECT-UNDECLARED" for item in roles))
        principal = auth.roles_of("P-PRINCIPAL", at=AT,
                                  assignments=self.roles["assignments"])
        self.assertEqual({item["role"] for item in principal}, {"release_authority"})

    def test_controls_exercise_every_code(self) -> None:
        self.assertEqual(self.controls["missingCodes"], [])
        self.assertEqual(self.controls["counts"]["refusalCodes"], len(auth.REFUSAL_CODES))
        self.assertEqual(self.controls["counts"]["codesExercised"], len(auth.REFUSAL_CODES))
        for control in self.controls["controls"]:
            self.assertTrue(control["pass"], control["name"])

    def test_positive_control_is_control_only(self) -> None:
        positive = [item for item in self.controls["controls"]
                    if item["name"] == "positive-distinct-roles"][0]
        self.assertEqual(positive["observed"]["outcome"], "AUTHORISED")
        self.assertEqual(positive["label"], "control-only")
        self.assertIn("not a real authorised action", positive["establishes"])
        self.assertEqual(self.authorisation["aggregate"]["authorised"], 0)


class Determinism(unittest.TestCase):
    def test_builder_is_byte_identical_twice_and_matches_committed(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for out in (first, second):
                run = subprocess.run(
                    [sys.executable, str(BUILDER), "--out", out,
                     "--source-commit", FULL_COMMIT],
                    cwd=str(REPO), text=True, capture_output=True, timeout=120,
                )
                self.assertEqual(run.returncode, 0, run.stderr)
            for name in ("ROLES.json", "AUTHORISATION.json", "CONTROLS.json"):
                left = (Path(first) / name).read_bytes()
                right = (Path(second) / name).read_bytes()
                committed = (EVIDENCE / name).read_bytes()
                self.assertEqual(left, right, name)
                self.assertEqual(left, committed, name)

    def test_build_is_deterministic_in_process(self) -> None:
        builder = load_builder()
        names = ("ROLES.json", "AUTHORISATION.json", "CONTROLS.json")
        first = builder.build(FULL_COMMIT)
        second = builder.build(FULL_COMMIT)
        for name, document, other in zip(names, first, second):
            rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
            rendered_again = json.dumps(other, indent=2, sort_keys=True) + "\n"
            self.assertEqual(rendered, rendered_again, name)
            self.assertEqual(rendered.encode(), (EVIDENCE / name).read_bytes(), name)


class CommandLine(unittest.TestCase):
    def run_tool(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(TOOLS / "authorisation.py"), *args],
            cwd=str(cwd or REPO), text=True, capture_output=True, timeout=120,
        )

    def test_roles_exit_zero_and_one(self) -> None:
        found = self.run_tool("roles", "P-CAMPAIGN", "--at", AT)
        self.assertEqual(found.returncode, 0, found.stderr)
        self.assertIn("role=producer", found.stdout)
        absent = self.run_tool("roles", "control-only-nobody", "--at", AT)
        self.assertEqual(absent.returncode, 1)
        self.assertIn("roles=NONE", absent.stdout)

    def test_authorise_release_prints_outcome_and_code(self) -> None:
        run = self.run_tool("authorise", "release")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("outcome=REFUSED", run.stdout)
        self.assertIn("RA_REFUSED_SIGNATURE_UNVERIFIED", run.stdout)
        self.assertIn("face-value: outcome=REFUSED", run.stdout)
        self.assertIn("RA_REFUSED_SEPARATION", run.stdout)

    def test_authorise_face_value_prints_the_role_refusals(self) -> None:
        run = self.run_tool("authorise", "release", "--face-value")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("outcome=REFUSED", run.stdout)
        self.assertIn("RA_REFUSED_SEPARATION", run.stdout)

    def test_authorise_unknown_action_prints_its_code(self) -> None:
        run = self.run_tool("authorise", "launch")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("RA_REFUSED_ACTION_UNKNOWN", run.stdout)

    def test_explain_known_and_unknown(self) -> None:
        known = self.run_tool("explain", "claim-promotion")
        self.assertEqual(known.returncode, 0, known.stderr)
        self.assertIn("adjudicator != producer", known.stdout)
        unknown = self.run_tool("explain", "launch")
        self.assertEqual(unknown.returncode, 1)
        self.assertIn("RA_REFUSED_ACTION_UNKNOWN", unknown.stdout)

    def test_json_output_is_machine_readable(self) -> None:
        run = self.run_tool("authorise", "release", "--json")
        self.assertEqual(run.returncode, 1, run.stderr)
        payload = json.loads(run.stdout)
        self.assertEqual(payload["outcome"], "REFUSED")
        self.assertIn("RA_REFUSED_SIGNATURE_UNVERIFIED", payload["codes"])
        self.assertIsNotNone(payload["faceValue"])
        self.assertTrue(payload["separationFailed"])

    def test_positive_control_cli_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assignments = [
                assignment("control-only-release", "release_authority", "P-CONTROL-RELEASE"),
                assignment("control-only-adjudicator", "adjudicator", "P-CONTROL-ADJUDICATOR"),
                assignment("control-only-author", "producer", "P-CONTROL-AUTHOR"),
            ]
            context = {
                "scope": ["release:control"],
                "evidenceProducer": "control-only-author",
                "roleIdentities": {"producer": "control-only-author"},
            }
            signatures = [
                signature("control-only-release", "release_authority", "release:control"),
                signature("control-only-adjudicator", "adjudicator", "release:control"),
            ]
            (root / "assignments.json").write_text(
                json.dumps({"assignments": assignments}), encoding="utf-8"
            )
            (root / "authorisation.json").write_text(
                json.dumps({"actions": {"release": {
                    "context": context,
                    "recorded": {"signatures": signatures},
                }}}),
                encoding="utf-8",
            )
            run = self.run_tool(
                "authorise", "release",
                "--assignments", str(root / "assignments.json"),
                "--authorisations", str(root / "authorisation.json"),
                "--at", AT,
            )
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("outcome=AUTHORISED", run.stdout)

    def test_usage_error_exits_two(self) -> None:
        run = self.run_tool("authorise")
        self.assertEqual(run.returncode, 2)

    def test_unreadable_input_exits_two(self) -> None:
        run = self.run_tool("authorise", "release", "--assignments", "/nonexistent/roles.json")
        self.assertEqual(run.returncode, 2)
        self.assertIn("error", run.stderr)


class DocumentSynchronisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8")

    def test_every_role_is_named(self) -> None:
        for role in auth.ROLES:
            self.assertIn(f"`{role}`", self.text, role)

    def test_every_action_is_named(self) -> None:
        for action in auth.ACTIONS:
            self.assertIn(f"`{action}`", self.text, action)

    def test_every_refusal_code_is_named(self) -> None:
        for code in auth.REFUSAL_CODES:
            self.assertIn(code, self.text, code)

    def test_real_result_is_stated(self) -> None:
        self.assertIn("0 actions authorised", self.text)
        self.assertIn("0 authorised", self.text)
        self.assertIn("same undeclared party", self.text)

    def test_controls_and_positive_control_are_stated(self) -> None:
        self.assertIn("control-only", self.text)
        self.assertIn("positive control", self.text.lower())
        self.assertIn("does not establish", self.text)

    def test_release_gate_status_is_stated(self) -> None:
        self.assertIn("RG_AUTHORISATION_REFUSED", self.text)
        self.assertTrue(
            "release gate refuses" in self.text.lower()
            or "release-gate integration" in self.text.lower()
        )

    def test_not_run_section_exists(self) -> None:
        self.assertIn("## `NOT_RUN`", self.text)
        self.assertIn("NOT_RUN", self.text)

    def test_every_enforced_by_names_a_code_or_test(self) -> None:
        markers = ("RA_REFUSED_", "test_", "`authorisation.py`", "`build_evidence.py`")
        for line in self.text.splitlines():
            if "Enforced by" in line:
                self.assertTrue(
                    any(marker in line for marker in markers),
                    f"enforcement line names no code or test: {line!r}",
                )


class JsonRecords(unittest.TestCase):
    def test_every_record_parses_and_is_bound(self) -> None:
        schemas = {
            "ROLES.json": "openssl-rs/a14/roles/1",
            "AUTHORISATION.json": "openssl-rs/a14/authorisation/1",
            "CONTROLS.json": "openssl-rs/a14/controls/1",
        }
        for name, schema in schemas.items():
            document = load_json(EVIDENCE / name)
            self.assertEqual(document["schema"], schema)
            self.assertEqual(document["sourceIdentity"]["baseCommit"], FULL_COMMIT)
            self.assertTrue(document["sourceIdentity"]["tool"]["sha256"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
