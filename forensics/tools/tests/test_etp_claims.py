#!/usr/bin/env python3
"""Tests for forensics/tools/etp_claims.py and evidence/etp/claims.json.

Run directly (`python3 forensics/tools/tests/test_etp_claims.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.

The negative controls each mutate one field of a well-formed claim and require
the named rule to fire against the named field. The integrity-hardening controls
add admitted-exclusion witnesses, CLI operation validation, and strict JSON
loading (duplicate keys and non-finite numbers), each with its own rule. The
positive controls prove the validator accepts a well-formed document, that the
committed typed claims validate, and that the schema is not vacuous.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
sys.path.insert(0, str(TOOLS))

import etp_claims  # noqa: E402

SCHEMA = etp_claims.load_json(etp_claims.DEFAULT_SCHEMA)
CLAIMS_PATH = etp_claims.DEFAULT_CLAIMS


def base_claim() -> dict:
    """A well-formed claim with every axis stated."""
    return {
        "id": "ETP-CLM-901",
        "property": "memory-safety",
        "interpretation": "A synthetic claim used to exercise the validator's laws.",
        "quantification": {
            "kind": "universal",
            "population": "the single synthetic unit",
            "measure": {"form": "count", "value": "1 unit", "aggregation": "forbidden"},
        },
        "scope": {
            "kind": "code",
            "subject": "synthetic unit",
            "venue": "test",
            "locations": ["src/synthetic.rs"],
            "excludes": [],
        },
        "threat_model": {
            "adversary": "a hostile input reaching the synthetic unit",
            "observation_model": "static inspection of the cited unit",
            "out_of_scope": ["unreachable code"],
        },
        "identity": {
            "source": {
                "candidate": "synthetic",
                "commit": "a" * 40,
                "binding": "exact",
                "tree_sha256": None,
            },
            "build": {"toolchain": None, "profile": None, "target": None},
            "artefacts": [],
        },
        "authority": {
            "kind": "source-tree",
            "name": "src/synthetic.rs",
            "version": None,
            "path": "src/synthetic.rs",
        },
        "target": {
            "kind": "code",
            "name": "synthetic unit",
            "path": "src/synthetic.rs",
        },
        "assumptions": [],
        "evidence": [
            {
                "id": "EV-01",
                "path": "src/synthetic.rs",
                "kind": "file",
                "sha256": "0" * 64,
                "digest_identity": "S",
                "present": True,
                "reconstructable": True,
            }
        ],
        "tcb": [
            {
                "component": "Git object store",
                "trusted_for": "the cited bytes",
                "verified": False,
            }
        ],
        "obligations": [],
        "invalidation": {
            "depends_on": [{"kind": "commit", "id": "a" * 40}],
            "rationale": "The synthetic source identity is the only input.",
        },
        "modality": "TESTED",
        "reproduction": {"status": "NOT_ATTEMPTED", "procedure": None, "at": None},
        "verdict": {
            "state": "ESTABLISHED",
            "basis": "The cited unit states the assertion.",
        },
    }


def base_document(claim: dict | None = None) -> dict:
    return {
        "schema": "openssl-rs/etp/claims/v1",
        "kind": "etp-typed-claims",
        "generated_utc": "2026-11-22T00:00:00Z",
        "source_identity": {
            "commit": "a" * 40,
            "branch": "staging",
            "worktree_dirty_tracked_files": 0,
            "tracked_file_count": 1,
            "tree_hash_rule": "sha256 over canonical JSON of tracked entries",
            "trees": {"src": {"paths": ["src"], "file_count": 1, "sha256": "b" * 64}},
            "authority_registry": {
                "path": "forensics/authorities/AUTHORITIES.json",
                "file_count": 1,
                "sha256": "c" * 64,
            },
        },
        "derived_from": {
            "document": "evidence/etp0/CLAIMS.json",
            "sha256": "d" * 64,
            "input_evidence_commit": "e" * 40,
            "claim_count": 1,
            "trust_gaps": {
                "path": "evidence/etp0/TRUST-GAPS.json",
                "sha256": "f" * 64,
                "gap_count": 1,
            },
        },
        "claims": [claim if claim is not None else base_claim()],
    }


def witness() -> dict:
    """A structurally complete exclusion witness, bound to base_claim()."""
    return {
        "obligation": "OBL-EX",
        "candidate": "a" * 40,
        "procedure": "python3 courts/review_exclusion.py --obligation OBL-EX",
        "result": {
            "path": "courts/review-exclusion.json",
            "sha256": "1" * 64,
            "digest_identity": "E",
            "present": True,
            "producer": "courts/review_exclusion.py",
        },
        "reviewer": {
            "role": "evidence-adjudicator",
            "identity": "reviewer-1",
        },
    }


def exclusion_claim() -> dict:
    claim = base_claim()
    claim["author"] = {"role": "conversion-engineer", "identity": "author-1"}
    claim["obligations"] = [
        {
            "id": "OBL-EX",
            "statement": "a synthetic open obligation used to exercise exclusions",
            "state": "OPEN",
            "blocks": ["graduation"],
            "settled_by": "the independent review result",
            "evidence": ["EV-01"],
            "exclusions": [
                {
                    "claim": "ETP-CLM-902",
                    "argument": "the dependent uses an independently measured replacement",
                    "checkable_by": "courts/review-exclusion.json",
                    "witness": witness(),
                }
            ],
        }
    ]
    return claim


def refusals(doc: dict) -> list[dict]:
    return etp_claims.validate_document(doc, SCHEMA, repo_root=None)


def rules(doc: dict) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for refusal in refusals(doc):
        grouped.setdefault(refusal["rule"], []).append(refusal)
    return grouped


def assert_rule(test: unittest.TestCase, doc: dict, rule: str, field: str) -> None:
    grouped = rules(doc)
    test.assertIn(rule, grouped, f"expected {rule}; got {sorted(grouped)}")
    test.assertTrue(
        any(field in refusal["path"] or field in refusal["field"] for refusal in grouped[rule]),
        f"{rule} did not name {field}: {grouped[rule]}",
    )


class NegativeControls(unittest.TestCase):
    """The ten refusals required by ETP-1, each for its named reason."""

    def test_01_verdict_outruns_modality(self) -> None:
        claim = base_claim()
        claim["modality"] = "DOCUMENTED"
        claim["evidence"] = []
        doc = base_document(claim)
        assert_rule(self, doc, "EG_VERDICT_MODALITY", "verdict/state")

    def test_02_graduated_verdict_with_open_obligation(self) -> None:
        claim = base_claim()
        claim["modality"] = "PROOF_OBLIGATIONS_DISCHARGED"
        claim["verdict"]["state"] = "SAFE_COMPATIBLE"
        claim["closure"] = {
            "dependencies": ["ETP-CLM-901"],
            "unresolved_dependencies": [],
            "complete": True,
        }
        claim["obligations"] = [
            {
                "id": "OBL-OPEN",
                "statement": "an unresolved open item",
                "state": "OPEN",
                "blocks": ["graduation"],
                "settled_by": "a tracked receipt",
                "evidence": ["EV-01"],
            }
        ]
        doc = base_document(claim)
        assert_rule(self, doc, "EG_GRADUATED_WITH_OPEN_OBLIGATION", "obligations")

    def test_03_evidence_unreconstructable(self) -> None:
        claim = base_claim()
        claim["evidence"] = [
            {
                "id": "EV-01",
                "path": None,
                "kind": "log",
                "sha256": None,
                "digest_identity": None,
                "present": False,
                "reconstructable": False,
            }
        ]
        doc = base_document(claim)
        assert_rule(self, doc, "EG_EVIDENCE_UNRECONSTRUCTABLE", "evidence/0")

    def test_04_threat_model_missing(self) -> None:
        claim = base_claim()
        claim["property"] = "memory-safety"
        claim["threat_model"] = None
        doc = base_document(claim)
        assert_rule(self, doc, "EG_THREAT_MODEL_MISSING", "threat_model")

    def test_05_self_declared_policy(self) -> None:
        doc = base_document()
        doc["policy"] = {"acceptance": "any verdict with a citation is ESTABLISHED"}
        assert_rule(self, doc, "EG_SELF_DECLARED_POLICY", "policy")

    def test_06_evidence_alias(self) -> None:
        claim = base_claim()
        duplicate = dict(claim["evidence"][0])
        duplicate["id"] = "EV-02"
        claim["evidence"].append(duplicate)
        doc = base_document(claim)
        assert_rule(self, doc, "EG_EVIDENCE_ALIAS", "evidence/1")

    def test_07_invalidation_cycle(self) -> None:
        first = base_claim()
        second = copy.deepcopy(first)
        second["id"] = "ETP-CLM-902"
        first["invalidation"]["depends_on"] = [{"kind": "claim", "id": "ETP-CLM-902"}]
        second["invalidation"]["depends_on"] = [{"kind": "claim", "id": "ETP-CLM-901"}]
        doc = base_document(first)
        doc["claims"].append(second)
        assert_rule(self, doc, "EG_INVALIDATION_CYCLE", "invalidation")

    def test_08_modality_ranking(self) -> None:
        claim = base_claim()
        claim["modality_rank"] = {"DOCUMENTED": 1, "ESTABLISHED": 2, "TESTED": 3}
        doc = base_document(claim)
        assert_rule(self, doc, "EG_MODALITY_RANKING", "modality_rank")

    def test_09_multiple_candidate_identities(self) -> None:
        claim = base_claim()
        claim["identity"]["source"]["candidates"] = ["a" * 40, "b" * 40]
        doc = base_document(claim)
        assert_rule(self, doc, "EG_MULTIPLE_CANDIDATES", "identity/source")

    def test_10_quantification_coverage(self) -> None:
        claim = base_claim()
        claim["quantification"] = {
            "kind": "enumerated",
            "population": "33 cohort families",
            "population_size": 33,
            "members": [f"family-{index}" for index in range(32)],
            "measure": {"form": "count", "value": "32 listed", "aggregation": "forbidden"},
        }
        doc = base_document(claim)
        assert_rule(self, doc, "EG_QUANTIFICATION_COVERAGE", "quantification/members")


class PositiveControls(unittest.TestCase):
    def test_base_claim_is_accepted(self) -> None:
        self.assertEqual(refusals(base_document()), [])

    def test_schema_is_not_vacuous_required_claim_fields(self) -> None:
        required = SCHEMA["$defs"]["claim"]["required"]
        self.assertGreaterEqual(len(required), 15)
        for name in required:
            with self.subTest(field=name):
                claim = base_claim()
                claim.pop(name)
                found = refusals(base_document(claim))
                self.assertTrue(
                    any(name in refusal["path"] for refusal in found),
                    f"removing '{name}' was not refused: {found}",
                )

    def test_schema_is_not_vacuous_required_document_fields(self) -> None:
        for name in SCHEMA["required"]:
            with self.subTest(field=name):
                doc = base_document()
                doc.pop(name)
                self.assertTrue(
                    any(name in refusal["path"] for refusal in refusals(doc)),
                    f"removing document field '{name}' was not refused",
                )

    def test_schema_rejects_unknown_property(self) -> None:
        claim = base_claim()
        claim["unexpressible_axis"] = "not in the type"
        self.assertIn("EG_SCHEMA_VIOLATION", rules(base_document(claim)))

    def test_schema_rejects_wrong_enum(self) -> None:
        claim = base_claim()
        claim["verdict"]["state"] = "PROBABLY_FINE"
        self.assertIn("EG_SCHEMA_VIOLATION", rules(base_document(claim)))

    def test_measure_cannot_be_aggregated(self) -> None:
        claim = base_claim()
        claim["quantification"]["measure"]["aggregation"] = "mean"
        self.assertIn("EG_MEASURE_AGGREGATION", rules(base_document(claim)))

    def test_absent_evidence_needs_obligation(self) -> None:
        claim = base_claim()
        claim["evidence"][0]["present"] = False
        claim["evidence"][0]["reconstructable"] = "partial"
        self.assertIn("EG_EVIDENCE_ABSENT_NO_OBLIGATION", rules(base_document(claim)))

    def test_unchecked_assumption_is_refused(self) -> None:
        claim = base_claim()
        claim["assumptions"] = [
            {"id": "A-ONE", "statement": "a premise", "checkable_by": "not stated"}
        ]
        self.assertIn("EG_ASSUMPTION_UNCHECKABLE", rules(base_document(claim)))

    def test_contradiction_keeps_both_sides(self) -> None:
        claim = base_claim()
        claim["verdict"]["state"] = "CONTRADICTED"
        claim["contradiction"] = {
            "parties": [
                {
                    "id": "side-a",
                    "source": "docs/a.md",
                    "assertion": "the value is 1",
                    "asserted_verdict": "ESTABLISHED",
                    "evidence": ["docs/a.md"],
                }
            ],
            "resolution_owner": "ETP-T15",
        }
        self.assertIn("EG_CONTRADICTION_PARTIES", rules(base_document(claim)))

    def test_graduated_claim_with_complete_closure_is_accepted(self) -> None:
        claim = base_claim()
        claim["modality"] = "PROOF_OBLIGATIONS_DISCHARGED"
        claim["verdict"]["state"] = "SAFE_COMPATIBLE"
        claim["closure"] = {
            "dependencies": ["ETP-CLM-901"],
            "unresolved_dependencies": [],
            "complete": True,
        }
        self.assertEqual(refusals(base_document(claim)), [])

    def test_graduated_claim_with_unresolved_dependency_is_refused(self) -> None:
        claim = base_claim()
        claim["modality"] = "PROOF_OBLIGATIONS_DISCHARGED"
        claim["verdict"]["state"] = "SAFE_COMPATIBLE"
        claim["closure"] = {
            "dependencies": ["ETP-CLM-901", "libcrypto"],
            "unresolved_dependencies": ["libcrypto"],
            "complete": True,
        }
        self.assertIn(
            "EG_GRADUATED_WITHOUT_CLOSURE", rules(base_document(claim))
        )

    def test_derived_verdict_may_not_be_promoted(self) -> None:
        claim = base_claim()
        claim["derived_from"] = {
            "document": "evidence/etp0/CLAIMS.json",
            "id": "ETP0-CLM-013",
            "property": "memory-safety",
            "verdict": "PARTIAL",
        }
        claim["verdict"]["state"] = "ESTABLISHED"
        self.assertIn(
            "EG_DERIVED_VERDICT_MISMATCH", rules(base_document(claim))
        )


class Determinism(unittest.TestCase):
    def test_same_input_same_refusals(self) -> None:
        doc = base_document()
        doc["policy"] = {"accept": "everything"}
        first = json.dumps(refusals(doc), sort_keys=True)
        second = json.dumps(refusals(doc), sort_keys=True)
        self.assertEqual(first, second)

    def test_key_insertion_order_does_not_change_output(self) -> None:
        doc = base_document()
        doc["modality_rank"] = {"DOCUMENTED": 1}
        reordered = _reverse_keys(doc)
        self.assertEqual(
            json.dumps(refusals(doc), sort_keys=True),
            json.dumps(refusals(reordered), sort_keys=True),
        )

    def test_cli_output_is_byte_identical(self) -> None:
        doc = base_document()
        doc["policy"] = {"accept": "everything"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "doc.json"
            path.write_text(json.dumps(doc), encoding="utf-8")
            command = [
                sys.executable,
                str(TOOLS / "etp_claims.py"),
                "validate",
                "--no-tree-check",
                "--document",
                str(path),
            ]
            first = subprocess.run(command, capture_output=True, check=False)
            second = subprocess.run(command, capture_output=True, check=False)
        self.assertEqual(first.returncode, 1)
        self.assertEqual(first.stdout, second.stdout)
        payload = json.loads(first.stdout)
        self.assertIn("EG_SELF_DECLARED_POLICY", payload["refusals_by_rule"])


def _reverse_keys(value: object) -> object:
    if isinstance(value, dict):
        return {key: _reverse_keys(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [_reverse_keys(item) for item in value]
    return value


class AlgebraOperations(unittest.TestCase):
    @staticmethod
    def _claim(claim_id: str, state: str, obligations: list[dict] | None = None) -> dict:
        return {
            "id": claim_id,
            "verdict": {"state": state, "basis": "synthetic"},
            "modality": "TESTED",
            "obligations": obligations or [],
        }

    def test_conjunction_never_better_than_weakest(self) -> None:
        result = etp_claims.conjoin(
            [
                self._claim("ETP-CLM-901", "ESTABLISHED"),
                self._claim("ETP-CLM-902", "PARTIAL"),
            ]
        )
        self.assertEqual(result["verdict"], "PARTIAL")
        self.assertEqual(result["aggregation"], "forbidden")
        self.assertIn("ETP-CLM-902", [item["id"] for item in result["blocked_by"]])
        self.assertEqual(
            sorted(member["verdict"] for member in result["members"]),
            ["ESTABLISHED", "PARTIAL"],
        )

    def test_conjunction_keeps_every_member_verdict(self) -> None:
        result = etp_claims.conjoin(
            [
                self._claim("ETP-CLM-901", "ESTABLISHED"),
                self._claim("ETP-CLM-902", "NOT_ESTABLISHED"),
                self._claim("ETP-CLM-903", "SAFE_COMPATIBLE"),
            ]
        )
        self.assertEqual(result["verdict"], "NOT_ESTABLISHED")
        self.assertEqual(len(result["members"]), 3)

    def test_absorbing_verdict_cannot_be_hidden(self) -> None:
        result = etp_claims.conjoin(
            [
                self._claim("ETP-CLM-901", "SAFE_COMPATIBLE"),
                self._claim("ETP-CLM-902", "CONTRADICTED"),
            ]
        )
        self.assertEqual(result["verdict"], "CONTRADICTED")
        self.assertIn("ETP-CLM-902", result["weakest"])

    def test_conjunction_unions_obligations(self) -> None:
        first = self._claim("ETP-CLM-901", "PARTIAL", [{"id": "OBL-A", "state": "OPEN"}])
        second = self._claim("ETP-CLM-902", "PARTIAL", [{"id": "OBL-B", "state": "OPEN"}])
        result = etp_claims.conjoin([first, second])
        self.assertEqual(
            [obligation["id"] for obligation in result["obligations"]], ["OBL-A", "OBL-B"]
        )

    def test_invalidation_is_transitive(self) -> None:
        def link(claim_id: str, dependency_id: str) -> dict:
            return {
                "id": claim_id,
                "invalidation": {
                    "depends_on": [{"kind": "claim", "id": dependency_id}],
                    "rationale": "synthetic",
                },
                "evidence": [],
            }

        claims = [
            link("ETP-CLM-901", "ETP-CLM-902"),
            link("ETP-CLM-902", "ETP-CLM-903"),
            {
                "id": "ETP-CLM-903",
                "invalidation": {
                    "depends_on": [{"kind": "path", "id": "src/c.rs"}],
                    "rationale": "synthetic",
                },
                "evidence": [],
            },
        ]
        result = etp_claims.invalidated_claims(claims, ["src/c.rs"])
        self.assertEqual(
            result["invalidated"],
            ["ETP-CLM-901", "ETP-CLM-902", "ETP-CLM-903"],
        )
        self.assertEqual(result["direct"], ["ETP-CLM-903"])

    def test_invalidation_follows_cited_bytes_and_commits(self) -> None:
        claim = {
            "id": "ETP-CLM-901",
            "identity": {"source": {"commit": "a" * 40}},
            "evidence": [{"path": "docs/x.md", "sha256": "b" * 64}],
            "invalidation": {"depends_on": [], "rationale": "synthetic"},
        }
        self.assertIn(
            "ETP-CLM-901",
            etp_claims.invalidated_claims([claim], ["docs/x.md"])["invalidated"],
        )
        self.assertIn(
            "ETP-CLM-901",
            etp_claims.invalidated_claims([claim], ["a" * 40])["invalidated"],
        )

    def test_obligation_propagation_honours_only_admitted_exclusion_witnesses(self) -> None:
        dependency = {
            "id": "ETP-CLM-903",
            "author": {"role": "conversion-engineer", "identity": "author-9"},
            "identity": {"source": {"candidate": "a" * 40, "commit": "a" * 40}},
            "obligations": [
                {
                    "id": "OBL-X",
                    "state": "OPEN",
                    "exclusions": [
                        {
                            "claim": "ETP-CLM-902",
                            "argument": "the dependent uses an independently measured replacement",
                            "checkable_by": "courts/replacement.json",
                            "witness": {
                                "obligation": "OBL-X",
                                "candidate": "a" * 40,
                                "procedure": "python3 courts/replacement.py",
                                "result": {
                                    "path": "courts/replacement.json",
                                    "sha256": "1" * 64,
                                    "digest_identity": "E",
                                    "present": True,
                                    "producer": "courts/replacement.py",
                                },
                                "reviewer": {
                                    "role": "evidence-adjudicator",
                                    "identity": "reviewer-2",
                                },
                            },
                        }
                    ],
                }
            ],
        }
        direct = {
            "id": "ETP-CLM-901",
            "invalidation": {
                "depends_on": [{"kind": "claim", "id": "ETP-CLM-903"}],
                "rationale": "synthetic",
            },
        }
        excluded = {
            "id": "ETP-CLM-902",
            "invalidation": {
                "depends_on": [{"kind": "claim", "id": "ETP-CLM-903"}],
                "rationale": "synthetic",
            },
        }
        result = etp_claims.propagated_obligations([dependency, direct, excluded])
        self.assertIn("ETP-CLM-901", result["propagated"])
        self.assertNotIn("ETP-CLM-902", result["propagated"])

    def test_exclusion_without_a_witness_does_not_stop_propagation(self) -> None:
        dependency = {
            "id": "ETP-CLM-903",
            "obligations": [
                {
                    "id": "OBL-X",
                    "state": "OPEN",
                    "exclusions": [
                        {
                            "claim": "ETP-CLM-902",
                            "argument": "the dependent uses an independently measured replacement",
                            "checkable_by": "courts/replacement.json",
                        }
                    ],
                }
            ],
        }
        dependent = {
            "id": "ETP-CLM-902",
            "invalidation": {
                "depends_on": [{"kind": "claim", "id": "ETP-CLM-903"}],
                "rationale": "synthetic",
            },
        }
        result = etp_claims.propagated_obligations([dependency, dependent])
        self.assertIn("ETP-CLM-902", result["propagated"])

    def test_exclusion_bound_to_another_candidate_does_not_stop_propagation(self) -> None:
        exclusion = {
            "claim": "ETP-CLM-902",
            "argument": "the dependent uses an independently measured replacement",
            "checkable_by": "courts/replacement.json",
            "witness": {
                "obligation": "OBL-X",
                "candidate": "b" * 40,
                "procedure": "python3 courts/replacement.py",
                "result": {
                    "path": "courts/replacement.json",
                    "sha256": "1" * 64,
                    "digest_identity": "E",
                    "present": True,
                    "producer": "courts/replacement.py",
                },
                "reviewer": {
                    "role": "evidence-adjudicator",
                    "identity": "reviewer-2",
                },
            },
        }
        dependency = {
            "id": "ETP-CLM-903",
            "author": {"role": "conversion-engineer", "identity": "author-9"},
            "identity": {"source": {"candidate": "a" * 40, "commit": "a" * 40}},
            "obligations": [{"id": "OBL-X", "state": "OPEN", "exclusions": [exclusion]}],
        }
        dependent = {
            "id": "ETP-CLM-902",
            "invalidation": {
                "depends_on": [{"kind": "claim", "id": "ETP-CLM-903"}],
                "rationale": "synthetic",
            },
        }
        result = etp_claims.propagated_obligations([dependency, dependent])
        self.assertIn("ETP-CLM-902", result["propagated"])

    def test_uncheckable_exclusion_does_not_stop_propagation(self) -> None:
        dependency = {
            "id": "ETP-CLM-903",
            "obligations": [
                {
                    "id": "OBL-X",
                    "state": "OPEN",
                    "exclusions": [
                        {
                            "claim": "ETP-CLM-902",
                            "argument": "",
                            "checkable_by": "unknown",
                        }
                    ],
                }
            ],
        }
        dependent = {
            "id": "ETP-CLM-902",
            "invalidation": {
                "depends_on": [{"kind": "claim", "id": "ETP-CLM-903"}],
                "rationale": "synthetic",
            },
        }
        result = etp_claims.propagated_obligations([dependency, dependent])
        self.assertIn("ETP-CLM-902", result["propagated"])

    def test_cross_claim_contradiction_is_a_hard_error(self) -> None:
        first = self._claim("ETP-CLM-901", "ESTABLISHED")
        second = self._claim("ETP-CLM-902", "REFUTED")
        for claim in (first, second):
            claim["property"] = "timing"
            claim["scope"] = {"subject": "same subject"}
            claim["identity"] = {
                "source": {"candidate": "same", "commit": "a" * 40}
            }
        conflicts = etp_claims.contradiction_conflicts([first, second])
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["resolution"], "hard error: preference may not resolve it")


class TypedClaims(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = etp_claims.load_json(CLAIMS_PATH)
        cls.etp0 = etp_claims.load_json(REPO_ROOT / "evidence/etp0/CLAIMS.json")

    def test_every_etp0_claim_is_typed_without_a_verdict_change(self) -> None:
        typed = {claim["id"]: claim for claim in self.document["claims"]}
        self.assertEqual(len(typed), len(self.etp0["claims"]))
        for original in self.etp0["claims"]:
            claim = typed[original["id"]]
            self.assertEqual(claim["property"], original["property"])
            self.assertEqual(
                claim["verdict"]["state"],
                etp_claims.ETP0_VERDICT_MAP[original["verdict"]["state"]],
            )

    def test_four_contradictions_keep_both_sides(self) -> None:
        contradicted = [
            claim
            for claim in self.document["claims"]
            if claim["verdict"]["state"] == "CONTRADICTED"
        ]
        self.assertEqual(len(contradicted), 4)
        for claim in contradicted:
            parties = claim["contradiction"]["parties"]
            self.assertGreaterEqual(len(parties), 2)
            self.assertGreaterEqual(len({party["source"] for party in parties}), 2)
            self.assertEqual(claim["contradiction"]["resolution_owner"], "ETP-T15")

    def test_committed_claims_validate_against_schema_and_tree(self) -> None:
        found = etp_claims.validate_document(
            self.document, SCHEMA, repo_root=REPO_ROOT
        )
        self.assertEqual(found, [], f"committed claims were refused: {found}")

    def test_absent_evidence_carries_an_obligation(self) -> None:
        for claim in self.document["claims"]:
            covered = {
                evidence_id
                for obligation in claim["obligations"]
                for evidence_id in obligation["evidence"]
            }
            for entry in claim["evidence"]:
                if entry["present"] is not True or entry["reconstructable"] is False:
                    self.assertIn(entry["id"], covered, f"{claim['id']} {entry['path']}")

    def test_no_claim_is_silently_downgraded(self) -> None:
        partial = [
            claim
            for claim in self.document["claims"]
            if claim["verdict"]["state"] == "PARTIAL"
        ]
        self.assertEqual(len(partial), 13)
        for claim in partial:
            self.assertTrue(claim["obligations"], claim["id"])

    def test_typed_claims_contain_no_first_person(self) -> None:
        text = CLAIMS_PATH.read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"\b(I|we|my|our|us)\b", text), [])


class ExclusionWitnessControls(unittest.TestCase):
    """An exclusion is admitted only by a bound, candidate-specific witness."""

    def test_complete_witness_is_accepted(self) -> None:
        self.assertEqual(refusals(base_document(exclusion_claim())), [])

    def test_absent_witness_is_refused(self) -> None:
        claim = exclusion_claim()
        claim["obligations"][0]["exclusions"][0].pop("witness")
        assert_rule(
            self,
            base_document(claim),
            "EG_EXCLUSION_WITNESS_MISSING",
            "witness",
        )

    def test_unbound_obligation_is_refused(self) -> None:
        claim = exclusion_claim()
        claim["obligations"][0]["exclusions"][0]["witness"]["obligation"] = "OBL-OTHER"
        assert_rule(
            self,
            base_document(claim),
            "EG_EXCLUSION_WITNESS_UNBOUND",
            "witness",
        )

    def test_witness_bound_to_another_candidate_is_refused(self) -> None:
        claim = exclusion_claim()
        claim["obligations"][0]["exclusions"][0]["witness"]["candidate"] = "b" * 40
        assert_rule(
            self,
            base_document(claim),
            "EG_EXCLUSION_WITNESS_CANDIDATE",
            "witness",
        )

    def test_self_authored_witness_is_refused(self) -> None:
        claim = exclusion_claim()
        claim["obligations"][0]["exclusions"][0]["witness"]["reviewer"] = {
            "role": "conversion-engineer",
            "identity": "author-1",
        }
        assert_rule(
            self,
            base_document(claim),
            "EG_EXCLUSION_WITNESS_SELF_AUTHORED",
            "witness",
        )

    def test_absent_witness_result_is_refused(self) -> None:
        claim = exclusion_claim()
        claim["obligations"][0]["exclusions"][0]["witness"]["result"]["present"] = False
        assert_rule(
            self,
            base_document(claim),
            "EG_EXCLUSION_WITNESS_RESULT_ABSENT",
            "witness",
        )

    def test_witness_result_digest_is_re_derived(self) -> None:
        claim = exclusion_claim()
        exclusion = claim["obligations"][0]["exclusions"][0]
        exclusion["witness"]["result"]["sha256"] = "0" * 64
        document = base_document(claim)
        document["claims"][0]["evidence"] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "courts").mkdir()
            (root / "courts/review-exclusion.json").write_text("{}\n", encoding="utf-8")
            found = etp_claims.validate_document(document, SCHEMA, repo_root=root)
        rules_found = {item["rule"] for item in found}
        self.assertIn("EG_EXCLUSION_WITNESS_DIGEST", rules_found)

    def test_witness_result_must_be_present_in_the_tree(self) -> None:
        claim = exclusion_claim()
        exclusion = claim["obligations"][0]["exclusions"][0]
        exclusion["witness"]["result"]["path"] = "courts/absent.json"
        document = base_document(claim)
        document["claims"][0]["evidence"] = []
        with tempfile.TemporaryDirectory() as directory:
            found = etp_claims.validate_document(
                document, SCHEMA, repo_root=Path(directory)
            )
        rules_found = {item["rule"] for item in found}
        self.assertIn("EG_EXCLUSION_WITNESS_RESULT_ABSENT", rules_found)


class CliValidationControls(unittest.TestCase):
    """conjoin, invalidate and propagate refuse a document validate refuses."""

    def _run(self, command: str, document: dict) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "doc.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "etp_claims.py"),
                    command,
                    "--document",
                    str(path),
                    "--no-tree-check",
                ],
                capture_output=True,
                check=False,
            )

    def test_operations_refuse_an_invalid_document(self) -> None:
        document = base_document()
        document["policy"] = {"acceptance": "anything with a citation"}
        for command, operation_key in (
            ("conjoin", "verdict"),
            ("invalidate", "invalidated"),
            ("propagate", "propagated"),
        ):
            with self.subTest(command=command):
                completed = self._run(command, document)
                self.assertEqual(completed.returncode, 1)
                payload = json.loads(completed.stdout)
                self.assertEqual(payload["valid"], False)
                self.assertIn("EG_SELF_DECLARED_POLICY", payload["refusals_by_rule"])
                self.assertNotIn(operation_key, payload)

    def test_operations_refuse_a_schema_violation(self) -> None:
        document = base_document()
        document["claims"][0]["unexpressible_axis"] = "not in the type"
        for command in ("conjoin", "invalidate", "propagate"):
            with self.subTest(command=command):
                completed = self._run(command, document)
                self.assertEqual(completed.returncode, 1)
                payload = json.loads(completed.stdout)
                self.assertIn("EG_SCHEMA_VIOLATION", payload["refusals_by_rule"])

    def test_conjoin_still_answers_a_valid_document(self) -> None:
        completed = self._run("conjoin", base_document())
        self.assertEqual(completed.returncode, 0)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["verdict"], "ESTABLISHED")
        self.assertEqual(payload["aggregation"], "forbidden")


class JsonIntegrityControls(unittest.TestCase):
    """Ambiguous or non-finite JSON is refused with the offending key path."""

    def test_duplicate_object_key_is_refused_with_path(self) -> None:
        with self.assertRaises(etp_claims.JsonIntegrityError) as caught:
            etp_claims.loads_strict('{"claims": [{"id": "A", "id": "B"}]}')
        finding = caught.exception.findings[0]
        self.assertEqual(finding["rule"], "EG_JSON_DUPLICATE_KEY")
        self.assertEqual(finding["path"], "$/claims/0/id")

    def test_non_finite_number_is_refused_with_path(self) -> None:
        with self.assertRaises(etp_claims.JsonIntegrityError) as caught:
            etp_claims.loads_strict('{"quantification": {"measure": NaN}}')
        finding = caught.exception.findings[0]
        self.assertEqual(finding["rule"], "EG_JSON_NON_FINITE")
        self.assertEqual(finding["path"], "$/quantification/measure")

    def test_infinite_number_is_refused(self) -> None:
        with self.assertRaises(etp_claims.JsonIntegrityError) as caught:
            etp_claims.loads_strict('[Infinity]')
        self.assertEqual(caught.exception.findings[0]["rule"], "EG_JSON_NON_FINITE")

    def test_overflowing_number_is_refused(self) -> None:
        with self.assertRaises(etp_claims.JsonIntegrityError) as caught:
            etp_claims.loads_strict('{"n": 1e999}')
        finding = caught.exception.findings[0]
        self.assertEqual(finding["rule"], "EG_JSON_NON_FINITE")
        self.assertEqual(finding["path"], "$/n")

    def test_valid_document_still_loads(self) -> None:
        loaded = etp_claims.loads_strict('{"a": 1, "b": [true, null]}')
        self.assertEqual(loaded, {"a": 1, "b": [True, None]})

    def test_cli_refuses_duplicate_key_with_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "doc.json"
            path.write_text('{"claims": [], "claims": []}', encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "etp_claims.py"),
                    "validate",
                    "--document",
                    str(path),
                    "--no-tree-check",
                ],
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 1)
        payload = json.loads(completed.stdout)
        self.assertIn("EG_JSON_DUPLICATE_KEY", payload["refusals_by_rule"])
        self.assertTrue(
            any(
                refusal["path"] == "$/claims"
                for refusal in payload["refusals"]
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
