#!/usr/bin/env python3
"""Controls for the project-wide finding-identity model.

Each control exercises one claim of `docs/FINDING-IDENTITY.md`: the wire format is
the recorded one; every logical key is built from registered fields and no
registered class depends on a location; the eight code-motion cases behave
conservatively; a collision is a set and an ambiguous attribution is refused; an
exact identity is not reused across artefacts or candidates; and the four
consumers use the model rather than a private notion.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import closure_discipline  # noqa: E402
import etp_claims  # noqa: E402
import finding_identity as fi  # noqa: E402
import freshness  # noqa: E402
import sarif_adapter as adapter  # noqa: E402

A1_SARIF = REPO_ROOT / "evidence" / "a1" / "SARIF.json"
DIGEST_A = "1" * 64
DIGEST_B = "2" * 64
CANDIDATE_A = {"branch": "staging", "commit": "a" * 40}
CANDIDATE_B = {"branch": "staging", "commit": "b" * 40}
LOCATION_WORDS = {"line", "column", "byteOffset", "address", "ordinal", "callSite"}


# --------------------------------------------------------------------------
# Fixture helpers
# --------------------------------------------------------------------------

def _sha(domain: str, *parts: str) -> str:
    payload = "\x00".join((domain,) + tuple(parts))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _finding(
    *,
    rule="A1-UNSAFE-CONTRACT-ABSENT",
    key_class="path-symbol-status",
    uri="src/a.rs",
    digest=DIGEST_A,
    scope="source-tree",
    line=10,
    candidate=CANDIDATE_A,
    locator="site[0]",
    **overrides,
) -> fi.Finding:
    if key_class == "register-entry":
        fields = {"id": "SEC-1"}
    else:
        fields = {
            "path": uri,
            "symbol": "f",
            "status": "VACUOUS_PRECONDITION",
        }
    fields.update(overrides)
    return fi.identify(
        rule_id=rule,
        key_class=key_class,
        binding=fi.Binding(uri=uri, digest=digest, digest_scope=scope),
        region=fi.Region("source", line=line),
        candidate=candidate,
        native_locator=locator,
        **fields,
    )


# --------------------------------------------------------------------------
# Wire format
# --------------------------------------------------------------------------

class WireFormatTests(unittest.TestCase):
    def test_rule_fingerprint_is_the_recorded_construction(self):
        self.assertEqual(fi.rule_fingerprint("A1-X"), _sha("a1-rule/v1", "A1-X"))

    def test_logical_fingerprint_is_the_recorded_construction(self):
        self.assertEqual(
            fi.logical_fingerprint("A1-X", "key"), _sha("a1-logical/v1", "A1-X", "key")
        )

    def test_exact_fingerprint_is_the_recorded_construction(self):
        binding = fi.Binding("src/a.rs", DIGEST_A, "source-tree")
        region = fi.Region("source", line=10)
        self.assertEqual(
            fi.exact_fingerprint("A1-X", "key", binding, region),
            _sha(
                "a1-exact/v1",
                "A1-X",
                "key",
                "src/a.rs",
                f"source-tree:{DIGEST_A}",
                "line=10",
            ),
        )

    def test_wire_labels_are_the_recorded_ones(self):
        self.assertEqual(
            fi.WIRE_KEYS,
            {"rule": "a1Rule/v1", "logical": "a1Logical/v1", "exact": "a1Exact/v1"},
        )
        self.assertEqual(fi.MODEL_ID, "a1/v1")


# --------------------------------------------------------------------------
# Logical keys
# --------------------------------------------------------------------------

class KeyClassTests(unittest.TestCase):
    def test_registered_key_classes_never_use_a_location_field(self):
        for name, spec in fi.KEY_CLASSES.items():
            with self.subTest(key_class=name):
                self.assertFalse(
                    set(spec.fields) & LOCATION_WORDS,
                    f"{name} derives its key from a location field",
                )
                self.assertTrue(set(spec.excludes) & LOCATION_WORDS or not spec.fields)

    def test_declared_independence_agrees_with_the_key_fields(self):
        for name, spec in fi.KEY_CLASSES.items():
            with self.subTest(key_class=name):
                self.assertEqual(
                    spec.location_independent,
                    "path" not in spec.fields,
                    f"{name} declares an independence its fields do not support",
                )

    def test_each_registered_class_builds_its_recorded_key(self):
        cases = {
            "register-entry": ({"id": "SEC-1"}, "SEC-1"),
            "primitive-name": ({"name": "BN_mod_exp"}, "BN_mod_exp"),
            "normalised-text": ({"text": "  a   b\n"}, "a b"),
            "path-symbol-status": (
                {"path": "src/a.rs", "symbol": "f", "status": "S"},
                "src/a.rs::f::S",
            ),
            "path-symbol-class": (
                {"path": "src/a.rs", "symbol": "f", "class": "C"},
                "src/a.rs::f::C",
            ),
            "literal": ({"value": "verdict"}, "verdict"),
            "stable-id": ({"id": "OBL-1"}, "OBL-1"),
            "obligation-boundary-receipt": (
                {"obligation": "OBL-1", "boundary": "b", "receipt": "r"},
                "OBL-1::b::r",
            ),
            "dso-class-reason": (
                {"dso": "libcrypto.so.3", "class": "C", "reason": "R"},
                "libcrypto.so.3::C::R",
            ),
            "field-path": ({"json_path": "precision.verdict"}, "precision.verdict"),
            "refutation": (
                {"text": "a  b", "digest_chars": 16},
                "refutation::" + hashlib.sha256(b"a b").hexdigest()[:16],
            ),
            "mechanism": ({"name": "M"}, "mechanism::M"),
            "obligation-decision": (
                {"obligation": "OBL-1", "decision": "D"},
                "OBL-1::D",
            ),
        }
        for key_class, (fields, expected) in cases.items():
            with self.subTest(key_class=key_class):
                self.assertEqual(fi.logical_key(key_class, **fields), expected)

    def test_refutation_length_is_explicit_and_bounded(self):
        text = hashlib.sha256(b"a b").hexdigest()
        self.assertEqual(
            fi.logical_key("refutation", text="a b", digest_chars=64),
            "refutation::" + text,
        )
        for bad in (7, 65, "16", None):
            with self.subTest(digest_chars=bad):
                with self.assertRaises(fi.IdentityRefusal) as caught:
                    fi.logical_key("refutation", text="a b", digest_chars=bad)
                self.assertEqual(caught.exception.code, fi.FI_REFUSED_KEY_FIELD)

    def test_unknown_class_and_missing_field_are_refused(self):
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.logical_key("not-a-class", id="x")
        self.assertEqual(caught.exception.code, fi.FI_REFUSED_UNKNOWN_KEY_CLASS)
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.logical_key("register-entry")
        self.assertEqual(caught.exception.code, fi.FI_REFUSED_KEY_FIELD)


# --------------------------------------------------------------------------
# Bindings and regions
# --------------------------------------------------------------------------

class BindingTests(unittest.TestCase):
    def test_scope_names_the_algorithm(self):
        self.assertEqual(fi.Binding("x", DIGEST_A, "artifact").algorithm, "sha-256")
        self.assertEqual(
            fi.Binding("x", "a" * 40, "candidate-commit").algorithm, "sha1-git-object"
        )

    def test_scope_and_digest_form_must_agree(self):
        for scope, digest in (
            ("artifact", "a" * 40),
            ("candidate-commit", DIGEST_A),
            ("record", "a" * 40),
            ("source-tree", "a" * 7),
        ):
            with self.subTest(scope=scope, digest=digest):
                with self.assertRaises(fi.IdentityRefusal) as caught:
                    fi.Binding("x", digest, scope)
                self.assertEqual(caught.exception.code, fi.FI_REFUSED_SCOPE_ALGORITHM)
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.Binding("x", DIGEST_A, "somewhere")
        self.assertEqual(caught.exception.code, fi.FI_REFUSED_UNKNOWN_SCOPE)

    def test_region_precedence_is_line_then_offset_then_locator(self):
        self.assertEqual(
            fi.Region.from_native(
                path="a.rs", line=4, byte_offset=8, address=8, locator="l"
            ).key(),
            "line=4",
        )
        self.assertEqual(
            fi.Region.from_native(
                path="a.rs", line=None, byte_offset=8, address=9, locator="l"
            ).key(),
            "byteOffset=8;address=9",
        )
        self.assertEqual(
            fi.Region.from_native(
                path="a.rs", line=None, byte_offset=None, address=None, locator="l"
            ).key(),
            "locator=l",
        )

    def test_digest_and_token_classification(self):
        self.assertEqual(fi.digest_algorithm(DIGEST_A), "sha-256")
        self.assertEqual(fi.digest_algorithm("a" * 40), "sha1-git-object")
        for bad in ("a" * 7, "A" * 64, "", None):
            with self.subTest(value=bad):
                with self.assertRaises(fi.IdentityRefusal):
                    fi.digest_algorithm(bad)
        self.assertTrue(fi.is_git_identity_token("a" * 40))
        self.assertTrue(fi.is_git_identity_token("a" * 7))
        self.assertFalse(fi.is_git_identity_token(DIGEST_A))
        self.assertFalse(fi.is_git_identity_token("a" * 6))


# --------------------------------------------------------------------------
# Code motion
# --------------------------------------------------------------------------

class CodeMotionTests(unittest.TestCase):
    def _verdict(self, before, after):
        return fi.classify_motion(before, after)

    def test_moved_within_file_preserves_logical_changes_exact(self):
        before = _finding(line=10)
        after = _finding(line=90)
        verdict = self._verdict(before, after)
        self.assertTrue(verdict.logical_preserved)
        self.assertFalse(verdict.exact_preserved)
        self.assertEqual(verdict.relation, fi.RELATION_LOCATION_MOVED)

    def test_moved_to_another_file_changes_a_path_keyed_logical_identity(self):
        before = _finding(uri="src/a.rs")
        after = _finding(uri="src/b.rs")
        verdict = self._verdict(before, after)
        self.assertFalse(verdict.logical_preserved)
        self.assertEqual(verdict.relation, fi.RELATION_LOGICAL_KEY_CHANGED)

    def test_moved_to_another_file_preserves_a_location_independent_key(self):
        before = _finding(key_class="register-entry")
        after = _finding(key_class="register-entry", uri="src/b.rs")
        verdict = self._verdict(before, after)
        self.assertTrue(verdict.logical_preserved)
        self.assertFalse(verdict.exact_preserved)
        self.assertEqual(verdict.relation, fi.RELATION_SUBJECT_CHANGED)

    def test_rename_changes_a_path_and_symbol_keyed_logical_identity(self):
        before = _finding(line=10)
        after = _finding(line=10, symbol="g")
        verdict = self._verdict(before, after)
        self.assertFalse(verdict.logical_preserved)
        self.assertEqual(verdict.relation, fi.RELATION_LOGICAL_KEY_CHANGED)

    def test_reformat_preserves_logical_and_changes_exact(self):
        before = _finding(digest=DIGEST_A)
        after = _finding(digest=DIGEST_B)
        verdict = self._verdict(before, after)
        self.assertTrue(verdict.logical_preserved)
        self.assertFalse(verdict.exact_preserved)
        self.assertEqual(verdict.relation, fi.RELATION_ARTEFACT_BYTES_CHANGED)

    def test_insertion_and_deletion_above_preserve_logical(self):
        for delta in (14, -14):
            with self.subTest(delta=delta):
                verdict = self._verdict(_finding(line=40), _finding(line=40 + delta))
                self.assertTrue(verdict.logical_preserved)
                self.assertEqual(verdict.relation, fi.RELATION_LOCATION_MOVED)

    def test_file_split_and_merge_change_a_path_keyed_logical_identity(self):
        for target in ("src/a_part.rs", "src/merged.rs"):
            with self.subTest(target=target):
                verdict = self._verdict(_finding(uri="src/a.rs"), _finding(uri=target))
                self.assertFalse(verdict.logical_preserved)
                self.assertEqual(verdict.relation, fi.RELATION_LOGICAL_KEY_CHANGED)

    def test_unchanged_finding_keeps_both_identities(self):
        verdict = self._verdict(_finding(), _finding())
        self.assertTrue(verdict.logical_preserved)
        self.assertTrue(verdict.exact_preserved)
        self.assertEqual(verdict.relation, fi.RELATION_UNCHANGED)

    def test_unjustified_preservation_is_refused(self):
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.require_preservation(_finding(uri="src/a.rs"), _finding(uri="src/b.rs"))
        self.assertEqual(
            caught.exception.code, fi.FI_REFUSED_UNJUSTIFIED_PRESERVATION
        )

    def test_a_different_rule_is_never_the_same_finding(self):
        verdict = self._verdict(_finding(rule="A1-A"), _finding(rule="A1-B"))
        self.assertFalse(verdict.logical_preserved)
        self.assertEqual(verdict.relation, fi.RELATION_DIFFERENT_RULE)


# --------------------------------------------------------------------------
# Collisions
# --------------------------------------------------------------------------

class CollisionTests(unittest.TestCase):
    def _pair(self):
        first = _finding(
            key_class="register-entry",
            uri="src/c.rs",
            line=30,
            locator="entries[0]",
        )
        second = _finding(
            key_class="register-entry",
            uri="src/d.rs",
            line=40,
            locator="entries[1]",
        )
        return first, second

    def test_a_logical_collision_is_a_set_of_every_member(self):
        first, second = self._pair()
        report = fi.collision_report([first, second], "logical")
        self.assertEqual(report["collisionCount"], 1)
        self.assertEqual(report["groups"][0]["count"], 2)
        self.assertEqual(
            len(report["groups"][0]["members"]), 2, "no member is merged or dropped"
        )
        self.assertEqual(report["population"], 2)
        self.assertEqual(fi.collision_report([first, second], "exact")["collisionCount"], 0)

    def test_ambiguous_attribution_is_refused(self):
        first, second = self._pair()
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.attribute([first, second], first.logical_fingerprint, "logical")
        self.assertEqual(caught.exception.code, fi.FI_REFUSED_AMBIGUOUS_ATTRIBUTION)

    def test_a_discriminator_resolves_only_when_one_member_remains(self):
        first, second = self._pair()
        resolved = fi.attribute(
            [first, second],
            first.logical_fingerprint,
            "logical",
            discriminator=lambda f: f.binding.uri == "src/c.rs",
        )
        self.assertEqual(resolved.binding.uri, "src/c.rs")
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.attribute(
                [first, second],
                first.logical_fingerprint,
                "logical",
                discriminator=lambda f: True,
            )
        self.assertEqual(caught.exception.code, fi.FI_REFUSED_AMBIGUOUS_ATTRIBUTION)
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.attribute(
                [first, second],
                first.logical_fingerprint,
                "logical",
                discriminator=lambda f: f.binding.uri == "src/z.rs",
            )
        self.assertEqual(caught.exception.code, fi.FI_REFUSED_UNKNOWN_IDENTITY)

    def test_unknown_fingerprint_is_refused(self):
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.attribute([_finding()], "0" * 64, "logical")
        self.assertEqual(caught.exception.code, fi.FI_REFUSED_UNKNOWN_IDENTITY)


# --------------------------------------------------------------------------
# Reuse across artefacts, candidates and time
# --------------------------------------------------------------------------

class ReuseTests(unittest.TestCase):
    def test_exact_reuse_across_artefacts_is_refused(self):
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.relate(_finding(uri="src/a.rs"), _finding(uri="src/b.rs"), "same-occurrence")
        self.assertEqual(caught.exception.code, fi.FI_REFUSED_CROSS_ARTEFACT_REUSE)

    def test_exact_reuse_across_candidates_is_refused(self):
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.relate(
                _finding(candidate=CANDIDATE_A),
                _finding(candidate=CANDIDATE_B),
                "same-occurrence",
            )
        self.assertEqual(caught.exception.code, fi.FI_REFUSED_CROSS_CANDIDATE_REUSE)

    def test_same_occurrence_permits_exact_scope(self):
        permit = fi.relate(_finding(), _finding(), "same-occurrence")
        self.assertEqual(permit.scope, fi.SCOPE_EXACT)
        self.assertTrue(permit.authorises_exact_reuse)
        self.assertTrue(fi.permits_reuse(_finding(), _finding(), "same-occurrence"))

    def test_logical_match_does_not_authorise_exact_reuse(self):
        permit = fi.relate(
            _finding(digest=DIGEST_A), _finding(digest=DIGEST_B), "same-logical-finding"
        )
        self.assertEqual(permit.scope, fi.SCOPE_LOGICAL)
        self.assertFalse(permit.authorises_exact_reuse)
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.authorise_scope(permit, fi.SCOPE_EXACT)
        self.assertEqual(
            caught.exception.code, fi.FI_REFUSED_INSUFFICIENT_RELATIONSHIP
        )

    def test_logical_match_across_candidates_keeps_its_scope(self):
        permit = fi.relate(
            _finding(candidate=CANDIDATE_A),
            _finding(candidate=CANDIDATE_B),
            "same-logical-finding",
        )
        self.assertTrue(permit.cross_candidate)
        self.assertFalse(permit.authorises_exact_reuse)

    def test_code_motion_permits_logical_scope_only(self):
        permit = fi.relate(_finding(line=10), _finding(line=90), "code-motion")
        self.assertEqual(permit.scope, fi.SCOPE_LOGICAL)
        self.assertFalse(permit.authorises_exact_reuse)
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.relate(_finding(), _finding(), "code-motion")
        self.assertEqual(caught.exception.code, fi.FI_REFUSED_NOT_CODE_MOTION)

    def test_code_motion_does_not_cover_a_changed_key(self):
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.relate(_finding(uri="src/a.rs"), _finding(uri="src/b.rs"), "code-motion")
        self.assertEqual(caught.exception.code, fi.FI_REFUSED_NOT_CODE_MOTION)

    def test_a_logical_identity_does_not_authorise_a_claim_about_another_artefact(
        self,
    ):
        left = _finding(key_class="register-entry", uri="src/a.rs")
        right = _finding(key_class="register-entry", uri="src/b.rs")
        permit = fi.relate(left, right, "same-logical-finding")
        fi.authorise_about(permit, left, left.binding)
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.authorise_about(permit, left, right.binding)
        self.assertEqual(caught.exception.code, fi.FI_REFUSED_CROSS_ARTEFACT_REUSE)
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.authorise_about(fi.relate(left, left, "distinct"), left, left.binding)
        self.assertEqual(
            caught.exception.code, fi.FI_REFUSED_INSUFFICIENT_RELATIONSHIP
        )

    def test_an_unstated_relationship_is_refused(self):
        with self.assertRaises(fi.IdentityRefusal) as caught:
            fi.relate(_finding(), _finding(), "looks-the-same")
        self.assertEqual(caught.exception.code, fi.FI_REFUSED_UNSTATED_RELATIONSHIP)

    def test_distinct_claims_no_transfer(self):
        permit = fi.relate(_finding(), _finding(), "distinct")
        self.assertEqual(permit.scope, fi.SCOPE_NONE)
        self.assertFalse(permit.authorises_exact_reuse)


# --------------------------------------------------------------------------
# Positional identities
# --------------------------------------------------------------------------

class PositionalIdentityTests(unittest.TestCase):
    def test_recorded_text_and_portability(self):
        row = fi.row_identity("src/a.rs", 10, "op")
        self.assertEqual(row.text, "src/a.rs:10:op")
        self.assertFalse(row.portable)
        self.assertTrue(row.includes_location)
        self.assertEqual(fi.site_identity("libcrypto.so.3", "f", "10").text,
                         "libcrypto.so.3:f:10")
        self.assertEqual(fi.target_identity("e", "t").text, "e#target=t")


# --------------------------------------------------------------------------
# The four consumers use the model
# --------------------------------------------------------------------------

class ConsumerTests(unittest.TestCase):
    def test_claim_algebra_uses_the_model_canonicaliser(self):
        value = {"b": 1, "a": [2, 3]}
        self.assertEqual(etp_claims.canonical(value), fi.canonical_json(value))

    def test_claim_algebra_refuses_a_commit_id_recorded_as_file_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "docs/x.md").write_text("x", encoding="utf-8")
            doc = {
                "source_identity": {"commit": "a" * 40},
                "claims": [
                    {
                        "evidence": [
                            {
                                "path": "docs/x.md",
                                "sha256": "b" * 40,
                                "digest_identity": "E",
                            }
                        ]
                    }
                ],
            }
            refusals = etp_claims.check_evidence_tree(doc, root)
            self.assertEqual(
                [refusal["rule"] for refusal in refusals],
                ["EG_EVIDENCE_DIGEST_FORM"],
            )

    def test_closure_discipline_uses_the_model_digest_and_identities(self):
        self.assertEqual(closure_discipline.sha256_bytes(b"x"), fi.digest_bytes(b"x"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f"
            path.write_bytes(b"bytes")
            self.assertEqual(closure_discipline.file_sha256(path), fi.digest_file(path))

    def test_freshness_uses_the_model_token_rule(self):
        self.assertEqual(freshness.sha256_bytes(b"x"), fi.digest_bytes(b"x"))
        self.assertEqual(freshness.sha256_hex("x"), fi.digest_bytes(b"x"))
        self.assertEqual(freshness._hex_strings("a" * 40), ["a" * 40])
        self.assertEqual(freshness._hex_strings("a" * 7), ["a" * 7])
        self.assertEqual(freshness._hex_strings(DIGEST_A), [])

    def test_adapter_has_no_private_fingerprint_or_region_function(self):
        for name in ("_fingerprint", "_region_key", "_normalise_text"):
            self.assertFalse(hasattr(adapter, name), f"adapter still carries {name}")

    def test_adapter_recomputes_every_recorded_fingerprint(self):
        document = json.loads(A1_SARIF.read_text(encoding="utf-8"))
        verified = 0
        for run in document["runs"]:
            for result in run["results"]:
                identity = adapter.identity_from_result(result)
                self.assertEqual(identity.fingerprints, result["partialFingerprints"])
                verified += 1
        self.assertEqual(verified, 4245)

    def test_adapter_refuses_a_tampered_recorded_fingerprint(self):
        document = json.loads(A1_SARIF.read_text(encoding="utf-8"))
        result = document["runs"][0]["results"][0]
        result["partialFingerprints"][fi.WIRE_KEYS["logical"]] = "0" * 64
        with self.assertRaises(fi.IdentityRefusal) as caught:
            adapter.identity_from_result(result)
        self.assertEqual(
            caught.exception.code, fi.FI_REFUSED_RECORDED_FINGERPRINT_MISMATCH
        )


# --------------------------------------------------------------------------
# Deliverable hygiene
# --------------------------------------------------------------------------

class DeliverableTests(unittest.TestCase):
    def test_no_first_person_in_a3_deliverables(self):
        first_person = re.compile(
            r"\b(I|We|Our|My|Mine|Ours|Me|Us|we|our|my|mine|ours|me|us)\b"
        )
        paths = [
            REPO_ROOT / "docs" / "FINDING-IDENTITY.md",
            REPO_ROOT / "forensics" / "tools" / "finding_identity.py",
            REPO_ROOT / "evidence" / "a3" / "build_evidence.py",
            REPO_ROOT / "evidence" / "a3" / "RECEIPT.md",
        ]
        for path in paths:
            if not path.exists():
                continue
            with self.subTest(path=str(path)):
                self.assertEqual(
                    first_person.findall(path.read_text(encoding="utf-8")), []
                )

    def test_evidence_json_is_well_formed(self):
        for name in ("CODE-MOTION.json", "COLLISIONS.json", "MIGRATION.json"):
            path = REPO_ROOT / "evidence" / "a3" / name
            if not path.exists():
                continue
            with self.subTest(document=name):
                document = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(document["model"], fi.MODEL_ID)


if __name__ == "__main__":
    unittest.main(verbosity=2)
