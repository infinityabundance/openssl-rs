#!/usr/bin/env python3
"""Tests for forensics/tools/freshness.py (ETP-T9).

Run directly (`python3 forensics/tools/tests/test_freshness.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.

Each control builds a throwaway Git repository, commits a known tree, and then
changes exactly one thing. The controls are the eight required by the item plus
the ones that make the interesting refusals reachable:

  1. a changed dependency invalidates the artefact that names it;
  2. a comment-only change to a file the artefact does not name does not;
  3. an unprovable non-impact argument is refused, not accepted;
  4. a stale artefact carried with no declaration is refused;
  5. an artefact declared explicit history is accepted, and its exclusion from
     current claims is enforced;
  6. a preservation argument that assumes a touched dependency is refused;
  7. invalidation travels through the claim algebra's dependency edges;
  8. the same inputs produce byte-identical output.

The positive control for the preservation machinery is `comment_only`: an
argument that a change is comment-only is *executed*, not read, so a working
procedure must be able to carry an artefact forward as well as refuse one.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import freshness  # noqa: E402


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Fixture:
    """A throwaway repository with a small, readable tree."""

    files = {
        "src/unit.rs": "pub fn f() -> u8 {\n    1\n}\n",
        "src/other.rs": "pub fn g() -> u8 {\n    2\n}\n",
        "docs/NOTES.md": "notes\n",
        "evidence/a.json": "{\n  \"kind\": \"receipt\"\n}\n",
        "evidence/b.json": "{\n  \"kind\": \"receipt\"\n}\n",
        "evidence/notes.md": "a prose receipt\n",
    }

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "repo"
        self.root.mkdir(parents=True)
        self.git = freshness.Git(self.root)
        self._run("init", "-q", "-b", "main")
        for relpath, text in self.files.items():
            self.write(relpath, text)
        self.base = self.commit("initial tree")

    def close(self) -> None:
        self._tmp.cleanup()

    def _run(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                "git",
                "-c",
                "user.name=etp-t9",
                "-c",
                "user.email=etp-t9@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-C",
                str(self.root),
                *args,
            ],
            capture_output=True,
            check=False,
        )

    def write(self, relpath: str, text: str) -> None:
        path = self.root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def commit(self, message: str) -> str:
        self._run("add", "-A")
        self._run("commit", "-q", "-m", message)
        return self.git.head() or ""

    def digest(self, relpath: str, commit: str | None = None) -> str:
        value = self.git.digest(commit or (self.git.head() or ""), relpath)
        return value or ""


def artefact(fixture: Fixture, relpath: str, deps: list[dict[str, Any]], identity: str | None = None) -> dict[str, Any]:
    commit = fixture.git.head() or ""
    return {
        "path": relpath,
        "kind": "record",
        "sha256": fixture.digest(relpath),
        "identity": {
            "commit": identity,
            "kind": "structured" if identity else "none",
            "ambiguous": False,
            "all": [],
            "upstream": [],
            "note": None,
        },
        "provenance": {"last_commit": commit, "basis": "test"},
        "depends_on": deps,
        "citations": [],
        "claim_ids": [],
        "derivation": {},
    }


def registry(artefacts: list[dict[str, Any]], declarations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "schema": freshness.SCHEMA,
        "kind": "evidence-dependency-registry",
        "item": "ETP-T9",
        "artefacts": artefacts,
        "declarations": declarations or [],
    }


def claim(
    claim_id: str,
    verdict: str = "ESTABLISHED",
    evidence: list[str] | None = None,
    depends_on: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": claim_id,
        "property": "documentary",
        "scope": {"kind": "documentation", "subject": claim_id, "locations": []},
        "identity": {"source": {"commit": None, "candidate": None, "tree_sha256": None}, "artefacts": []},
        "evidence": [{"id": f"EV-{index}", "path": path} for index, path in enumerate(evidence or [])],
        "invalidation": {
            "depends_on": [{"kind": "claim", "id": other} for other in (depends_on or [])],
        },
        "verdict": {"state": verdict},
    }


def rules(payload: dict[str, Any]) -> list[str]:
    return [item["rule"] for item in payload.get("refusals", [])]


def verdict_of(payload: dict[str, Any], relpath: str) -> str | None:
    for record in payload["artefacts"]["records"]:
        if record["path"] == relpath:
            return record["verdict"]
    if relpath in payload["artefacts"].get("unaffected", {}).get("dependency_counts", {}):
        return "UNAFFECTED"
    if relpath in payload["artefacts"].get("unmodelled", {}).get("paths", []):
        return "UNMODELLED"
    return None


class FreshnessControls(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = Fixture()

    def tearDown(self) -> None:
        self.fx.close()

    # -- helpers ---------------------------------------------------------

    def evaluate(
        self,
        artefacts: list[dict[str, Any]],
        declarations: list[dict[str, Any]] | None = None,
        claims: list[dict[str, Any]] | None = None,
        base: str | None = None,
        head: str | None = None,
    ) -> dict[str, Any]:
        head = head or self.fx.git.head() or ""
        base = base or self.fx.base
        changed = self.fx.git.changed(base, head)
        return freshness.evaluate(
            self.fx.git,
            registry(artefacts, declarations),
            {"claims": claims or []},
            changed,
            base,
            head,
        )

    def change_unit_comment_only(self) -> str:
        """Change `src/unit.rs` by adding a comment line."""
        self.fx.write("src/unit.rs", "// a comment\npub fn f() -> u8 {\n    1\n}\n")
        return self.fx.commit("comment only")

    def change_other_comment_only(self) -> str:
        self.fx.write("src/other.rs", "// unrelated note\npub fn g() -> u8 {\n    2\n}\n")
        return self.fx.commit("unrelated comment only")

    def change_unit_code(self) -> str:
        self.fx.write("src/unit.rs", "pub fn f() -> u8 {\n    3\n}\n")
        return self.fx.commit("behaviour change")

    def preservation(self, **overrides: Any) -> dict[str, Any]:
        declaration = {
            "artefact": "evidence/a.json",
            "kind": "PRESERVATION",
            "argument": "the change adds a comment line to the measured unit and alters no code",
            "procedure": "comment_only",
            "concerned_paths": ["src/unit.rs"],
            "assumes_unchanged": ["src/other.rs"],
            "evidence": [{"path": "evidence/a.json", "sha256": self.fx.digest("evidence/a.json")}],
        }
        declaration.update(overrides)
        return declaration

    # -- 1. a changed dependency invalidates -----------------------------

    def test_changed_dependency_invalidates(self) -> None:
        head = self.change_unit_code()
        payload = self.evaluate(
            [artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}])],
            head=head,
        )
        self.assertEqual(verdict_of(payload, "evidence/a.json"), "INVALIDATED")
        self.assertIn("FR_EVIDENCE_INVALIDATED", rules(payload))
        self.assertEqual(payload["status"], "REFUSED")

    def test_unmentioned_file_does_not_invalidate(self) -> None:
        head = self.change_unit_code()
        payload = self.evaluate(
            [artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/other.rs"}])],
            head=head,
        )
        self.assertEqual(verdict_of(payload, "evidence/a.json"), "UNAFFECTED")
        self.assertEqual(payload["refusals"], [])
        self.assertEqual(payload["artefacts"]["unaffected"]["count"], 1)

    # -- 2. a comment-only change to an unconcerned file does not --------

    def test_comment_only_change_to_unconcerned_file_does_not_invalidate(self) -> None:
        head = self.change_other_comment_only()
        payload = self.evaluate(
            [artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}])],
            head=head,
        )
        self.assertEqual(verdict_of(payload, "evidence/a.json"), "UNAFFECTED")
        self.assertEqual(payload["refusals"], [])

    # -- 3. an unprovable non-impact invalidates ------------------------

    def test_unprovable_preservation_is_refused(self) -> None:
        head = self.change_unit_code()
        declaration = self.preservation(procedure="no test covers this path")
        payload = self.evaluate(
            [artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}])],
            [declaration],
            head=head,
        )
        self.assertEqual(verdict_of(payload, "evidence/a.json"), "INVALIDATED")
        self.assertIn("FR_PRESERVATION_UNDECIDABLE", rules(payload))
        self.assertEqual(payload["status"], "REFUSED")

    def test_empty_argument_is_refused(self) -> None:
        head = self.change_unit_code()
        declaration = self.preservation(argument="")
        payload = self.evaluate(
            [artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}])],
            [declaration],
            head=head,
        )
        self.assertIn("FR_PRESERVATION_INCOMPLETE", rules(payload))

    def test_preservation_without_its_own_evidence_is_refused(self) -> None:
        head = self.change_unit_code()
        declaration = self.preservation(evidence=[{"path": "evidence/a.json", "sha256": "0" * 64}])
        payload = self.evaluate(
            [artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}])],
            [declaration],
            head=head,
        )
        self.assertIn("FR_PRESERVATION_UNEVIDENCED", rules(payload))

    # -- 4. a stale carried-forward artefact is refused -----------------

    def test_stale_artefact_with_no_declaration_is_refused_in_the_tree(self) -> None:
        base = self.fx.base
        self.change_unit_code()
        head = self.fx.git.head() or ""
        artefacts = [
            artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}], identity=base)
        ]
        payload = freshness._tree_sweep(
            self.fx.git, registry(artefacts), {"claims": []}, head
        )
        self.assertIn("FR_CARRY_FORWARD_UNDECLARED", rules(payload))
        record = payload["artefacts"]["records"][0]
        self.assertEqual(record["verdict"], "INVALIDATED")
        self.assertEqual(payload["status"], "REFUSED")

    # -- 5. explicit history is accepted --------------------------------

    def test_explicit_history_is_accepted(self) -> None:
        base = self.fx.base
        head = self.change_unit_code()
        declarations = [
            {
                "artefact": "evidence/a.json",
                "kind": "HISTORY",
                "identity": {"commit": base},
                "basis": "the receipt is the record of that tree and of no later one",
            }
        ]
        payload = self.evaluate(
            [artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}], identity=base)],
            declarations,
            head=head,
        )
        self.assertEqual(verdict_of(payload, "evidence/a.json"), "HISTORY")
        self.assertEqual(payload["refusals"], [])
        self.assertEqual(payload["status"], "PASS")

    def test_explicit_history_cited_as_current_is_refused(self) -> None:
        base = self.fx.base
        head = self.change_unit_code()
        declarations = [
            {"artefact": "evidence/a.json", "kind": "HISTORY", "identity": {"commit": base}, "basis": "historical"}
        ]
        artefacts = [
            artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}], identity=base)
        ]
        change_set = self.evaluate(
            artefacts,
            declarations,
            claims=[claim("C-1", evidence=["evidence/a.json"])],
            head=head,
        )
        # A declaration plus a citing claim is a state of the tree, not a
        # consequence of the change set: it is reported, and the tree sweep is
        # where it refuses.
        self.assertTrue(change_set["claims"]["history_cited_as_current"])
        tree = freshness._tree_sweep(
            self.fx.git,
            registry(artefacts, declarations),
            {"claims": [claim("C-1", evidence=["evidence/a.json"])]},
            head,
        )
        self.assertIn("FR_HISTORY_CITED_AS_CURRENT", rules(tree))
        self.assertEqual(tree["status"], "REFUSED")

    def test_history_cited_by_a_withdrawn_claim_is_not_refused(self) -> None:
        base = self.fx.base
        head = self.change_unit_code()
        declarations = [
            {"artefact": "evidence/a.json", "kind": "HISTORY", "identity": {"commit": base}, "basis": "historical"}
        ]
        payload = self.evaluate(
            [artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}], identity=base)],
            declarations,
            claims=[claim("C-1", verdict="WITHDRAWN", evidence=["evidence/a.json"])],
            head=head,
        )
        self.assertNotIn("FR_HISTORY_CITED_AS_CURRENT", rules(payload))

    # -- 6. a preservation argument naming a touched dependency ---------

    def test_preservation_assuming_a_touched_dependency_is_refused(self) -> None:
        head = self.change_unit_code()
        declaration = self.preservation(assumes_unchanged=["src/unit.rs"])
        payload = self.evaluate(
            [artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}])],
            [declaration],
            head=head,
        )
        self.assertIn("FR_PRESERVATION_TOUCHED", rules(payload))
        self.assertEqual(verdict_of(payload, "evidence/a.json"), "INVALIDATED")

    def test_preservation_about_a_non_dependency_is_refused(self) -> None:
        head = self.change_unit_code()
        declaration = self.preservation(concerned_paths=["docs/NOTES.md"])
        payload = self.evaluate(
            [artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}])],
            [declaration],
            head=head,
        )
        self.assertIn("FR_PRESERVATION_INCOMPLETE", rules(payload))

    # -- positive control: the procedure executes and carries forward ----

    def test_comment_only_procedure_carries_the_artefact_forward(self) -> None:
        head = self.change_unit_comment_only()
        payload = self.evaluate(
            [
                artefact(
                    self.fx,
                    "evidence/a.json",
                    [
                        {"kind": "path", "id": "src/unit.rs"},
                        {"kind": "path", "id": "src/other.rs"},
                    ],
                )
            ],
            [self.preservation()],
            head=head,
        )
        self.assertEqual(verdict_of(payload, "evidence/a.json"), "CARRIED_FORWARD")
        self.assertEqual(payload["status"], "PASS")

    def test_comment_only_procedure_refuses_a_code_change(self) -> None:
        head = self.change_unit_code()
        payload = self.evaluate(
            [
                artefact(
                    self.fx,
                    "evidence/a.json",
                    [
                        {"kind": "path", "id": "src/unit.rs"},
                        {"kind": "path", "id": "src/other.rs"},
                    ],
                )
            ],
            [self.preservation()],
            head=head,
        )
        self.assertIn("FR_PRESERVATION_FAILED", rules(payload))
        self.assertEqual(verdict_of(payload, "evidence/a.json"), "INVALIDATED")

    def test_comment_only_refuses_a_file_with_a_raw_string(self) -> None:
        path = self.fx.root / "src/unit.rs"
        path.write_text('pub fn f() -> &\'static str { r#"a\n// b"# }\n', encoding="utf-8")
        self.fx.commit("raw string")
        head = self.fx.git.head() or ""
        payload = self.evaluate(
            [
                artefact(
                    self.fx,
                    "evidence/a.json",
                    [
                        {"kind": "path", "id": "src/unit.rs"},
                        {"kind": "path", "id": "src/other.rs"},
                    ],
                )
            ],
            [self.preservation()],
            head=head,
        )
        self.assertIn("FR_PRESERVATION_UNDECIDABLE", rules(payload))

    # -- 7. transitive invalidation through a claim ---------------------

    def test_invalidation_travels_through_the_claim_edges(self) -> None:
        head = self.change_unit_code()
        claims = [
            claim("C-1", evidence=["evidence/a.json"]),
            claim("C-2", depends_on=["C-1"]),
        ]
        payload = self.evaluate(
            [artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}])],
            claims=claims,
            head=head,
        )
        self.assertIn("C-1", payload["claims"]["algebra_invalidated"])
        self.assertIn("C-2", payload["claims"]["algebra_transitive_only"])
        refused = {item["where"] for item in payload["refusals"]}
        self.assertIn("C-1", refused)
        self.assertIn("C-2", refused)

    def test_transitive_invalidation_through_upstream_evidence(self) -> None:
        head = self.change_unit_code()
        artefacts = [
            artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}]),
            artefact(self.fx, "evidence/b.json", [{"kind": "upstream_evidence", "id": "evidence/a.json"}]),
        ]
        payload = self.evaluate(artefacts, head=head)
        self.assertEqual(verdict_of(payload, "evidence/a.json"), "INVALIDATED")
        self.assertEqual(verdict_of(payload, "evidence/b.json"), "INVALIDATED")
        self.assertIn("FR_EVIDENCE_TRANSITIVE", rules(payload))

    def test_an_unrelated_upstream_stays_current(self) -> None:
        head = self.change_unit_code()
        artefacts = [
            artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/other.rs"}]),
            artefact(self.fx, "evidence/b.json", [{"kind": "upstream_evidence", "id": "evidence/a.json"}]),
        ]
        payload = self.evaluate(artefacts, head=head)
        self.assertEqual(verdict_of(payload, "evidence/b.json"), "UNAFFECTED")

    # -- 8. determinism --------------------------------------------------

    def test_output_is_byte_identical(self) -> None:
        head = self.change_unit_code()
        artefacts = [artefact(self.fx, "evidence/a.json", [{"kind": "path", "id": "src/unit.rs"}])]
        first = freshness.dump_json(self.evaluate(artefacts, head=head))
        second = freshness.dump_json(self.evaluate(artefacts, head=head))
        self.assertEqual(first, second)

    def test_record_is_byte_identical(self) -> None:
        first = freshness.dump_json(freshness.derive(self.fx.git, self.fx.base))
        second = freshness.dump_json(freshness.derive(self.fx.git, self.fx.base))
        self.assertEqual(first, second)

    # -- refusals about the model itself ---------------------------------

    def test_dependency_cycle_is_refused(self) -> None:
        artefacts = [
            artefact(self.fx, "evidence/a.json", [{"kind": "upstream_evidence", "id": "evidence/b.json"}]),
            artefact(self.fx, "evidence/b.json", [{"kind": "upstream_evidence", "id": "evidence/a.json"}]),
        ]
        findings = freshness.validate_registry(self.fx.git, registry(artefacts), self.fx.base)
        self.assertIn("FR_DEPENDENCY_CYCLE", [item.rule for item in findings])

    def test_unknown_dependency_kind_is_refused(self) -> None:
        artefacts = [artefact(self.fx, "evidence/a.json", [{"kind": "vibes", "id": "src/unit.rs"}])]
        findings = freshness.validate_registry(self.fx.git, registry(artefacts), self.fx.base)
        self.assertIn("FR_UNKNOWN_DEPENDENCY_KIND", [item.rule for item in findings])

    def test_duplicate_artefact_is_refused(self) -> None:
        one = artefact(self.fx, "evidence/a.json", [])
        findings = freshness.validate_registry(self.fx.git, registry([one, dict(one)]), self.fx.base)
        self.assertIn("FR_DUPLICATE_ARTEFACT", [item.rule for item in findings])

    def test_unresolved_tool_digest_is_unresolved_not_unaffected(self) -> None:
        artefacts = [
            artefact(
                self.fx,
                "evidence/a.json",
                [{"kind": "verification_tool", "id": "src/unit.rs", "sha256": "UNKNOWN", "controls": []}],
            )
        ]
        payload = self.evaluate(artefacts, head=self.change_other_comment_only())
        self.assertEqual(verdict_of(payload, "evidence/a.json"), "UNRESOLVED")

    def test_absent_dependency_is_unresolved(self) -> None:
        artefacts = [
            artefact(
                self.fx,
                "evidence/a.json",
                [{"kind": "path", "id": "court/tmp/never-tracked.log", "present": False}],
            )
        ]
        payload = self.evaluate(artefacts, head=self.change_other_comment_only())
        self.assertEqual(verdict_of(payload, "evidence/a.json"), "UNRESOLVED")

    def test_missing_identity_is_unresolved_in_the_tree(self) -> None:
        artefacts = [artefact(self.fx, "evidence/notes.md", [])]
        payload = freshness._tree_sweep(
            self.fx.git, registry(artefacts), {"claims": []}, self.fx.git.head() or ""
        )
        self.assertIn("FR_IDENTITY_UNKNOWN", rules(payload))

    def test_artefact_with_no_dependency_is_not_reported_unaffected(self) -> None:
        payload = self.evaluate([artefact(self.fx, "evidence/a.json", [])])
        self.assertEqual(verdict_of(payload, "evidence/a.json"), "UNMODELLED")
        self.assertIn("evidence/a.json", payload["artefacts"]["unmodelled"]["paths"])

    def test_a_path_list_cannot_execute_a_preservation_procedure(self) -> None:
        refusal = freshness._preservation_check(
            self.fx.git,
            self.preservation() | {"artefact": "evidence/a.json"},
            None,
            self.fx.git.head() or "",
            [{"path": "src/unit.rs", "status": "M"}],
            [{"kind": "path", "id": "src/unit.rs"}, {"kind": "path", "id": "src/other.rs"}],
        )
        assert refusal is not None
        self.assertEqual(refusal.rule, "FR_PRESERVATION_UNDECIDABLE")

    # -- derivation ------------------------------------------------------

    def test_derive_records_identity_only_for_artefacts_that_name_one(self) -> None:
        self.fx.write(
            "evidence/bound.json",
            json.dumps({"source_identity": {"repository_head": self.fx.base}}),
        )
        self.fx.commit("add a bound record")
        document = freshness.derive(self.fx.git, self.fx.git.head() or "")
        by_path = {item["path"]: item for item in document["artefacts"]}
        self.assertEqual(by_path["evidence/bound.json"]["identity"]["commit"], self.fx.base)
        self.assertIsNone(by_path["evidence/a.json"]["identity"]["commit"])
        kinds = {item["kind"] for item in by_path["evidence/bound.json"]["depends_on"]}
        self.assertIn("source_tree", kinds)
        self.assertNotIn("source_tree", {item["kind"] for item in by_path["evidence/a.json"]["depends_on"]})

    def test_derive_excludes_normative_documents_from_the_population(self) -> None:
        self.fx.write(
            "evidence/etp/claims.json",
            json.dumps({"claims": [claim("C-1", evidence=["docs/NOTES.md"])]}),
        )
        self.fx.commit("a claim that cites a document")
        document = freshness.derive(self.fx.git, self.fx.git.head() or "")
        paths = {item["path"] for item in document["artefacts"]}
        self.assertIn("evidence/a.json", paths)
        self.assertNotIn("docs/NOTES.md", paths)
        reasons = {item["path"]: item["reason"] for item in document["excluded"]}
        self.assertIn("docs/NOTES.md", reasons)
        self.assertIn("normative document", reasons["docs/NOTES.md"])

    def test_prose_citations_are_advisory(self) -> None:
        self.fx.write("evidence/notes.md", "see `src/unit.rs` and `court/tmp/missing.log`\n")
        self.fx.commit("prose citation")
        document = freshness.derive(self.fx.git, self.fx.git.head() or "")
        record = next(item for item in document["artefacts"] if item["path"] == "evidence/notes.md")
        cited = {item["path"]: item["present"] for item in record["citations"]}
        self.assertTrue(cited.get("src/unit.rs"))
        self.assertFalse(cited.get("court/tmp/missing.log"))
        self.assertEqual(record["depends_on"], [], "a prose mention must not become an authority")


class RegistryShape(unittest.TestCase):
    """The committed registry must satisfy the same structural rules."""

    def test_committed_registry_validates(self) -> None:
        path = Path(freshness.REGISTRY)
        if not path.exists():  # pragma: no cover - the registry is a deliverable
            self.skipTest("registry not recorded")
        document = freshness.load_json(path)
        repo = freshness.Git(freshness.REPO_ROOT)
        findings = freshness.validate_registry(repo, document, repo.head() or "")
        self.assertEqual([item.as_dict() for item in findings], [])
        self.assertEqual(document["schema"], freshness.SCHEMA)
        self.assertGreater(document["counts"]["artefacts"], 0)

    def test_committed_history_record_is_reproducible(self) -> None:
        path = Path(freshness.REPO_ROOT / "evidence/etp-t9/HISTORY-RUNS.json")
        if not path.exists():  # pragma: no cover - the history record is a deliverable
            self.skipTest("history record not recorded")
        document = freshness.load_json(path)
        self.assertEqual(document["schema"], freshness.HISTORY_SCHEMA)
        names = [run["name"] for run in document["runs"]]
        self.assertIn("evidence-only-change", names)
        only_evidence = next(run for run in document["runs"] if run["name"] == "evidence-only-change")
        self.assertEqual(only_evidence["status"], "PASS")
        self.assertEqual(only_evidence["refusals"], [])
        self.assertFalse(
            any(record["verdict"] == "INVALIDATED" for record in only_evidence["artefacts"]["records"])
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
