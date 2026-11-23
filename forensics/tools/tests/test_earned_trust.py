#!/usr/bin/env python3
"""Controls for the earned-trust constitution checker.

Each control constructs a tree in a temporary directory, mutates exactly one thing
and asserts the refusal the checker claims to make. The three controls the item
requires are named in `REQUIRED_CONTROLS`; the rest exist so that a checker which
refused everything, or nothing, cannot pass.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import earned_trust  # noqa: E402

REQUIRED_CONTROLS = (
    "test_cited_article_that_does_not_exist",
    "test_article_with_no_enforcement_and_no_declaration",
    "test_release_gate_cites_an_uncovered_article",
)

SPECS = [
    {
        "title": "A claim may never exceed its evidence",
        "tool": "forensics/tools/etp_claims.py",
        "rule": "EG_VERDICT_MODALITY",
        "why": "a claim can outrun the evidence bound to it.",
        "refused": "a verdict outruns its modality.",
        "not_established": "that the cited evidence is true.",
        "gate_items": ["gate-2"],
    },
    {
        "title": "Evidence is bound to an exact identity",
        "tool": "forensics/tools/freshness.py",
        "rule": "FR_EVIDENCE_SUPERSEDED",
        "why": "a record can drift off the identity it describes.",
        "refused": "the bytes differ from the recorded digest.",
        "not_established": "that the bound bytes were executed.",
        "gate_items": ["gate-1", "gate-2"],
    },
    {
        "title": "A third commitment",
        "tool": "forensics/tools/freshness.py",
        "rule": "FR_IDENTITY_UNKNOWN",
        "why": "a third failure mode, used by the coverage control.",
        "refused": "a third observable condition.",
        "not_established": "anything beyond the fixture.",
        "gate_items": [],
    },
]

GATE_ROWS = {
    "gate-1": [2],
    "gate-2": [1, 2],
}


def _article_block(number: int, spec: dict) -> str:
    return (
        f"### Article {number}. {spec['title']}\n\n"
        f"- **Why.** {spec['why']}\n"
        f"- **Enforced by.** `{spec['tool']}` — `{spec['rule']}`.\n"
        f"- **Refused when.** {spec['refused']}\n"
        f"- **Not established.** {spec['not_established']}\n"
    )


def build(root: Path, count: int = 2) -> None:
    """Write a consistent constitution, record, standard and gate table."""
    specs = SPECS[:count]
    doc = ["# Earned trust", "", "Status: control fixture.", "",
           "## 1. What this document is", "", "(fixture body)", ""]
    for number, spec in enumerate(specs, start=1):
        doc.append(_article_block(number, spec))
    (root / "docs").mkdir(parents=True, exist_ok=True)
    (root / "docs/EARNED-TRUST.md").write_text("\n".join(doc), encoding="utf-8")

    record = {
        "schema": earned_trust.SCHEMA,
        "document": earned_trust.DOC,
        "source_candidate": "0" * 40,
        "branch": "fixture",
        "gate_items": [
            {"id": "gate-1", "label": "candidate identity"},
            {"id": "gate-2", "label": "claim set"},
        ],
        "articles": [
            {
                "id": f"FIX-A{number:02d}",
                "number": number,
                "title": spec["title"],
                "declared_none": False,
                "enforcement": [{"tool": spec["tool"], "rule": spec["rule"]}],
                "refusals": [spec["rule"]],
                "gate_items": spec["gate_items"],
            }
            for number, spec in enumerate(specs, start=1)
        ],
    }
    (root / "evidence/etp-t14").mkdir(parents=True, exist_ok=True)
    (root / earned_trust.RECORD).write_text(json.dumps(record, indent=2) + "\n",
                                            encoding="utf-8")

    standard = ["# Standard", "", "## 23. Earned-trust constitution (additive)", "",
                "Cumulative with the standard; re-read at the point of use.", "",
                "| article | commitment |", "|---|---|"]
    for number, spec in enumerate(specs, start=1):
        standard.append(f"| {number} | {spec['title'].lower()} |")
    (root / earned_trust.STANDARD).write_text("\n".join(standard) + "\n", encoding="utf-8")

    covered = sorted({number for cited in GATE_ROWS.values() for number in cited})
    uncovered = [number for number in range(1, count + 1) if number not in covered]
    gates = ["# Release gates", "", "## 10. Earned-trust constitution gate", "",
             "| gate item | articles it evidences | what the item refuses |",
             "|---|---|---|"]
    for ident, cited in GATE_ROWS.items():
        cell = ", ".join(f"Article {number}" for number in cited)
        gates.append(f"| `{ident}` | {cell} | fixture refusal |")
    listing = "none" if not uncovered else ", ".join(str(n) for n in uncovered)
    gates += ["", f"**Articles no gate item covers: {listing}.** Fixture policy.", ""]
    (root / earned_trust.GATES).write_text("\n".join(gates), encoding="utf-8")

    for spec in specs:
        tool = root / spec["tool"]
        tool.parent.mkdir(parents=True, exist_ok=True)
        existing = tool.read_text(encoding="utf-8") if tool.is_file() else ""
        if spec["rule"] not in existing:
            tool.write_text(existing + f'\nREFUSAL = "{spec["rule"]}"\n', encoding="utf-8")


def edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture edit target not found in {path}: {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


class ConstitutionControls(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="et14-controls-")
        self.root = Path(self._temporary.name)
        build(self.root)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def problems(self) -> list[str]:
        return earned_trust.check_root(self.root)

    def assertRule(self, rule: str) -> None:
        found = self.problems()
        self.assertTrue(any(rule in problem for problem in found),
                        f"expected {rule}, got {found!r}")

    # -- positive control -------------------------------------------------
    def test_clean_fixture_passes(self) -> None:
        self.assertEqual(self.problems(), [])

    def test_third_article_fixture_passes_when_named_uncovered(self) -> None:
        build(self.root, count=3)
        self.assertEqual(self.problems(), [])

    # -- the three required controls --------------------------------------
    def test_cited_article_that_does_not_exist(self) -> None:
        edit(self.root / earned_trust.STANDARD,
             "| 2 | evidence is bound to an exact identity |",
             "| 2 | evidence is bound to an exact identity |\n| 3 | a third commitment |")
        self.assertRule("ET_CITATION_UNKNOWN")

    def test_article_with_no_enforcement_and_no_declaration(self) -> None:
        document = json.loads((self.root / earned_trust.RECORD).read_text(encoding="utf-8"))
        document["articles"][0]["enforcement"] = []
        document["articles"][0]["refusals"] = []
        (self.root / earned_trust.RECORD).write_text(json.dumps(document, indent=2) + "\n",
                                                     encoding="utf-8")
        edit(self.root / earned_trust.DOC,
             "- **Enforced by.** `forensics/tools/etp_claims.py` — `EG_VERDICT_MODALITY`.",
             "- **Enforced by.** none recorded.")
        self.assertRule("ET_ENFORCEMENT_ABSENT")

    def test_release_gate_cites_an_uncovered_article(self) -> None:
        build(self.root, count=3)  # Article 3 exists and is correctly declared uncovered
        edit(self.root / earned_trust.GATES,
             "**Articles no gate item covers: 3.**",
             "Article 3 also applies here.\n\n**Articles no gate item covers: 3.**")
        self.assertRule("ET_GATE_UNCOVERED")

    # -- enforcement must exist -------------------------------------------
    def test_unknown_rule_identifier(self) -> None:
        document = json.loads((self.root / earned_trust.RECORD).read_text(encoding="utf-8"))
        document["articles"][0]["enforcement"][0]["rule"] = "EG_NEVER_EMITTED"
        document["articles"][0]["refusals"] = ["EG_NEVER_EMITTED"]
        (self.root / earned_trust.RECORD).write_text(json.dumps(document, indent=2) + "\n",
                                                     encoding="utf-8")
        edit(self.root / earned_trust.DOC, "`EG_VERDICT_MODALITY`", "`EG_NEVER_EMITTED`")
        self.assertRule("ET_ENFORCEMENT_UNKNOWN")

    def test_missing_tool_path(self) -> None:
        (self.root / "forensics/tools/etp_claims.py").unlink()
        self.assertRule("ET_ENFORCEMENT_TOOL_MISSING")

    def test_declared_none_with_listed_enforcement(self) -> None:
        edit(self.root / earned_trust.DOC,
             "- **Enforced by.** `forensics/tools/etp_claims.py` — `EG_VERDICT_MODALITY`.",
             "- **Enforced by.** `forensics/tools/etp_claims.py` — `EG_VERDICT_MODALITY`; "
             "No enforcement exists for the claim wording itself.")
        self.assertRule("ET_ENFORCEMENT_DRIFT")

    # -- document structure ------------------------------------------------
    def test_missing_field(self) -> None:
        edit(self.root / earned_trust.DOC,
             "- **Not established.** that the cited evidence is true.\n", "")
        self.assertRule("ET_FIELD_MISSING")

    def test_duplicate_article(self) -> None:
        edit(self.root / earned_trust.DOC,
             "### Article 2. Evidence is bound to an exact identity",
             "### Article 1. Evidence is bound to an exact identity")
        self.assertRule("ET_DUPLICATE_ARTICLE")

    def test_numbering_gap(self) -> None:
        edit(self.root / earned_trust.DOC,
             "### Article 2. Evidence is bound to an exact identity",
             "### Article 3. Evidence is bound to an exact identity")
        self.assertRule("ET_NUMBERING")

    def test_record_title_drift(self) -> None:
        document = json.loads((self.root / earned_trust.RECORD).read_text(encoding="utf-8"))
        document["articles"][1]["title"] = "A different title"
        (self.root / earned_trust.RECORD).write_text(json.dumps(document, indent=2) + "\n",
                                                     encoding="utf-8")
        self.assertRule("ET_RECORD_DRIFT")

    def test_record_missing_article(self) -> None:
        document = json.loads((self.root / earned_trust.RECORD).read_text(encoding="utf-8"))
        document["articles"] = document["articles"][:1]
        (self.root / earned_trust.RECORD).write_text(json.dumps(document, indent=2) + "\n",
                                                     encoding="utf-8")
        self.assertRule("ET_RECORD_DRIFT")

    def test_missing_constitution(self) -> None:
        (self.root / earned_trust.DOC).unlink()
        self.assertRule("ET_DOC_MISSING")

    def test_missing_standard_section(self) -> None:
        edit(self.root / earned_trust.STANDARD,
             "## 23. Earned-trust constitution (additive)",
             "## 23. Some other section")
        self.assertRule("ET_STANDARD_SECTION_MISSING")

    def test_missing_gate_section(self) -> None:
        edit(self.root / earned_trust.GATES,
             "## 10. Earned-trust constitution gate",
             "## 10. Some other section")
        self.assertRule("ET_GATE_SECTION_MISSING")

    # -- gate mapping ------------------------------------------------------
    def test_uncovered_list_mismatch(self) -> None:
        build(self.root, count=3)
        edit(self.root / earned_trust.GATES,
             "**Articles no gate item covers: 3.**",
             "**Articles no gate item covers: none.**")
        self.assertRule("ET_GATE_LIST_MISMATCH")

    def test_uncovered_sentence_absent(self) -> None:
        edit(self.root / earned_trust.GATES,
             "**Articles no gate item covers: none.** Fixture policy.", "Fixture policy.")
        self.assertRule("ET_GATE_LIST_MISSING")

    def test_registered_gate_item_without_a_row(self) -> None:
        document = json.loads((self.root / earned_trust.RECORD).read_text(encoding="utf-8"))
        document["gate_items"].append({"id": "gate-3", "label": "unused"})
        (self.root / earned_trust.RECORD).write_text(json.dumps(document, indent=2) + "\n",
                                                     encoding="utf-8")
        self.assertRule("ET_GATE_ITEM_DRIFT")

    def test_record_gate_items_disagree_with_table(self) -> None:
        document = json.loads((self.root / earned_trust.RECORD).read_text(encoding="utf-8"))
        document["articles"][0]["gate_items"] = ["gate-1", "gate-2"]
        (self.root / earned_trust.RECORD).write_text(json.dumps(document, indent=2) + "\n",
                                                     encoding="utf-8")
        self.assertRule("ET_RECORD_DRIFT")

    def test_gate_item_unknown_to_the_registry(self) -> None:
        document = json.loads((self.root / earned_trust.RECORD).read_text(encoding="utf-8"))
        document["articles"][0]["gate_items"] = ["gate-2", "gate-9"]
        (self.root / earned_trust.RECORD).write_text(json.dumps(document, indent=2) + "\n",
                                                     encoding="utf-8")
        self.assertRule("ET_GATE_ITEM_UNKNOWN")

    # -- strictness and determinism ---------------------------------------
    def test_duplicate_json_key_is_refused(self) -> None:
        (self.root / earned_trust.RECORD).write_text(
            '{"schema": "x", "schema": "y", "articles": []}\n', encoding="utf-8")
        self.assertRule("ET_RECORD_SCHEMA")

    def test_two_runs_agree(self) -> None:
        first = self.problems()
        second = self.problems()
        self.assertEqual(first, second)
        self.assertEqual(first, sorted(dict.fromkeys(first)))

    def test_nonexistent_root_is_a_refusal(self) -> None:
        problems = earned_trust.check_root(self.root / "absent")
        self.assertTrue(any("ET_DOC_MISSING" in p for p in problems), problems)

    # -- the committed tree and the docs gate -----------------------------
    def test_committed_tree_passes(self) -> None:
        self.assertEqual(earned_trust.check_root(), [])

    def test_docs_consistency_runs_the_checker(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "docs_consistency_under_test", TOOLS / "docs_consistency.py")
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.assertIs(module.earned_trust, earned_trust)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = module.main(["--list"])
        self.assertEqual(code, 0)
        self.assertIn("earned_trust_constitution", buffer.getvalue())

    def test_required_controls_are_present(self) -> None:
        names = {name for name in dir(type(self)) if name.startswith("test_")}
        for required in REQUIRED_CONTROLS:
            self.assertIn(required, names)

    def test_no_first_person_in_deliverables(self) -> None:
        root = TOOLS.parents[1]
        first_person = re.compile(r"\b(I|We|Our|My|Mine|Ours|Me|Us|we|our|my|mine|ours|me|us)\b")
        texts = {
            "docs/EARNED-TRUST.md": (root / "docs/EARNED-TRUST.md").read_text(encoding="utf-8"),
            "evidence/etp-t14/ARTICLES.json":
                (root / "evidence/etp-t14/ARTICLES.json").read_text(encoding="utf-8"),
        }
        agents = (root / "AGENTS.md").read_text(encoding="utf-8")
        start = agents.index("## 23. Earned-trust constitution")
        texts["AGENTS.md (section 23)"] = agents[start:]
        for where, text in texts.items():
            matches = first_person.findall(text)
            self.assertEqual(matches, [], f"first-person word(s) {matches} in {where}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
