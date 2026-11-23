#!/usr/bin/env python3
"""earned_trust.py -- the claim constitution must stay wired to what refuses it.

`docs/EARNED-TRUST.md` states the standing commitments this project makes about
claims, one numbered article each, with four fields: `Why`, `Enforced by`,
`Refused when`, `Not established`. A constitution is only worth the wiring behind
it, so this checker treats a broken wire as a refusal rather than a note.

What is checked
---------------
1. **The document parses.** Every article is a `### Article N. <title>` heading
   followed by the four labelled fields, non-empty. Numbering is contiguous from
   1, with no duplicate.
2. **The record agrees with the document.** `evidence/etp-t14/ARTICLES.json`
   names the same article set and titles, and its `enforcement` entries are the
   machine form of each `Enforced by` field. `refusals` must equal the enforcement
   rule list.
3. **Every claimed enforcement exists.** The credited tool path must exist, and
   the credited rule identifier must appear in that tool's bytes. A rule the tool
   does not emit is refused (`ET_ENFORCEMENT_UNKNOWN`) rather than believed.
4. **An unenforced article declares it.** An article with no enforcement entry
   must say `No enforcement exists` in its `Enforced by` field *and* set
   `declared_none`; one without either is refused (`ET_ENFORCEMENT_ABSENT`). An
   article that declares none while listing enforcement is refused as drift.
5. **Citations resolve.** Every `Article N` cited in `AGENTS.md` (in the section
   that names the constitution) and in `docs/RELEASE_GATES.md` (its constitution
   gate section) must be an article of the document.
6. **The release mapping is complete and consistent.** The gate table's item ids
   must equal the record's `gate_items` registry; each article's recorded gate
   items must equal the items whose row cites it; the document must name exactly
   the articles no gate item covers, and a gate-section mention of an uncovered
   article is refused (`ET_GATE_UNCOVERED`).

Every failure is reported with a stable `ET_*` identifier on one line, sorted and
de-duplicated, so the same input produces byte-identical output. Exit status is 0
only when nothing is refused, 1 for a refusal, 2 for a usage error. The checker
fails closed: a missing document, an unreadable record or an unparseable section
is a refusal, never a pass.

What this does not do
---------------------
It checks wiring, not fairness: it cannot show that a named rule is the only or
the best enforcement of an article, that the rule is reachable from a release
artefact, or that an unchecked prose document obeys the article. Those are review
obligations, stated in `docs/EARNED-TRUST.md` section 2.

Usage
-----
    python3 forensics/tools/earned_trust.py check [--repo-root PATH] [--json]

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

DOC = "docs/EARNED-TRUST.md"
RECORD = "evidence/etp-t14/ARTICLES.json"
STANDARD = "AGENTS.md"
GATES = "docs/RELEASE_GATES.md"
SCHEMA = "openssl-rs/etp-t14/articles/1"

FIELDS = ("Why", "Enforced by", "Refused when", "Not established")
DECLARED_NONE = "No enforcement exists"

ARTICLE_HEADING = re.compile(r"^### Article (\d+)\. (.+?)\s*$", re.M)
NEXT_HEADING = re.compile(r"^#{2,3} ", re.M)
FIELD_RX = re.compile(r"^- \*\*(Why|Enforced by|Refused when|Not established)\.\*\*(.*)$", re.M)
STANDARD_SECTION = re.compile(r"^## .*Earned-trust constitution.*$", re.M)
GATE_SECTION = re.compile(r"^## .*Earned-trust constitution gate.*$", re.M)
STANDARD_ROW = re.compile(r"^\|\s*(\d+)\s*\|\s*(.+?)\s*\|\s*$", re.M)
TABLE_ROW = re.compile(r"^\|([^|\n]*)\|([^|\n]*)\|", re.M)
GATE_ID = re.compile(r"\bgate-\d+b?\b")
CITATION = re.compile(r"\bArticle\s+(\d+)\b")
UNCOVERED = re.compile(r"\*\*Articles no gate item covers:\s*(none|[0-9][0-9,\s\u2013-]*?)\.\*\*",
                       re.S)


def _read(root: Path, relpath: str) -> str:
    return (root / relpath).read_text(encoding="utf-8")


def _duplicate_key(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen: dict[str, object] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate object key {key!r}")
        seen[key] = value
    return seen


def _non_finite(token: str) -> object:
    raise ValueError(f"non-finite number {token!r}")


def _safe_relative(path: str) -> bool:
    candidate = Path(path)
    return bool(path) and not candidate.is_absolute() and ".." not in candidate.parts


def parse_articles(text: str) -> tuple[dict[int, dict[str, object]], list[str]]:
    """Return {number: {title, fields}} and the problems found while parsing."""
    problems: list[str] = []
    articles: dict[int, dict[str, object]] = {}
    for match in ARTICLE_HEADING.finditer(text):
        number = int(match.group(1))
        title = match.group(2).strip()
        start = match.end()
        following = NEXT_HEADING.search(text, start)
        block = text[start:following.start() if following else len(text)]
        if number in articles:
            problems.append(f"{DOC}: ET_DUPLICATE_ARTICLE Article {number} is defined twice")
            continue
        labels = list(FIELD_RX.finditer(block))
        fields: dict[str, str] = {}
        for index, label in enumerate(labels):
            stop = labels[index + 1].start() if index + 1 < len(labels) else len(block)
            value = (label.group(2) + "\n" + block[label.end():stop]).strip()
            fields[label.group(1)] = value
        for name in FIELDS:
            if not fields.get(name):
                problems.append(
                    f"{DOC}: ET_FIELD_MISSING Article {number} has no non-empty {name!r} field")
        articles[number] = {"title": title, "fields": fields}
    if not articles:
        problems.append(f"{DOC}: ET_ARTICLE_MISSING the constitution defines no article")
    numbers = sorted(articles)
    if numbers and numbers != list(range(1, len(numbers) + 1)):
        problems.append(
            f"{DOC}: ET_NUMBERING articles are {numbers}, not 1..{len(numbers)}")
    return articles, problems


def load_record(root: Path) -> tuple[dict[str, object], list[str], set[str]]:
    """Strictly load the machine record; return (document, problems, gate ids)."""
    try:
        text = _read(root, RECORD)
    except OSError as exc:
        return {}, [f"{RECORD}: ET_RECORD_SCHEMA cannot read the record: {exc}"], set()
    try:
        document = json.loads(text, object_pairs_hook=_duplicate_key,
                              parse_constant=_non_finite)
    except ValueError as exc:
        return {}, [f"{RECORD}: ET_RECORD_SCHEMA {exc}"], set()
    problems: list[str] = []
    if not isinstance(document, dict):
        return {}, [f"{RECORD}: ET_RECORD_SCHEMA the record is not a JSON object"], set()
    if document.get("schema") != SCHEMA:
        problems.append(f"{RECORD}: ET_RECORD_SCHEMA schema is {document.get('schema')!r}, "
                        f"expected {SCHEMA!r}")
    if document.get("document") != DOC:
        problems.append(f"{RECORD}: ET_RECORD_DRIFT document is "
                        f"{document.get('document')!r}, expected {DOC!r}")
    registry: set[str] = set()
    raw_items = document.get("gate_items")
    if not isinstance(raw_items, list):
        problems.append(f"{RECORD}: ET_RECORD_SCHEMA gate_items is not a list")
    else:
        for entry in raw_items:
            if not isinstance(entry, dict):
                problems.append(f"{RECORD}: ET_RECORD_SCHEMA a gate_items entry is not an object")
                continue
            ident = entry.get("id")
            if not isinstance(ident, str) or not GATE_ID.fullmatch(ident):
                problems.append(f"{RECORD}: ET_RECORD_SCHEMA gate item id {ident!r} is not "
                                "`gate-N` or `gate-Nb`")
                continue
            if ident in registry:
                problems.append(f"{RECORD}: ET_RECORD_SCHEMA gate item {ident} is listed twice")
            registry.add(ident)
    if not isinstance(document.get("articles"), list):
        problems.append(f"{RECORD}: ET_RECORD_SCHEMA articles is not a list")
    return document, problems, registry


def _entries(document: dict[str, object]) -> list[dict[str, object]]:
    raw = document.get("articles")
    return [entry for entry in raw if isinstance(entry, dict)] if isinstance(raw, list) else []


def verify_record(root: Path, articles: dict[int, dict[str, object]],
                  document: dict[str, object], registry: set[str]) -> list[str]:
    """Compare the record with the document and with the tools it credits."""
    problems: list[str] = []
    numbers = set(articles)
    entries = _entries(document)
    recorded: set[int] = set()

    for entry in entries:
        where = f"{RECORD}: articles[{entry.get('id', '?')}]"
        number = entry.get("number")
        if not isinstance(number, int) or isinstance(number, bool):
            problems.append(f"{where}: ET_RECORD_SCHEMA number is not an integer")
            continue
        if number in recorded:
            problems.append(f"{where}: ET_RECORD_SCHEMA article {number} is recorded twice")
        recorded.add(number)
        if number not in articles:
            problems.append(f"{where}: ET_RECORD_DRIFT article {number} is not in {DOC}")
            continue
        title = entry.get("title")
        if title != articles[number]["title"]:
            problems.append(f"{where}: ET_RECORD_DRIFT title {title!r} disagrees with "
                            f"{articles[number]['title']!r}")
        declared_none = entry.get("declared_none")
        if not isinstance(declared_none, bool):
            problems.append(f"{where}: ET_RECORD_SCHEMA declared_none is not a boolean")
            declared_none = False

        raw_enforcement = entry.get("enforcement")
        enforcement = raw_enforcement if isinstance(raw_enforcement, list) else []
        if not isinstance(raw_enforcement, list):
            problems.append(f"{where}: ET_RECORD_SCHEMA enforcement is not a list")
        rules: list[str] = []
        field = str(articles[number]["fields"].get("Enforced by", ""))
        for item in enforcement:
            if not isinstance(item, dict):
                problems.append(f"{where}: ET_RECORD_SCHEMA an enforcement entry is not an object")
                continue
            tool, rule = item.get("tool"), item.get("rule")
            if not isinstance(tool, str) or not isinstance(rule, str) or not tool or not rule:
                problems.append(f"{where}: ET_RECORD_SCHEMA enforcement needs string tool and rule")
                continue
            rules.append(rule)
            if not _safe_relative(tool):
                problems.append(f"{where}: ET_ENFORCEMENT_TOOL_MISSING {tool!r} is not a "
                                "repository-relative path")
            elif not (root / tool).is_file():
                problems.append(f"{where}: ET_ENFORCEMENT_TOOL_MISSING {tool} does not exist")
            else:
                source = _read(root, tool)
                if rule not in source:
                    problems.append(f"{where}: ET_ENFORCEMENT_UNKNOWN {tool} does not emit {rule}")
            if rule not in field:
                problems.append(f"{where}: ET_ENFORCEMENT_DRIFT Article {number}'s Enforced by "
                                f"field does not name {rule}")

        refusals = entry.get("refusals")
        if not isinstance(refusals, list) or not all(isinstance(r, str) for r in refusals):
            problems.append(f"{where}: ET_RECORD_SCHEMA refusals is not a list of strings")
        elif list(refusals) != rules:
            problems.append(f"{where}: ET_RECORD_SCHEMA refusals {refusals!r} disagree with "
                            f"the enforcement rules {rules!r}")

        if enforcement:
            if declared_none:
                problems.append(f"{where}: ET_ENFORCEMENT_DRIFT article declares no enforcement "
                                "but lists one")
            if DECLARED_NONE in field:
                problems.append(f"{where}: ET_ENFORCEMENT_DRIFT Article {number} declares no "
                                "enforcement while the record lists enforcement")
        else:
            if not declared_none:
                problems.append(f"{where}: ET_ENFORCEMENT_ABSENT Article {number} lists no "
                                "enforcement and does not declare that none exists")
            if DECLARED_NONE not in field:
                problems.append(f"{where}: ET_ENFORCEMENT_ABSENT Article {number} lists no "
                                "enforcement and its Enforced by field does not say "
                                f"{DECLARED_NONE!r}")

        gate_items = entry.get("gate_items")
        if not isinstance(gate_items, list) or not all(isinstance(g, str) for g in gate_items):
            problems.append(f"{where}: ET_RECORD_SCHEMA gate_items is not a list of strings")
        else:
            for gate in gate_items:
                if gate not in registry:
                    problems.append(f"{where}: ET_GATE_ITEM_UNKNOWN {gate} is not a registered "
                                    "gate item")

    for number in sorted(numbers - recorded):
        problems.append(f"{RECORD}: ET_RECORD_DRIFT Article {number} is not recorded")
    return problems


def check_standard(root: Path, numbers: set[int]) -> list[str]:
    """Every article must appear once, with a summary, in the AGENTS.md section."""
    try:
        text = _read(root, STANDARD)
    except OSError as exc:
        return [f"{STANDARD}: ET_STANDARD_SECTION_MISSING cannot read the file: {exc}"]
    match = STANDARD_SECTION.search(text)
    if match is None:
        return [f"{STANDARD}: ET_STANDARD_SECTION_MISSING no section heading names the "
                "earned-trust constitution"]
    section = text[match.start():]
    problems: list[str] = []
    cited: dict[int, int] = {}
    for raw_number, summary in STANDARD_ROW.findall(section):
        number = int(raw_number)
        cited[number] = cited.get(number, 0) + 1
        if number not in numbers:
            problems.append(f"{STANDARD}: ET_CITATION_UNKNOWN the constitution section cites "
                            f"Article {number}, which does not exist")
        if not summary.strip():
            problems.append(f"{STANDARD}: ET_CITATION_EMPTY the row for Article {number} has no "
                            "summary")
    for number in sorted(numbers):
        if cited.get(number, 0) == 0:
            problems.append(f"{STANDARD}: ET_CITATION_OMITTED the constitution section does not "
                            f"list Article {number}")
        elif cited[number] > 1:
            problems.append(f"{STANDARD}: ET_CITATION_DUPLICATE Article {number} is listed "
                            f"{cited[number]} times")
    return problems


def check_gates(root: Path, numbers: set[int], document: dict[str, object],
                registry: set[str]) -> list[str]:
    """The release gate table must cover what it cites and name the remainder."""
    try:
        text = _read(root, GATES)
    except OSError as exc:
        return [f"{GATES}: ET_GATE_SECTION_MISSING cannot read the file: {exc}"]
    match = GATE_SECTION.search(text)
    if match is None:
        return [f"{GATES}: ET_GATE_SECTION_MISSING no section heading names the earned-trust "
                "constitution gate"]
    section = text[match.start():]
    problems: list[str] = []

    covered_by: dict[str, set[int]] = {}
    for cell in TABLE_ROW.findall(section):
        ident = GATE_ID.search(cell[0])
        if ident is None:
            continue
        covered_by[ident.group(0)] = {int(n) for n in CITATION.findall(cell[1])}

    if set(covered_by) != registry:
        problems.append(f"{GATES}: ET_GATE_ITEM_DRIFT the gate table lists "
                        f"{sorted(covered_by)} but the record registers {sorted(registry)}")

    covered: set[int] = set()
    for ident, cited in sorted(covered_by.items()):
        covered |= cited
        for number in sorted(cited):
            if number not in numbers:
                problems.append(f"{GATES}: ET_CITATION_UNKNOWN {ident} cites Article {number}, "
                                "which does not exist")

    for entry in _entries(document):
        number = entry.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number not in numbers:
            continue
        declared = {gate for gate in entry.get("gate_items", [])
                    if isinstance(gate, str)} if isinstance(entry.get("gate_items"), list) else set()
        computed = {ident for ident, cited in covered_by.items() if number in cited}
        if declared != computed:
            problems.append(f"{GATES}: ET_RECORD_DRIFT Article {number} records gate items "
                            f"{sorted(declared)} but the table covers it with {sorted(computed)}")

    uncovered_match = UNCOVERED.search(section)
    if uncovered_match is None:
        problems.append(f"{GATES}: ET_GATE_LIST_MISSING the gate section does not state which "
                        "articles no gate item covers")
        remainder = section
    else:
        raw = uncovered_match.group(1).strip()
        listed = set() if raw.lower() == "none" else {int(n) for n in re.findall(r"\d+", raw)}
        expected = numbers - covered
        if listed != expected:
            problems.append(f"{GATES}: ET_GATE_LIST_MISMATCH the gate section names "
                            f"{sorted(listed)} as uncovered but the table leaves "
                            f"{sorted(expected)}")
        remainder = section[:uncovered_match.start()] + section[uncovered_match.end():]

    for raw_number in CITATION.findall(remainder):
        number = int(raw_number)
        if number not in covered:
            problems.append(f"{GATES}: ET_GATE_UNCOVERED the gate section cites Article "
                            f"{number}, which no gate item covers")
    return problems


def check_root(root: Path | str | None = None) -> list[str]:
    """Return the sorted, de-duplicated problems found under `root`."""
    base = Path(root) if root is not None else REPO_ROOT
    try:
        text = _read(base, DOC)
    except OSError as exc:
        return [f"{DOC}: ET_DOC_MISSING cannot read the constitution: {exc}"]
    articles, problems = parse_articles(text)
    document, record_problems, registry = load_record(base)
    problems.extend(record_problems)
    problems.extend(verify_record(base, articles, document, registry))
    numbers = set(articles)
    problems.extend(check_standard(base, numbers))
    problems.extend(check_gates(base, numbers, document, registry))
    return sorted(dict.fromkeys(problems))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", nargs="?", default="check", choices=["check"])
    parser.add_argument("--repo-root", default=None,
                        help="check another tree (default: this repository)")
    parser.add_argument("--json", action="store_true", help="emit one JSON decision")
    args = parser.parse_args(argv)

    problems = check_root(args.repo_root)
    if args.json:
        print(json.dumps({"ok": not problems, "problems": problems},
                         indent=2, sort_keys=True))
    else:
        for problem in problems:
            print(f"REFUSED {problem}")
        if problems:
            print(f"earned-trust: {len(problems)} refusal(s)")
        else:
            print("earned-trust: ok: every article is enforced or declares none, every "
                  "citation resolves, and the release mapping is complete")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
