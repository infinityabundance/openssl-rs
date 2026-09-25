#!/usr/bin/env python3
"""openssl-rs — the hand-written documents must not contradict the generated evidence.

Why this gate exists
--------------------
The *generated* projections cannot go stale: `evidence_determinism.py` regenerates
`docs/SEAL-CENSUS.md`, `forensics/STATUS.md` and `forensics/phase-state.md` from their
generators and fails if the committed bytes differ. The *hand-written* documents have no
such protection, and they accumulated claims the evidence contradicts -- a status sentence
naming the wrong current stratum, a court count that a later phase moved, a "not yet
implemented" that has since landed. `README.md` is explicit that a document should not type
a quantity a generator can supply ("a number written into prose has no generator to correct
it"), but prose still needs the *shape* claims, so prohibition alone is not enough. This is
the corrected version of that rule: a small, explicit set of quantities, each traceable to
the generated file that holds it.

Design: precise rather than broad
---------------------------------
A gate that cries wolf gets disabled, so this one checks a short list of named claims, each
anchored to an exact phrase in one named document and each compared against one named
generator's output. It does not scan free-form prose for numbers. Three properties make it
hard to weaken by accident:

* **An anchor that disappears is a failure.** If a checked phrase is reworded away, the
  check reports "claim not found" rather than silently passing, so the registry has to be
  kept in step with the documents.
* **An exemption must still be doing work.** A `(check, document)` pair named in
  `EXEMPTIONS` is reported as exempt only while the claim it covers actually contradicts the
  evidence and still exists; an exemption that has become unnecessary, or that names a claim
  that is gone, is itself a failure. "It is historical" is therefore never a blanket escape
  hatch -- it is a per-claim statement with a reason string.
* **The failure names both values and the source.** Every message says what the document
  asserts, what the generated file holds, and which file that is.

What it does not do
-------------------
It does not check the generated documents (they are compared byte-for-byte elsewhere), the
`.frf/`, `.gemel/`, `forensics/receipts/` or `forensics/atlas/*.json` evidence (never
edited), or `docs/DECISIONS.md` (append-only, and every numeral in it is a record of the
moment it was written).

Usage
-----
    python3 forensics/tools/docs_consistency.py          # check
    python3 forensics/tools/docs_consistency.py --list    # print the registry

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT  # noqa: E402
import gen_frf_courts  # noqa: E402


def load_json(relpath: str) -> dict:
    return json.loads((REPO_ROOT / relpath).read_text(encoding="utf-8"))


def as_int(text: str) -> int:
    return int(text.replace(",", ""))


# ---------------------------------------------------------------------------
# The generated sources. Each expected value below is read from exactly one of
# these, and a failure names it.
# ---------------------------------------------------------------------------
FRF_COURTS = gen_frf_courts.COURTS
FRF_RUNTIME_COURTS = len(FRF_COURTS)
FRF_BY_PHASE = Counter(phase for _id, phase, _probe, _desc in FRF_COURTS)
CANDIDATE_VERSION = gen_frf_courts.CANDIDATE_VERSION

SURFACE = load_json("forensics/atlas/implemented-surface.json")["body"]
LIBCRYPTO = SURFACE["libraries"]["libcrypto"]
# `LIBCRYPTO["implemented"]` and `["authority_exports"]` had constants here for the two seals'
# typed counts. D205 removed those anchors -- a seal defers to the census rather than naming a
# number -- and D205's CI.md half removed the baseline-snapshot tuple, so `BASELINE`'s four
# derived figures are gone too. The module-level `LIBCRYPTO` is kept because the C-identifier
# count below still reads it.

P1 = load_json("forensics/atlas/phase1-completeness.json")["body"]
P7 = load_json("forensics/phase7-obligations.json")["body"]
STATE = load_json("forensics/phase-state.json")["body"]

SRC_FRF = "forensics/tools/gen_frf_courts.py's COURTS table"
SRC_SURFACE = "forensics/atlas/implemented-surface.json"
SRC_BASELINE = "forensics/regression-baseline.json"
SRC_P1 = "forensics/atlas/phase1-completeness.json"
SRC_P7 = "forensics/phase7-obligations.json"
SRC_STATE = "forensics/phase-state.json"
SRC_CARGO = "Cargo.toml, through gen_frf_courts.py"

# Spelled numerals, for the prose counts that are written as words.
NUMBER_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
    "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
    "nineteen": 19, "twenty": 20,
}


class ClaimMissing(Exception):
    """The document no longer carries the phrase a check is anchored to."""


@dataclass
class Check:
    id: str
    path: str
    source: str
    # verify(text) -> list of (claim, found, expected) that contradict the evidence,
    # [] when the document agrees, or raises ClaimMissing when the anchor is gone.
    verify: Callable[[str], list[tuple[str, str, str]]]


@dataclass
class Finding:
    path: str
    claim: str
    found: str
    expected: str
    source: str


def regex_check(check_id: str, path: str, source: str, pattern: str,
                expected: object, transform: Callable[[str], object] = as_int) -> Check:
    """A check over exactly one anchored quantity captured as group `n`."""
    rx = re.compile(pattern, re.S)

    def verify(text: str) -> list[tuple[str, str, str]]:
        m = rx.search(text)
        if m is None:
            raise ClaimMissing(f"the phrase matching /{pattern}/")
        found = transform(m.group("n"))
        if found != expected:
            return [(m.group(0).strip(), str(found), str(expected))]
        return []

    return Check(check_id, path, source, verify)


def multi_check(check_id: str, path: str, source: str,
                patterns: list[tuple[str, str, object]]) -> Check:
    """Several anchored quantities in one document, each `(label, pattern, expected)`."""
    compiled = [(label, re.compile(pattern, re.S), expected)
                for label, pattern, expected in patterns]

    def verify(text: str) -> list[tuple[str, str, str]]:
        out: list[tuple[str, str, str]] = []
        for label, rx, expected in compiled:
            m = rx.search(text)
            if m is None:
                raise ClaimMissing(f"the {label} phrase matching /{rx.pattern}/")
            found = as_int(m.group("n"))
            if found != int(expected):
                out.append((label, str(found), str(expected)))
        return out

    return Check(check_id, path, source, verify)


def frf_phase_breakdown(text: str) -> list[tuple[str, str, str]]:
    """The per-phase breakdown sentence in `forensics/frf/README.md`."""
    m = re.search(r"runtime count is (?P<total>\d+) as of this revision:(?P<seg>.*?)"
                  r"(?=\(D200\)|\.)", text, re.S)
    if m is None:
        raise ClaimMissing("the runtime-count breakdown sentence")
    pairs = re.findall(r"(?P<w>[A-Za-z]+)\s+Phase\s+(?P<ph>\d+)", m.group("seg"))
    if not pairs:
        raise ClaimMissing("the per-phase numerals in the runtime-count sentence")
    found: dict[int, int] = {}
    for word, phase in pairs:
        if word.lower() not in NUMBER_WORDS:
            raise ClaimMissing(f"a spelled numeral this tool does not know ({word!r})")
        found[int(phase)] = NUMBER_WORDS[word.lower()]
    expected = dict(FRF_BY_PHASE)
    if found != expected:
        return [("the per-phase runtime-court breakdown", str(found), str(expected))]
    return []


def defers_to_baseline(text: str) -> list[tuple[str, str, str]]:
    """`docs/CI.md` must not type the regression baseline's figures.

    Worse than the seals' case (D205): `regression_guard.py --update` **rewrites the baseline at
    the end of every run**, so a typed snapshot in this document is stale by construction rather
    than merely late -- the pipeline itself proved it, by passing a comparison made against the
    pre-update file and then failing the same comparison one run later. So this fails if the
    deferral is removed, and if the snapshot tuple is typed back in. `docs/CI.md`'s own subject is
    the baseline, so there is no moment for it to bind: it defers, or it lies.
    """
    if "`forensics/regression-baseline.json`" not in text:
        raise ClaimMissing("the deferral to `forensics/regression-baseline.json`")
    m = re.search(r"[\d,]+ implemented `libcrypto` symbols", text)
    if m is not None:
        return [(m.group(0), "a typed snapshot",
                 "no numbers: the generated baseline carries them")]
    return []


def phase7_headers(text: str) -> list[tuple[str, str, str]]:
    anchor = "owned rows, the stratum is:"
    if anchor not in text:
        raise ClaimMissing("the declared-header breakdown sentence")
    segment = text[text.index(anchor):]
    if "By library:" in segment:
        segment = segment[: segment.index("By library:")]
    found = {h: int(n) for h, n in re.findall(r"`(?P<h>[a-z0-9_]+\.h)` (?P<n>\d+)", segment)}
    expected = {h: int(n) for h, n in P7["owned_by_header"].items()}
    if found != expected:
        return [("the declared-header breakdown", str(found), str(expected))]
    return []


def defers_to_census(text: str) -> list[tuple[str, str, str]]:
    """A seal whose own preamble sends the reader to the census must not type a count.

    D203 replaced these documents' historical figure (932, which was correct for the moment
    each seal records) with the figure current at the time (1841), which turned a *record* into
    a *live* claim and put it on a treadmill: it read stale two slices later, at 1879. The
    seal's preamble already says `docs/SEAL-CENSUS.md` is authoritative and "cannot go stale",
    so the honest shape is a deferral with no numeral -- and what is worth checking is the
    deferral, not a number. So this fails in two directions: if the deferral is removed, and
    if a `<n> of <m> `libcrypto`` count is reintroduced beside it.
    """
    if "`docs/SEAL-CENSUS.md`" not in text:
        raise ClaimMissing("the deferral to `docs/SEAL-CENSUS.md`")
    m = re.search(r"[\d,]+ of [\d,]+ `libcrypto`", text)
    if m is not None:
        return [(m.group(0), "a typed count", "no count: the generated census carries it")]
    return []


# ---------------------------------------------------------------------------
# The active-stratum status gate (D208)
# ---------------------------------------------------------------------------
#
# D203's checks are all against *settled* artefacts -- a seal, a census, a court table -- and
# an **active** stratum's status prose is the one thing that moves every slice. The Phase-8 plan
# said the five `sha.h` one-shots and the truncated SHA-2 rows were "Still open" long after the
# ledger recorded them implemented, because nothing compared the plan's status sentences with
# `forensics/phase8-obligations.json`.
#
# The mechanism is stratum-generic: an active stratum is discovered from `forensics/phase-state.json`
# (so the next one inherits this without a code change), its plan is `docs/PHASE-<n>-SUBPHASES.md`
# and its ledger is `forensics/phase<n>-obligations.json`. Two clause headings in the plan are the
# anchors, and the symbols inside them are compared per symbol with the ledger:
#
#   * a symbol in the **landed** clause must be in the ledger's `implemented` list;
#   * a symbol in the **open** clause must be in the ledger's `open` list.
#
# That fails in both directions on purpose: a symbol claimed open while implemented, and a symbol
# claimed landed while open, are each a finding. A missing clause is a `ClaimMissing` failure, so
# the gate cannot be dropped by deleting the anchor, and a symbol in neither ledger list is also a
# finding rather than a silent pass.
LANDED_CLAUSE = "**Landed exports (checked against the ledger):**"
OPEN_CLAUSE = "**Open exports (checked against the ledger):**"


def active_phases() -> list[int]:
    """The phases `forensics/phase-state.json` currently reports as `in-progress`."""
    return [int(p["phase"]) for p in STATE["phases"] if p.get("state") == "in-progress"]


def _clause_symbols(text: str, heading: str) -> list[str]:
    """The backticked symbols of the paragraph that starts at `heading`."""
    at = text.find(heading)
    if at < 0:
        raise ClaimMissing(f"the anchored status clause {heading!r}")
    segment = text[at + len(heading):]
    stop = segment.find("\n\n")
    if stop >= 0:
        segment = segment[:stop]
    return re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", segment)


def active_status_check(phase: int, path: str) -> Check:
    """The active stratum's plan status sentences against its obligation ledger."""
    ledger = load_json(f"forensics/phase{phase}-obligations.json")["body"]
    implemented = set(ledger["implemented"])
    open_symbols = {row["symbol"] for row in ledger["open"]}
    source = f"forensics/phase{phase}-obligations.json"

    def verify(text: str) -> list[tuple[str, str, str]]:
        findings: list[tuple[str, str, str]] = []
        clauses = (
            (LANDED_CLAUSE, "landed", implemented, open_symbols),
            (OPEN_CLAUSE, "open", open_symbols, implemented),
        )
        for heading, claimed, pool, other in clauses:
            for symbol in _clause_symbols(text, heading):
                claim = f"the status clause {heading!r} names `{symbol}` as {claimed}"
                if symbol in other:
                    actual = "open" if claimed == "landed" else "implemented"
                    findings.append((claim, claimed, actual))
                elif symbol not in pool:
                    findings.append((claim, claimed, "in neither ledger list"))
        return findings

    return Check(f"phase{phase}_active_status", path, source, verify)


CHECKS: list[Check] = [
    regex_check("frf_readme_runtime_total_all", "forensics/frf/README.md", SRC_FRF,
                r"\(all (?P<n>\d+) runtime courts\)", FRF_RUNTIME_COURTS),
    regex_check("frf_readme_runtime_total", "forensics/frf/README.md", SRC_FRF,
                r"runtime count is (?P<n>\d+) as of this revision", FRF_RUNTIME_COURTS),
    Check("frf_readme_phase_breakdown", "forensics/frf/README.md", SRC_FRF,
          frf_phase_breakdown),
    Check("ci_defers_to_baseline", "docs/CI.md", SRC_BASELINE, defers_to_baseline),
    regex_check("ci_c_style_count", "docs/CI.md", SRC_SURFACE,
                r"the (?P<n>\d+) plain C identifiers",
                len(SURFACE["internal_symbols"]["c_style"])),
    regex_check("release_gates_manifest_count", "docs/RELEASE_GATES.md", SRC_FRF,
                r"the alternative is (?P<n>\d+) YAML", FRF_RUNTIME_COURTS),
    multi_check("phase1_census", "docs/PHASE-1-ARCHAEOLOGY-SEAL.md", SRC_P1, [
        ("planes complete", r"\*\*(?P<n>\d+)\*\* planes complete", P1["complete_count"]),
        ("missing planes", r"\*\*(?P<n>\d+)\*\* missing", P1["missing_count"]),
        ("deferred planes", r"\*\*(?P<n>\d+)\*\* deliberately deferred",
         P1["deferred_count"]),
        ("dispositioned residual classes",
         r"\*\*(?P<n>\d+)\*\* residual classes dispositioned",
         len(P1["residual_dispositions"])),
        ("open unknowns", r"\*\*(?P<n>\d+)\*\* open unknowns", P1["open_unknown_count"]),
    ]),
    multi_check("phase1_status_block", "docs/PHASE-1-ARCHAEOLOGY-SEAL.md", SRC_P1, [
        ("OPEN UNKNOWNS", r"OPEN UNKNOWNS:\s*(?P<n>\d+)", P1["open_unknown_count"]),
        ("DEFERRED PLANES", r"DEFERRED PLANES:\s*(?P<n>\d+)", P1["deferred_count"]),
    ]),
    Check("phase4_defers_to_census", "docs/PHASE-4-BIO-CONF-SEAL.md", SRC_SURFACE,
          defers_to_census),
    Check("phase5_defers_to_census", "docs/PHASE-5-BN-ASN1-PEM-SEAL.md", SRC_SURFACE,
          defers_to_census),
    Check("phase7_headers", "docs/PHASE-7-SUBPHASES.md", SRC_P7, phase7_headers),
    regex_check("phase7_claim_candidate_version", "docs/PHASE-7-EVP-SEAL.md", SRC_CARGO,
                r"candidate `openssl-rs (?P<n>\d+\.\d+\.\d+)",
                CANDIDATE_VERSION, transform=str),
]

# Every active stratum's plan, discovered rather than listed: the next stratum to move to
# `in-progress` inherits this gate by carrying the two anchored clause headings in its plan, and
# a plan that has them removed fails `ClaimMissing` rather than passing silently.
for _phase in active_phases():
    _plan = f"docs/PHASE-{_phase}-SUBPHASES.md"
    if (REPO_ROOT / _plan).is_file():
        CHECKS.append(active_status_check(_phase, _plan))

# A `(check id, document)` pair here is exempt from the numeric comparison, and the
# reason is printed with every run. The entry below is a quantity a document legitimately
# binds to a *past* moment rather than to the present state, and it names the moment. An
# entry that stops contradicting the evidence -- or whose claim is gone -- fails, so this
# is not a place to park a check that is inconvenient. README.md's status narrative used to
# carry one of these; D432 removed the narrative, so the entry went with it rather than
# staying as an exemption that no longer does any work.
EXEMPTIONS: dict[tuple[str, str], str] = {
    ("phase7_claim_candidate_version", "docs/PHASE-7-EVP-SEAL.md"): (
        "the FRF claim named there is a stored object compiled under 0.0.10; the seal "
        "records the claim's version, not the crate's current version"
    ),
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list", action="store_true",
                    help="print the checked quantities and their generated sources")
    args = ap.parse_args(argv)

    if args.list:
        for check in CHECKS:
            exempt = "  [EXEMPT]" if (check.id, check.path) in EXEMPTIONS else ""
            print(f"{check.path}: {check.id}\n    expect from {check.source}{exempt}")
        return 0

    problems: list[str] = []
    exempt_seen: list[str] = []
    for check in CHECKS:
        key = (check.id, check.path)
        text = (REPO_ROOT / check.path).read_text(encoding="utf-8")
        try:
            findings = check.verify(text)
        except ClaimMissing as exc:
            if key in EXEMPTIONS:
                problems.append(
                    f"{check.path}: the exemption for {check.id!r} names {exc}, which is no "
                    f"longer present; remove the exemption or restore the claim")
            else:
                problems.append(
                    f"{check.path}: the claim for {check.id!r} is not found ({exc}); update "
                    f"forensics/tools/docs_consistency.py or the document, so this gate "
                    f"cannot be silently disabled by a reword")
            continue

        if key in EXEMPTIONS:
            if findings:
                exempt_seen.append(
                    f"{check.path}: {check.id!r} is exempt -- {EXEMPTIONS[key]}")
            else:
                problems.append(
                    f"{check.path}: the exemption for {check.id!r} is no longer needed "
                    f"(the document now agrees with {check.source}); remove it")
            continue

        for claim, found, expected in findings:
            problems.append(
                f"{check.path}: {claim!r} asserts {found}, but {check.source} holds "
                f"{expected}")

    for line in exempt_seen:
        print(f"[docs-consistency] EXEMPT: {line}")

    if problems:
        print(f"[docs-consistency] FAIL: {len(problems)} stale hand-written claim(s)")
        for p in problems:
            print(f"  STALE: {p}")
        print("  A hand-written document may not contradict the generated evidence. "
              "Fix the document, or add a reasoned exemption if the quantity is bound to "
              "a past moment (docs/DECISIONS.md D203).")
        return 1

    print(f"[docs-consistency] ok: {len(CHECKS)} hand-written claim(s) agree with "
          f"their generated sources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
