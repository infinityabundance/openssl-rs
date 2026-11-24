#!/usr/bin/env python3
"""build_evidence.py -- produce the A6 suppression-governance evidence.

The producer of `evidence/a6/{SUPPRESSIONS,INVALIDATION,CONTROLS}.json`. Every
record, count and identity in the outputs is read from a tracked record by
`forensics/tools/suppression_governance.py`; nothing is typed in here. Design
expectations (which codes fire, that no real suppression is actionable, that the
controls cover every code and trigger, that the reconciliation balances) are
asserted, but no number is: a count that cannot be derived from its record stops
the producer with a refusal instead of being written.

Usage:
    python3 evidence/a6/build_evidence.py
    python3 evidence/a6/build_evidence.py --out DIR

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import suppression_governance as sg  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent


def build(
    repo_root: Path, current: sg.CurrentIdentity | None = None
) -> tuple[dict[str, str], dict]:
    """Return the three evidence documents and the summary the producer prints.

    `current` names the candidate the suppressions are evaluated at. The default is
    the repository HEAD; an explicit identity reproduces the recorded bytes after the
    evidence commit has moved HEAD.
    """
    if current is None:
        current = sg.candidate_identity(repo_root)
    records = sg.build_register(repo_root)
    reviewers = sg.reviewer_register(repo_root)
    population = sg.sarif_population(
        repo_root / "evidence" / "a1" / "SARIF.json",
        expected=sg._second_statement(repo_root, "a1-sarif-results"),
        display="evidence/a1/SARIF.json",
    )
    as_of = current.as_of
    if as_of is None:
        raise AssertionError("the candidate under evaluation states no date")

    register = sg.register_document(
        records,
        population=population,
        reviewers=reviewers,
        as_of=as_of,
        current=current,
    )
    invalidation = sg.invalidation_document(
        records,
        population=population,
        current=current,
        reviewers=reviewers,
        as_of=as_of,
    )
    controls = sg.build_controls(population, reviewers=reviewers, as_of=as_of)
    controls_document = sg.controls_document(controls)

    # Design expectations. None of these is a count read from a record; each is a
    # statement about the model, asserted so a change stops the producer.
    totals = register["totals"]
    if totals["suppressions"] == 0:
        raise AssertionError("the register read no suppression")
    if totals["actionable"] != 0:
        raise AssertionError(
            f"{totals['actionable']} real suppression(s) are actionable; the recorded "
            "register was expected to contain none, so a reviewer must decide"
        )
    for admission in register["admissions"]:
        if admission["classification"] == sg.C_SUPPRESSION and not admission["codes"]:
            raise AssertionError(
                f"{admission['id']}: a suppression was admitted with no refusal code"
            )
    covered = {control["expectedCode"] for control in controls}
    if covered != set(sg.REFUSALS):
        raise AssertionError(
            "the controls do not cover every refusal code: missing "
            f"{sorted(set(sg.REFUSALS) - covered)}"
        )
    trigger_controls = {control["trigger"] for control in invalidation["controls"]}
    if trigger_controls != set(sg.TRIGGERS):
        raise AssertionError(
            "the invalidation controls do not cover every trigger: missing "
            f"{sorted(set(sg.TRIGGERS) - trigger_controls)}"
        )
    if invalidation["summary"]["controlsFired"] != len(sg.TRIGGERS):
        raise AssertionError("an invalidation control did not fire")

    reconciliation = sg.reconcile(
        population, records, reviewers=reviewers, as_of=as_of, current=current
    )
    if not reconciliation.balanced:
        raise AssertionError("the reconciliation does not balance")
    if reconciliation.suppressed:
        raise AssertionError(
            "an active suppression was found in the recorded register; the evidence "
            "expects none and refuses rather than deciding"
        )
    if len(reconciliation.unsuppressed) != reconciliation.enumerated:
        raise AssertionError("a finding was removed by the reconciliation")

    documents = {
        "SUPPRESSIONS.json": sg.dump_document(register),
        "INVALIDATION.json": sg.dump_document(invalidation),
        "CONTROLS.json": sg.dump_document(controls_document),
    }
    summary = {
        "records": totals["records"],
        "suppressions": totals["suppressions"],
        "notSuppressions": totals["notSuppressions"],
        "actionable": totals["actionable"],
        "byDisposition": totals["byDisposition"],
        "byCode": totals["byCode"],
        "controls": controls_document["totals"]["controls"],
        "invalidationControls": invalidation["summary"]["controls"],
        "population": population.summary(),
        "reconciliation": reconciliation.summary(),
        "current": current.as_dict(),
        "reviewerTokens": len(reviewers),
    }
    return documents, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=OUT_DIR)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--candidate", default=None)
    parser.add_argument("--as-of", default=None)
    args = parser.parse_args(argv)

    try:
        current = None
        if args.candidate is not None or args.as_of is not None:
            read = sg.candidate_identity(args.repo_root)
            current = sg.CurrentIdentity(
                candidate=args.candidate or read.candidate,
                source_tree=read.source_tree,
                tool=read.tool,
                policy_basis=read.policy_basis,
                new_occurrence_logical=read.new_occurrence_logical,
                new_occurrence_exact=read.new_occurrence_exact,
                as_of=args.as_of or read.as_of,
                detail=read.detail,
            )
        documents, summary = build(args.repo_root, current=current)
    except sg.Refusal as refusal:
        print(str(refusal), file=sys.stderr)
        return 2
    except AssertionError as error:
        print(f"producer assertion failed: {error}", file=sys.stderr)
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in documents.items():
        (args.out / name).write_text(text, encoding="utf-8")

    print(
        f"records={summary['records']} suppressions={summary['suppressions']} "
        f"notSuppressions={summary['notSuppressions']} "
        f"actionable={summary['actionable']} "
        + " ".join(
            f"{disposition}={count}"
            for disposition, count in summary["byDisposition"].items()
            if count
        )
    )
    print(
        f"population={summary['population']['id']} "
        f"enumerated={summary['population']['results']} "
        f"suppressed={summary['reconciliation']['suppressed']} "
        f"unsuppressed={summary['reconciliation']['unsuppressed']} "
        f"balance={'ok' if summary['reconciliation']['balanced'] else 'unbalanced'}"
    )
    print(
        f"controls={summary['controls']} invalidationControls="
        f"{summary['invalidationControls']} reviewerTokens={summary['reviewerTokens']}"
    )
    print(
        "wrote "
        + ", ".join(
            f"{name} ({len(text.encode('utf-8'))} bytes)"
            for name, text in documents.items()
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
