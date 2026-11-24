#!/usr/bin/env python3
"""build_evidence.py -- produce the A7 baseline and delta evidence.

The producer of `evidence/a7/{BASELINES,DELTA,CONTROLS}.json`. Every identity,
candidate, count and disposition is read from a tracked record by
`forensics/tools/baseline.py`; nothing is typed in here. The composition of the
baseline set and the expected disposition shape of each real delta are design
expectations and are asserted, but no count is: a count that cannot be derived
from its record stops the producer with a refusal instead of being written.

Re-running the producer at one source identity reproduces the three files
byte-for-byte. It does not regenerate the records it reads.

Usage:
    python3 evidence/a7/build_evidence.py
    python3 evidence/a7/build_evidence.py --out DIR

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import baseline as bl  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent

EXPECTED_BASELINES = {
    "a1-sarif-results",
    "a1-fingerprints-model",
    "etp-claims-before",
    "etp-claims-after",
    "closure-ssh-b50-baseline",
    "closure-ssh-b50-applied",
    "haz15-prefix",
    "haz15-postfix",
    "haz16-classification",
    "t4-unsafe-sites",
    "t4-suppressions",
    "t4-ignored-tests",
    "t10-closure-exclusions",
    "curl-residual-sites",
    "curl-obligations",
    "a3-logical-collisions",
}

EXPECTED_DELTAS = {
    "a3-fingerprint-migration",
    "claims-reconciliation",
    "closure-ssh-b50-status",
    "haz15-padding-observation",
}


def _check_scope_against_a5(
    baselines: list[bl.Baseline], repo_root: Path
) -> None:
    """A baseline's scope state must equal the state A5 admitted for that id."""
    admission = bl._admission_map(repo_root)
    for baseline in baselines:
        item = admission.get(baseline.scope.id)
        if item is None:
            continue
        if item["state"] != baseline.scope.completeness:
            raise AssertionError(
                f"{baseline.id}: scope {baseline.scope.id} is "
                f"{baseline.scope.completeness} but A5 admitted {item['state']}"
            )


def _check_delta_members(
    deltas: list[bl.DeltaResult], baselines: list[bl.Baseline]
) -> None:
    by_id = {baseline.id: baseline for baseline in baselines}
    for result in deltas:
        before = by_id[result.before]
        expected = Counter(
            member.exact for member in before.members if member.exact is not None
        )
        observed = Counter(
            record.exact
            for record in result.records
            if record.exact is not None and record.exact in expected
        )
        if expected != observed:
            raise AssertionError(
                f"{result.id}: every before-member must appear once; "
                f"missing {expected - observed}, extra {observed - expected}"
            )
        counts = result.counts()
        if sum(counts.values()) != len(result.records):
            raise AssertionError(f"{result.id}: the counts do not partition")
        for code in result.codes:
            if code not in bl.REFUSALS:
                raise AssertionError(f"{result.id}: unknown refusal code {code}")


def build(repo_root: Path) -> dict[str, str]:
    """Return the three evidence documents keyed by file name."""
    baselines, not_baselines = bl.build_baselines(repo_root)
    observed_ids = {baseline.id for baseline in baselines}
    if observed_ids != EXPECTED_BASELINES:
        raise AssertionError(
            "the baseline set does not match the registry: "
            f"missing {sorted(EXPECTED_BASELINES - observed_ids)}, "
            f"extra {sorted(observed_ids - EXPECTED_BASELINES)}"
        )
    if len(observed_ids) != len(baselines):
        raise AssertionError("a baseline id is duplicated")

    _check_scope_against_a5(baselines, repo_root)

    deltas, no_baseline = bl.build_deltas(baselines, repo_root)
    if {result.id for result in deltas} != EXPECTED_DELTAS:
        raise AssertionError("the delta set does not match the registry")
    _check_delta_members(deltas, baselines)

    real_resolutions = sum(
        record.disposition == bl.D_RESOLVED
        for result in deltas
        for record in result.records
    )
    if real_resolutions != 0:
        raise AssertionError(
            f"a real delta reached RESOLVED ({real_resolutions}); the document "
            "must be revised before the producer accepts it"
        )
    if len(no_baseline) != 7:
        raise AssertionError(
            f"the NO_BASELINE inventory has {len(no_baseline)} entries, not 7"
        )

    controls = bl.build_controls(baselines)
    covered = {control["code"] for control in controls}
    if covered != set(bl.REFUSALS):
        raise AssertionError(
            "the controls do not cover every refusal code: "
            f"missing {sorted(set(bl.REFUSALS) - covered)}"
        )
    if len(controls) != len(bl.REFUSALS):
        raise AssertionError(
            f"{len(controls)} controls over {len(bl.REFUSALS)} codes; one per code "
            "is required"
        )

    baselines_doc = bl.baselines_document(baselines, not_baselines, repo_root)
    delta_doc = bl.delta_document(deltas, no_baseline, repo_root)
    controls_doc = bl.controls_document(controls, repo_root)

    if baselines_doc["totals"]["baselines"] != len(baselines):
        raise AssertionError("the baseline total does not match the rows")
    if delta_doc["totals"]["records"] != sum(len(r.records) for r in deltas):
        raise AssertionError("the delta record total does not match the rows")
    if sum(delta_doc["totals"]["byDisposition"].values()) != delta_doc["totals"]["records"]:
        raise AssertionError("the disposition totals do not sum to the record total")

    return {
        "BASELINES.json": bl.dump_document(baselines_doc),
        "DELTA.json": bl.dump_document(delta_doc),
        "CONTROLS.json": bl.dump_document(controls_doc),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=OUT_DIR)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    try:
        documents = build(args.repo_root)
    except bl.Refusal as refusal:
        print(str(refusal), file=sys.stderr)
        return 2
    except AssertionError as error:
        print(f"producer assertion failed: {error}", file=sys.stderr)
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in documents.items():
        (args.out / name).write_text(text, encoding="utf-8")

    baselines, not_baselines = bl.build_baselines(args.repo_root)
    deltas, no_baseline = bl.build_deltas(baselines, args.repo_root)
    controls = bl.build_controls(baselines)
    dispositions: Counter[str] = Counter()
    for result in deltas:
        dispositions.update(result.counts())
    print(
        f"baselines={len(baselines)} "
        f"enumerated={sum(1 for b in baselines if not b.aggregate)} "
        f"aggregate={sum(1 for b in baselines if b.aggregate)} "
        f"members={sum(b.member_total() for b in baselines)} "
        f"notBaselines={len(not_baselines)}"
    )
    print(
        f"deltas={len(deltas)} admitted={sum(1 for d in deltas if d.admitted)} "
        f"refused={sum(1 for d in deltas if not d.admitted)} "
        f"records={sum(len(d.records) for d in deltas)} "
        + " ".join(
            f"{disposition}={count}"
            for disposition, count in sorted(dispositions.items())
            if count
        )
        + f" noBaseline={len(no_baseline)}"
    )
    print(
        "codes="
        + (
            ",".join(
                sorted({code for result in deltas for code in result.codes})
            )
            or "none"
        )
    )
    print(f"controls={len(controls)} codesCovered={len({c['code'] for c in controls})}")
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
