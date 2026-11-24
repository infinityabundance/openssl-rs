#!/usr/bin/env python3
"""build_evidence.py -- produce the A5 completeness-admission evidence.

The producer of `evidence/a5/{POPULATIONS,ADMISSION,CONTROLS}.json`. Every count
in the outputs is read from a tracked record by `forensics/tools/completeness.py`
and cross-checked against a second statement in that record; nothing is typed in
here. An expected admission state or refusal code is a design expectation and is
asserted, but no number is: a count that cannot be derived from its record stops
the producer with a refusal instead of being written.

Usage:
    python3 evidence/a5/build_evidence.py
    python3 evidence/a5/build_evidence.py --out DIR

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import completeness as ca  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent


def build(repo_root: Path) -> dict[str, str]:
    """Return the three evidence documents keyed by file name."""
    populations = ca.build_populations(repo_root)

    if len(populations) != len(ca.SPECS):
        raise AssertionError("a registered population was not read")
    if {p.id for p in populations} != set(ca.SPECS_BY_ID):
        raise AssertionError("the population ids do not match the registry")

    for spec, population in zip(ca.SPECS, populations):
        if population.id != spec.id:
            raise AssertionError(f"{spec.id}: registry order drifted")
        if ca.verify_declaration(population, repo_root) != "checked":
            raise AssertionError(f"{spec.id}: the declaration did not verify")
        admission = ca.admit(population)
        if admission.state != spec.expect_state:
            raise AssertionError(
                f"{spec.id}: expected state {spec.expect_state}, "
                f"observed {admission.state}"
            )
        if admission.refusal != spec.expect_refusal:
            raise AssertionError(
                f"{spec.id}: expected refusal {spec.expect_refusal}, "
                f"observed {admission.refusal}"
            )
        # The counts must partition. `Population` enforces this at construction,
        # and the assertion is repeated here so the producer's own gate is visible.
        if population.expected != ca.EXTENT_UNKNOWN:
            if population.examined + population.omitted != population.expected:
                raise AssertionError(f"{spec.id}: the counts do not partition")

    controls = ca.build_controls(populations, repo_root)
    covered = {control["expectedCode"] for control in controls}
    if covered != set(ca.REFUSALS):
        raise AssertionError(
            f"the controls do not cover every refusal code: "
            f"missing {sorted(set(ca.REFUSALS) - covered)}"
        )

    admission = ca.admission_document(populations)
    totals = admission["totals"]
    observed_admitted = sum(1 for item in admission["populations"]
                            if item["refusal"] is None)
    observed_refused = len(populations) - observed_admitted
    if totals["admitted"] != observed_admitted or totals["refused"] != observed_refused:
        raise AssertionError("the admission totals do not match the rows")
    if sum(totals["byState"].values()) != len(populations):
        raise AssertionError("the state counts do not sum to the population count")

    return {
        "POPULATIONS.json": ca.dump_document(ca.inventory_document(populations)),
        "ADMISSION.json": ca.dump_document(admission),
        "CONTROLS.json": ca.dump_document(ca.controls_document(controls)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=OUT_DIR)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    try:
        documents = build(args.repo_root)
    except ca.Refusal as refusal:
        print(str(refusal), file=sys.stderr)
        return 2
    except AssertionError as error:
        print(f"producer assertion failed: {error}", file=sys.stderr)
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in documents.items():
        (args.out / name).write_text(text, encoding="utf-8")

    totals = ca.admission_document(ca.build_populations(args.repo_root))["totals"]
    print(
        f"populations={totals['populations']} "
        f"admitted={totals['admitted']} refused={totals['refused']} "
        + " ".join(
            f"{state}={count}"
            for state, count in sorted(totals["byState"].items())
            if count
        )
    )
    print(
        "wrote "
        + ", ".join(f"{name} ({len(text.encode('utf-8'))} bytes)"
                    for name, text in documents.items())
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
