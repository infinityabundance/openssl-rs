#!/usr/bin/env python3
"""evidence/a22/build_evidence.py -- the deterministic A22 producer.

It runs the eight experiments twice each (the two runs are compared, so an
unstable measurement is a refusal rather than a result), builds the three
records from what it observed, checks the producer's own preconditions, and
writes the bytes.

The exit status describes the **evidence**, not the process: the records are
written either way, and the status is 0 only when all eight experiments ran and
every one was ``QUALIFIED``. A ``DEFECT``, ``PARTIAL`` or ``NOT_RUN`` is written
into the record and reported, and makes the status 1. That is deliberate: a
producer that exits 0 after finding a defect would be the same fail-open the
item exists to find.

Preconditions that stop the write entirely:

* every refusal code has a control that establishes it (the canary and the
  refusal codes are not decoration);
* every experiment's canary is detected, because a harness that cannot report
  ``DEFECT`` is not producing evidence;
* the declared witness set in ``EXPERIMENTS.json`` equals the observed case set,
  so the design document cannot drift from the measurement.

Usage:

    python3 evidence/a22/build_evidence.py [--out DIR] [--runs N]

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics/tools"
DEFAULT_OUT = REPO_ROOT / "evidence/a22"
sys.path.insert(0, str(TOOLS))

import adversarial_qualification as aq  # noqa: E402


def serialise(document: dict) -> bytes:
    return (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def write(path: Path, payload: bytes) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_bytes(payload)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="produce the A22 records")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--runs", type=int, default=2)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    results = aq.run_all(runs=args.runs)
    controls = aq.build_controls()

    if not controls["coversEveryCode"]:
        missing = sorted(
            set(aq.REFUSALS)
            - {control["code"] for control in controls["controls"] if control["code"]}
        )
        raise aq.Refusal(aq.AQ_REFUSED_EXPECTED_ABSENT, f"no control establishes {missing}")

    undetected = [
        result.spec.id
        for result in results
        if result.canary is None or not result.canary.detected
    ]
    if undetected:
        raise aq.Refusal(
            aq.AQ_REFUSED_CANARY_NOT_DETECTED,
            f"the canary was not detected for {undetected}; the harness is not producing evidence",
        )

    experiments = aq.experiments_document()
    declared = {
        entry["id"]: [witness["case"] for witness in entry["witnesses"]]
        for entry in experiments["experiments"]
    }
    for result in results:
        observed = [item.case for item in result.observations]
        if sorted(declared.get(result.spec.id, [])) != sorted(observed):
            raise aq.Refusal(
                aq.AQ_REFUSED_WITNESS_ABSENT,
                f"{result.spec.id}: declared witnesses {sorted(declared.get(result.spec.id, []))} "
                f"do not equal the observed ones {sorted(observed)}",
            )

    documents = {
        "EXPERIMENTS.json": serialise(experiments),
        "RESULTS.json": serialise(aq.results_document(results, runs=args.runs)),
        "CONTROLS.json": serialise(aq.controls_document(controls, results)),
    }
    for name, payload in documents.items():
        write(out / name, payload)

    totals = aq.summary(results)
    base = aq._base_commit()
    print(
        f"a22: base={base[:9]} experiments={totals['experiments']} "
        f"qualified={totals['qualified']} defect={totals['defect']} "
        f"partial={totals['partial']} notRun={totals['notRun']} "
        f"allQualified={str(totals['allQualified']).lower()} "
        f"codes={','.join(totals['codes']) if totals['codes'] else 'NONE'} "
        f"controls={len(controls['controls'])} codesCovered="
        f"{len({c['code'] for c in controls['controls'] if c['code']})}/{len(aq.REFUSALS)} "
        f"canariesDetected={sum(1 for r in results if r.canary and r.canary.detected)}"
        f"/{len(results)} out={out}"
    )
    for result in results:
        print(f"a22: {result.spec.id} {result.verdict} -- {result.reason}")
    return 0 if totals["allQualified"] else 1


if __name__ == "__main__":
    sys.exit(main())
