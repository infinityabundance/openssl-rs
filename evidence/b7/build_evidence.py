#!/usr/bin/env python3
"""Deterministic producer of the B7 records.

The model is declared in ``forensics/tools/transparency_model.py`` and described
in ``docs/TRANSPARENCY-FORMAL-ASSURANCE.md``.  This producer runs the model, the
exhaustive enumeration, the canaries, the differential against the real modules
and the controls, then writes five records:

    python3 evidence/b7/build_evidence.py [--out DIR] [--check]

The default output directory is this file's directory.  ``--out`` exists so the
gate can compare two runs; ``--check`` re-derives the records in memory and
compares them with the committed bytes.  No timestamp is written anywhere, every
array is built in a deterministic order, and two runs over the same tree
reproduce the same bytes.

The producer exits 0 only when every record agrees.  A violation, a missed
canary, a differential disagreement or an unsourced clause is preserved in the
record it concerns and the process exits 1 with that refusal code.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import transparency_model as bm  # noqa: E402

HERE = Path(__file__).resolve().parent
BASE_COMMIT = "554acc9d0"
TOOL = "forensics/tools/transparency_model.py"
DOCUMENT = "docs/TRANSPARENCY-FORMAL-ASSURANCE.md"


def enumeration_record(bound: int) -> tuple[dict[str, Any], dict[str, Any]]:
    enumeration = bm.enumerate_model(bound)
    canaries = bm.run_canaries(bound)
    record = {
        "schema": bm.SCHEMA_ENUMERATION,
        "item": "B7 of docs/ETP-TODO.md",
        "baseCommit": BASE_COMMIT,
        "tool": TOOL,
        "document": DOCUMENT,
        "bound": enumeration["bound"],
        "alphabet": enumeration["alphabet"],
        "alphabetSize": enumeration["alphabetSize"],
        "sequenceSpace": enumeration["sequenceSpace"],
        "sequences": enumeration["sequences"],
        "statesReached": enumeration["statesReached"],
        "statesExpanded": enumeration["statesExpanded"],
        "statesChecked": enumeration["statesChecked"],
        "transitionsExplored": enumeration["transitionsExplored"],
        "maxDepthReached": enumeration["maxDepthReached"],
        "refusalsByCode": enumeration["refusalsByCode"],
        "invariants": enumeration["invariants"],
        "violations": enumeration["violations"],
        "violationCount": enumeration["violationCount"],
        "canary": canaries,
        "code": enumeration["code"],
    }
    return record, enumeration


def build_records(bound: int = bm.BOUND) -> dict[str, dict[str, Any]]:
    model = bm.model_record()
    bm.validate_model(model)

    enumeration, raw = enumeration_record(bound)
    canaries = enumeration["canary"]
    bm.validate_enumeration(raw, model, canaries)

    differential_record = bm.differential()
    bm.assert_differential(differential_record)

    refinement = bm.build_refinement(raw, differential_record)
    bm.validate_refinement(refinement, differential_record)

    controls = bm.controls_record()
    bm.assert_controls(controls["controls"])

    return {
        "MODEL.json": model,
        "ENUMERATION.json": enumeration,
        "DIFFERENTIAL.json": differential_record,
        "REFINEMENT.json": refinement,
        "CONTROLS.json": controls,
    }


def write_records(records: dict[str, dict[str, Any]], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, record in records.items():
        (out / name).write_bytes(bm.pretty(record))


def check_records(records: dict[str, dict[str, Any]], out: Path) -> list[str]:
    problems = []
    for name, record in records.items():
        target = out / name
        if not target.is_file():
            problems.append(f"{name} is absent")
            continue
        if target.read_bytes() != bm.pretty(record):
            problems.append(f"{name} differs from the derived record")
    return problems


def summary(records: dict[str, dict[str, Any]]) -> str:
    enumeration = records["ENUMERATION.json"]
    differential = records["DIFFERENTIAL.json"]
    refinement = records["REFINEMENT.json"]
    controls = records["CONTROLS.json"]
    matched = sum(
        1 for row in refinement["invariants"] if row["status"] == "MODEL_AND_MATCHED"
    )
    return (
        f"code={bm.CODE_OK} b7: bound={enumeration['bound']} "
        f"alphabet={enumeration['alphabetSize']} "
        f"sequences={enumeration['sequences']} states={enumeration['statesReached']} "
        f"violations={enumeration['violationCount']} "
        f"canaries={len(enumeration['canary']['canaries'])} "
        f"canariesDetected={str(enumeration['canary']['allDetected']).lower()} "
        f"compared={differential['compared']} "
        f"agreed={differential['agreed']} "
        f"notRun={differential['notRunCount']} "
        f"matched={matched}/{len(refinement['invariants'])} "
        f"controls={len(controls['controls'])} codes={len(controls['codesCovered'])}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Produce the B7 model, enumeration, differential, refinement and "
            "control records."
        )
    )
    parser.add_argument(
        "--out",
        default=str(HERE),
        help="output directory (default: this file's directory)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare the committed records with a fresh derivation",
    )
    parser.add_argument(
        "--bound",
        type=int,
        default=bm.BOUND,
        help=f"sequence bound (default {bm.BOUND})",
    )
    arguments = parser.parse_args(sys.argv[1:] if argv is None else list(argv))
    out = Path(arguments.out)
    try:
        records = build_records(arguments.bound)
    except bm.Refusal as refusal:
        print(f"code={refusal.code} b7: {refusal.message}")
        return 1
    if arguments.check:
        problems = check_records(records, out)
        if problems:
            print(f"code=BM_REFUSED_MODEL_INCOMPLETE b7: {'; '.join(problems)}")
            return 1
        print(
            f"code={bm.CODE_OK} b7: check ok files={len(records)} "
            f"bound={records['ENUMERATION.json']['bound']} "
            f"states={records['ENUMERATION.json']['statesReached']}"
        )
        return 0
    write_records(records, out)
    print(summary(records))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
