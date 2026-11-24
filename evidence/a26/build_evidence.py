#!/usr/bin/env python3
"""evidence/a26/build_evidence.py -- the deterministic A26 producer.

The producer does not measure anything.  It takes the measured values as an
input (``MEASUREMENTS.json``), the declared budget as an input (``POLICY.json``),
validates both against the cost rules, runs the control suite, and writes the
three records.  Re-running it reproduces the same bytes because the timings are
inputs, not outputs: a timing is a measurement at a named time, not a
deterministic artefact.

    python3 evidence/a26/build_evidence.py [--out DIR]
        [--measurements PATH] [--policy PATH]

Exit status describes the evidence: 0 when every record validates, every control
fires, and no tier is over budget; 1 otherwise.  The records are written either
way, so a red result is readable.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics/tools"
DEFAULT_OUT = REPO_ROOT / "evidence/a26"
DEFAULT_MEASUREMENTS = DEFAULT_OUT / "MEASUREMENTS.json"
DEFAULT_POLICY = DEFAULT_OUT / "POLICY.json"
sys.path.insert(0, str(TOOLS))

import verification_economics as ve  # noqa: E402

REQUIRED_MEASURED_STEPS = (
    "a23-differential",
    "a8-export",
    "a8-export-verify",
    "a24-package-verify",
    "a22-qualification-run",
)
REQUIRED_NOT_RUN_STEPS = ("verify-all", "rust-library-suite", "external-reproduction")


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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stamp(document: dict) -> dict:
    stamped = dict(document)
    stamped["producer"] = {
        "path": "evidence/a26/build_evidence.py",
        "sha256": _sha256(Path(__file__).resolve()),
        "tool": {
            "path": "forensics/tools/verification_economics.py",
            "sha256": _sha256(TOOLS / "verification_economics.py"),
        },
    }
    return stamped


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="produce the A26 cost records")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--measurements", default=str(DEFAULT_MEASUREMENTS))
    parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    measurements = _load(Path(args.measurements))
    policy = _load(Path(args.policy))
    records = measurements.get("records") if isinstance(measurements, dict) else measurements
    if not isinstance(records, list):
        raise SystemExit("build_evidence: the measurements document holds a records list")
    candidate = policy.get("candidate")
    if measurements.get("candidate") != candidate:
        raise SystemExit(
            "build_evidence: the measurements candidate "
            f"{measurements.get('candidate')!r} is not the policy candidate {candidate!r}"
        )

    present = {record.get("step") for record in records if isinstance(record, dict)}
    missing_measured = [step for step in REQUIRED_MEASURED_STEPS if step not in present]
    missing_not_run = [step for step in REQUIRED_NOT_RUN_STEPS if step not in present]
    if missing_measured or missing_not_run:
        raise SystemExit(
            "build_evidence: required steps absent: "
            f"measured={missing_measured} notRun={missing_not_run}"
        )

    controls = ve.build_controls()
    if not controls["coversEveryCode"]:
        raise SystemExit("build_evidence: the controls do not cover every refusal code")
    if controls["failing"]:
        raise SystemExit(f"build_evidence: controls did not fire: {controls['failing']}")

    problems = ve.validate_records(records, policy)
    costs = _stamp(ve.costs_document(records, candidate=candidate,
                                     units=policy.get("units")))
    budget = _stamp(ve.budget(records, policy))

    documents = {
        "COSTS.json": serialise(costs),
        "BUDGET.json": serialise(budget),
        "CONTROLS.json": serialise(_stamp(ve.build_controls())),
    }
    for name, payload in documents.items():
        write(out / name, payload)

    codes = sorted(({item["code"] for item in problems} | set(budget["codes"])) - {"EC_OK"})
    print(
        f"a26: candidate={candidate} records={len(records)} "
        f"measured={costs['totals']['measuredSteps']} "
        f"notRun={costs['totals']['notRunSteps']} "
        f"controls={len(controls['controls'])} "
        f"codesCovered={len({c['code'] for c in controls['controls']})}/{len(ve.REFUSALS)} "
        f"failing={len(controls['failing'])} overall={budget['overall']} "
        f"codes={','.join(codes) if codes else 'NONE'} out={out}"
    )
    return 0 if not problems and budget["overall"] == "UNDER" and not codes else 1


if __name__ == "__main__":
    sys.exit(main())
