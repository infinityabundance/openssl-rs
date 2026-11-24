#!/usr/bin/env python3
"""Deterministic producer of the A21 records.

The summary is computed from A20's committed decision, the sources it cites and
the policy that supplied the mapping; it is signed as a DSSE envelope, then
reconstructed from the cited bytes. Nothing is typed by hand: the obligations,
counts, unmet set, source paths and digests are all read. No timestamp is
written, every array is sorted by the writer, and two runs over the same records
reproduce the same bytes.

    python3 evidence/a21/build_evidence.py [--out DIR]

The default output directory is this file's directory. ``--out`` exists so the
gate can compare two runs, and so a refusal can be inspected without touching the
committed records.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "forensics/tools"
sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402
import policy_engine as pe  # noqa: E402
import verification_summary as vs  # noqa: E402

HERE = Path(__file__).resolve().parent
BASE_COMMIT = "ad49d33f2"


def load_json(path: Path) -> Any:
    return pe.parse_json(path.read_bytes())


def write(path: Path, value: Any) -> None:
    path.write_bytes(
        (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
            "utf-8"
        )
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(HERE))
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    decision = load_json(REPO / vs.DECISION_PATH)
    summary = vs.summarise(decision, pe.filesystem_reader(REPO))
    statement, envelope = vs.sign_summary(summary, repo=REPO)
    summary_bytes = vs.encode_summary(summary)
    envelope_bytes = dsse.encode_envelope(envelope)

    verified = vs.verify_summary(summary_bytes, envelope_bytes, REPO)
    if not verified["equal"]:
        raise SystemExit(
            "a21: the produced summary does not reconstruct to itself: "
            f"{verified['counts']}"
        )

    reconstruction = vs.reconstruct(summary, REPO)
    if not reconstruction["equal"]:
        raise SystemExit(
            "a21: the produced reconstruction does not equal the summary: "
            f"{reconstruction['counts']}"
        )
    controls = vs.controls_document()

    (out / "SUMMARY.json").write_bytes(summary_bytes)
    (out / "SUMMARY.envelope.json").write_bytes(envelope_bytes)
    write(out / "RECONSTRUCTION.json", reconstruction)
    write(out / "CONTROLS.json", controls)

    counts = summary["counts"]
    print(
        "a21: "
        f"decision={summary['decision']} obligations={len(summary['obligations'])} "
        f"met={counts['met']} unmet={counts['unmet']} unknown={counts['unknown']} "
        f"notApplicable={counts['notApplicable']} sources={len(summary['reconstructedFrom'])} "
        f"topLevel={summary['topLevel']} "
        f"replacesEvidence={str(summary['replacesEvidence']).lower()} "
        f"decisionDigest={summary['decisionDigest'][:16]} "
        f"summaryDigest={vs.summary_digest(summary)[:16]} "
        f"label={vs.SIGNATURE_LABEL} keyid={dsse.test_only_keyid()} "
        f"controls={controls['totals']['controls']} "
        f"codesCovered={controls['totals']['coveredCodes']}/{controls['totals']['refusalCodes']} "
        f"commit={BASE_COMMIT}"
    )
    print(
        f"a21: unmet = {','.join(summary['unmet']) if summary['unmet'] else 'NONE'}"
    )
    return vs.EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
