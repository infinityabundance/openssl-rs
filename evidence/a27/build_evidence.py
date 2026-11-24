#!/usr/bin/env python3
"""evidence/a27/build_evidence.py -- the deterministic A27 producer.

The producer runs the vertical slice against the committed records and writes the
three A27 records. It does not re-run any live stage: every stage reads the
committed record it consumes, so re-running this producer reproduces the same
bytes. The trace is a function of the records, not of a tool's runtime state.

    python3 evidence/a27/build_evidence.py [--out DIR]

Exit status describes the evidence: 0 when the real trace validates, the chain
stops at A12 with zero independent verifications, every control fires, and the
committed A20 decision denies and names the same source records; 1 otherwise.
The records are written either way, so a red result is readable.

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
DEFAULT_OUT = REPO_ROOT / "evidence/a27"
sys.path.insert(0, str(TOOLS))

import vertical_slice as vs  # noqa: E402


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stamp(document: dict) -> dict:
    stamped = dict(document)
    stamped["producedBy"] = {
        "path": "evidence/a27/build_evidence.py",
        "sha256": _sha256(Path(__file__).resolve()),
        "tool": {
            "path": "forensics/tools/vertical_slice.py",
            "sha256": _sha256(TOOLS / "vertical_slice.py"),
        },
    }
    return stamped


def _write(path: Path, document: dict) -> bytes:
    payload = vs._serialise(document)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_bytes(payload)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="produce the A27 vertical-slice records")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    document = vs.build_slice(REPO_ROOT)
    trace = document["trace"]
    problems: list[str] = []

    trace_codes = vs.validate_trace(trace, root=REPO_ROOT)
    trace_codes += vs.check_stop_binding(REPO_ROOT, trace)
    if trace_codes:
        problems.extend(f"trace:{code}" for code in trace_codes)
    if document["counts"]["stopped"] != 1:
        problems.append(f"stop-count:{document['counts']['stopped']}")
    if document["counts"]["notReached"] != len(vs.STAGE_ORDER) - 9:
        problems.append(f"not-reached:{document['counts']['notReached']}")
    stop = vs.first_stop(trace)
    if stop is None:
        problems.append("stop:absent")
    else:
        if stop["stage"] != "A12":
            problems.append(f"stop-stage:{stop['stage']}")
        if stop["code"] != vs.VS_STOP_NO_INDEPENDENT_VERIFICATION:
            problems.append(f"stop-code:{stop['code']}")
        observed = (stop.get("establishedBy") or {}).get("observed") or {}
        if observed.get("outcome") != "SELF_ISSUED":
            problems.append(f"stop-outcome:{observed.get('outcome')}")
        if int(observed.get("independentlyVerifiedEnvelopes", -1)) != 0:
            problems.append(
                f"stop-independent:{observed.get('independentlyVerifiedEnvelopes')}"
            )

    policy = document["wouldBe"]["policy"]
    if policy["decision"] != "DENY":
        problems.append(f"policy:{policy['decision']}")
    if not policy["sourceRecordsMatchCurrentTree"]:
        problems.append("policy:stale-source-records:" + ",".join(policy["sourceRecordsMismatched"]))
    attestation = policy.get("attestation") or {}
    if attestation.get("state") != "UNMET":
        problems.append(f"policy:attestation:{attestation.get('state')}")
    if int((attestation.get("observed") or {}).get("count", -1)) != 0:
        problems.append(f"policy:attestation-count:{(attestation.get('observed') or {}).get('count')}")

    controls = vs.build_controls(REPO_ROOT)
    if not controls["coversEveryCode"]:
        problems.append("controls:missing:" + ",".join(controls["codesMissing"]))
    if controls["failing"]:
        problems.append("controls:failing:" + ",".join(controls["failing"]))

    slice_document = _stamp(document)
    slice_bytes = _write(out / "SLICE.json", slice_document)

    stops_document = _stamp(vs.build_stops(document))
    stops_document["slice"] = "evidence/a27/SLICE.json"
    stops_document["sliceSha256"] = hashlib.sha256(slice_bytes).hexdigest()
    _write(out / "STOPS.json", stops_document)

    controls_document = _stamp(controls)
    controls_document["slice"] = "evidence/a27/SLICE.json"
    controls_document["sliceSha256"] = hashlib.sha256(slice_bytes).hexdigest()
    _write(out / "CONTROLS.json", controls_document)

    print(
        f"a27: artefact={document['artefact']['id']} "
        f"exact={document['artefact']['fingerprints']['a1Exact/v1'][:12]} "
        f"stages={document['counts']['stages']} "
        f"passed={document['counts']['passed']} stopped={document['counts']['stopped']} "
        f"notReached={document['counts']['notReached']} "
        f"stop={stop['stage'] if stop else 'NONE'} "
        f"code={stop['code'] if stop else 'NONE'} "
        f"policy={policy['decision']} "
        f"controls={sum(1 for row in controls['controls'] if row['fired'])}"
        f"/{len(controls['controls'])} "
        f"codes={','.join(problems) if problems else 'NONE'} out={out}"
    )
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
