#!/usr/bin/env python3
"""evidence/a26/measure.py -- take the A26 cost measurements.

This is the measurement harness, not the producer.  Re-running it *re-measures*:
wall, CPU and peak RSS differ between runs, so its output is a measurement at a
named time and is deliberately not a deterministic artefact.  ``build_evidence.py``
takes the resulting ``MEASUREMENTS.json`` as an input and reproduces the records
byte for byte.

    python3 evidence/a26/measure.py --fresh
    python3 evidence/a26/measure.py --step tools-discovery

``--fresh`` rewrites the file with every step except the full discovery plus the
three NOT_RUN entries.  ``--step NAME`` measures just that step and merges it
into the existing file, which is how the full discovery is added after the
records it reads already exist.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics/tools"
OUT = REPO_ROOT / "evidence/a26/MEASUREMENTS.json"
sys.path.insert(0, str(TOOLS))

import verification_economics as ve  # noqa: E402

CANDIDATE = "46f3857722e1a79c0756e7d1b495782aac259687"

STEPS = {
    "docs-consistency": (
        "FAST",
        "forensics/tools/docs_consistency.py",
        [sys.executable, "forensics/tools/docs_consistency.py"],
        [],
        ["forensics/tools/docs_consistency.py", "forensics/tools/earned_trust.py"],
    ),
    "spec-guard-check": (
        "FAST",
        "forensics/tools/spec_guard.py check",
        [sys.executable, "forensics/tools/spec_guard.py", "check"],
        [],
        ["forensics/tools/spec_guard.py", "evidence/etp-t3/SPECIFICATIONS.json"],
    ),
    "a23-differential": (
        "BATCH",
        "forensics/tools/verifier_formalisation.py differential",
        [sys.executable, "forensics/tools/verifier_formalisation.py", "differential"],
        [],
        ["forensics/tools/verifier_formalisation.py"],
    ),
    "a8-export": (
        "BATCH",
        "forensics/tools/code_scanning_export.py emit",
        [sys.executable, "forensics/tools/code_scanning_export.py", "emit", "/tmp/a26-a8-export"],
        ["/tmp/a26-a8-export"],
        ["forensics/tools/code_scanning_export.py", "evidence/a1/SARIF.json"],
    ),
    "a8-export-verify": (
        "BATCH",
        "forensics/tools/code_scanning_export.py verify",
        [sys.executable, "forensics/tools/code_scanning_export.py", "verify", "/tmp/a26-a8-export"],
        [],
        ["forensics/tools/code_scanning_export.py", "evidence/a8/MANIFEST.json", "evidence/a8/SHARD-000.sarif"],
    ),
    "tools-discovery": (
        "BATCH",
        "python3 -m unittest discover -s forensics/tools/tests",
        [sys.executable, "-m", "unittest", "discover", "-s", "forensics/tools/tests"],
        [],
        ["forensics/tools/tests", "docs/PUBLIC-VERIFICATION.md"],
    ),
    "a24-package-verify": (
        "BOUNDARY",
        "forensics/tools/package_external.py verify evidence/a24/PACKAGE",
        [sys.executable, "forensics/tools/package_external.py", "verify", "evidence/a24/PACKAGE"],
        [],
        ["forensics/tools/package_external.py", "evidence/a24/PACKAGE", "evidence/a24/RUN.json"],
    ),
    "a22-qualification-run": (
        "BOUNDARY",
        "forensics/tools/adversarial_qualification.py run",
        [sys.executable, "forensics/tools/adversarial_qualification.py", "run"],
        [],
        ["forensics/tools/adversarial_qualification.py", "docs/ADVERSARIAL-QUALIFICATION.md"],
    ),
}

FRESH_STEPS = tuple(name for name in STEPS if name != "tools-discovery")

NOT_RUN = (
    ve.not_run(
        "verify-all",
        "SEAL",
        "verify all includes rebuild and differential, which require a Rust build; "
        "free -g reported available below the 24 GiB floor and the court cap is 6 GiB, "
        "so no build was started",
        "decision: the 24 GiB floor and the 6 GiB court",
        candidate=CANDIDATE,
        cited_by=["docs/PUBLIC-VERIFIER.md", "AGENTS.md#6.1"],
    ),
    ve.not_run(
        "rust-library-suite",
        "BATCH",
        "the Rust library suite requires a build; available memory is below the 24 GiB "
        "floor AGENTS.md 6.1 sets before a build and the court cap is 6 GiB",
        "decision: the 24 GiB floor and the 6 GiB court",
        candidate=CANDIDATE,
        cited_by=["AGENTS.md#6.1", "forensics/tools/verify.py"],
    ),
    ve.not_run(
        "external-reproduction",
        "EXTERNAL",
        "no party outside this project has run the A24 package; A24 records "
        "EXTERNAL_REVIEW_PENDING",
        "decision: A24 external status",
        candidate=CANDIDATE,
        cited_by=["evidence/a24/STATUS.json", "evidence/a24/RUN.json"],
    ),
)


def _write(records: list[dict]) -> None:
    document = {
        "schema": "openssl-rs/verification-economics/measurements/1",
        "item": "A26",
        "candidate": CANDIDATE,
        "recordedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "machine": ve.machine("openssl-rs-court-tools:1 (container openssl-rs-court)"),
        "method": (
            "os.wait4 per command in the reused 6 GiB court; wall is monotonic elapsed, "
            "cpu is the child's ru_utime+ru_stime, peakRssMiB is ru_maxrss/1024; one "
            "command at a time; re-measuring changes the timings"
        ),
        "records": sorted(
            records,
            key=lambda r: (ve.TIERS.index(r["tier"]), r["step"]),
        ),
    }
    OUT.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="take the A26 cost measurements")
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--step", action="append", default=[])
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if args.fresh:
        records: list[dict] = list(NOT_RUN)
        selected = list(FRESH_STEPS)
    else:
        if not OUT.exists():
            raise SystemExit("measure: no MEASUREMENTS.json; run --fresh first")
        records = list(json.loads(OUT.read_text(encoding="utf-8"))["records"])
        if not args.step:
            raise SystemExit("measure: name at least one --step, or use --fresh")
        selected = list(args.step)

    for name in selected:
        if name not in STEPS:
            raise SystemExit(f"measure: unknown step {name!r}")
        tier, method, command, artefacts, cites = STEPS[name]
        observation = ve._run_timed(command, cwd=str(REPO_ROOT), timeout=1800)
        combined = (observation["stdout"] + observation["stderr"]).strip()
        print(
            f"== {name} exit={observation['exitStatus']} "
            f"wall={observation['wallSeconds']}s cpu={observation['cpuSeconds']}s "
            f"rss={observation['peakRssMiB']}MiB timedOut={observation['timedOut']}"
        )
        print(combined[-4000:])
        record = ve.record_from(
            command,
            tier,
            method,
            observation,
            step=name,
            candidate=CANDIDATE,
            cited_by=cites,
            artefact_paths=artefacts,
        )
        records = [r for r in records if r.get("step") != name]
        records.append(record)

    _write(records)
    print(f"measure: wrote {OUT.relative_to(REPO_ROOT)} with {len(records)} records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
