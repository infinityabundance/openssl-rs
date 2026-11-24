#!/usr/bin/env python3
"""build_evidence.py -- deterministic producer of the A17 records.

It writes six documents and nothing else:

  * ``FREEZE-a15.json`` -- the expected population of the five
    ``evidence/a15/*.json`` records, frozen before the re-run below;
  * ``FREEZE-forward.json`` -- the expected evidence of the remaining queue
    items A18-A27 and B0-B8, declared **before** that work exists and recorded
    ``OPEN``;
  * ``RECONCILIATION-a15.json`` -- the closure of ``FREEZE-a15.json`` against a
    fresh read-only re-run of ``evidence/a15/build_evidence.py`` into a
    temporary directory;
  * ``RECONCILIATION-a15.envelope.json`` -- a DSSE envelope over the canonical
    bytes of that reconciliation, signed with A10's test-only HMAC-SHA256 key;
  * ``STATUS.json`` -- both cycles, their counts and the forward freeze's
    ``OPEN`` state;
  * ``CONTROLS.json`` -- one ``control-only`` fixture per refusal code, including
    a ``PASS`` summary over a missing member and a signed reconciliation whose
    bytes were mutated after signing.

The A15 re-run writes into a temporary directory and reads no A15 file except to
compare the produced digest with the committed one. Nothing in this producer
edits A15's files.

Two runs are byte-identical. Nothing reads the clock: the freeze time and the
observation time are literals whose order records that the freeze happened
before the re-run in this process.

Usage:
    python3 evidence/a17/build_evidence.py [--out DIR]

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics/tools"
A17 = REPO_ROOT / "evidence/a17"
A15 = REPO_ROOT / "evidence/a15"
sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402
import omission as om  # noqa: E402

BASE_COMMIT = "731b066e261ebc64cf8acb909df18d23b9b11883"
BASE_COMMIT_SHORT = "731b066e2"
ITEM = "A17"
AS_OF = "2026-11-24"

# Literal times: the freeze precedes the A15 re-run in this producer, and the
# observation follows it. No clock is read.
A15_FROZEN_AT = "2026-11-24T00:00:00Z"
A15_OBSERVED_AT = "2026-11-24T00:10:00Z"
FORWARD_FROZEN_AT = "2026-11-24T00:20:00Z"

CANDIDATE = {
    "baseCommit": BASE_COMMIT,
    "baseCommitShort": BASE_COMMIT_SHORT,
    "branch": "staging",
    "recordedAt": AS_OF,
}

A15_MEMBERS = (
    ("a15-approvals", "evidence/a15/APPROVALS.json",
     "the committed approval population, produced by the A15 producer"),
    ("a15-domains", "evidence/a15/DOMAINS.json",
     "the committed trust-domain population, produced by the A15 producer"),
    ("a15-evaluation", "evidence/a15/EVALUATION.json",
     "the committed threshold evaluation, produced by the A15 producer"),
    ("a15-thresholds", "evidence/a15/THRESHOLDS.json",
     "the committed threshold declarations, produced by the A15 producer"),
    ("a15-controls", "evidence/a15/CONTROLS.json",
     "the committed control fixtures, produced by the A15 producer"),
)

# One member per item's required records. A18-A27 each declare a receipt; B0
# declares a registry and the recorded service-configuration finding; B1-B8 each
# declare a receipt. These paths are expectations, not results.
FORWARD_MEMBERS = (
    ("a18-receipt", "evidence/a18/RECEIPT.md",
     "a receipt records the item's result, gates and NOT_RUN obligations", "A18"),
    ("a19-receipt", "evidence/a19/RECEIPT.md",
     "a receipt records the item's result, gates and NOT_RUN obligations", "A19"),
    ("a20-receipt", "evidence/a20/RECEIPT.md",
     "a receipt records the item's result, gates and NOT_RUN obligations", "A20"),
    ("a21-receipt", "evidence/a21/RECEIPT.md",
     "a receipt records the item's result, gates and NOT_RUN obligations", "A21"),
    ("a22-receipt", "evidence/a22/RECEIPT.md",
     "a receipt records the item's result, gates and NOT_RUN obligations", "A22"),
    ("a23-receipt", "evidence/a23/RECEIPT.md",
     "a receipt records the item's result, gates and NOT_RUN obligations", "A23"),
    ("a24-receipt", "evidence/a24/RECEIPT.md",
     "a receipt records the item's result, gates and NOT_RUN obligations", "A24"),
    ("a25-receipt", "evidence/a25/RECEIPT.md",
     "a receipt records the item's result, gates and NOT_RUN obligations", "A25"),
    ("a26-receipt", "evidence/a26/RECEIPT.md",
     "a receipt records the item's result, gates and NOT_RUN obligations", "A26"),
    ("a27-receipt", "evidence/a27/RECEIPT.md",
     "a receipt records the item's result, gates and NOT_RUN obligations", "A27"),
    ("b0-registry", "evidence/b0/REGISTRY.json",
     "a tracked registry names each admitted version, digest and unsupported feature", "B0"),
    ("b0-service-configuration", "evidence/b0/SERVICE-CONFIGURATION.json",
     "the recorded service-configuration finding", "B0"),
    ("b1-receipt", "evidence/b1/RECEIPT.md",
     "a receipt records the frozen statement, inclusion and checkpoint evidence", "B1"),
    ("b2-receipt", "evidence/b2/RECEIPT.md",
     "a receipt records the RFC 3161 timestamp evidence and offline verification", "B2"),
    ("b3-receipt", "evidence/b3/RECEIPT.md",
     "a receipt records the campaign opening, amendments and omission-sensitive closure", "B3"),
    ("b4-receipt", "evidence/b4/RECEIPT.md",
     "a receipt records the publication profile and independent verification", "B4"),
    ("b5-receipt", "evidence/b5/RECEIPT.md",
     "a receipt records checkpoints, consistency, monitoring and witnesses", "B5"),
    ("b6-receipt", "evidence/b6/RECEIPT.md",
     "a receipt records archival, revocation and anti-rollback controls", "B6"),
    ("b7-receipt", "evidence/b7/RECEIPT.md",
     "a receipt records the model, assumptions and refinement gap", "B7"),
    ("b8-receipt", "evidence/b8/RECEIPT.md",
     "a receipt records the enforced integration and its non-claims", "B8"),
)


def write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def source_identity() -> dict[str, Any]:
    return {
        "baseCommit": BASE_COMMIT,
        "baseCommitShort": BASE_COMMIT_SHORT,
        "branch": "staging",
        "recordedAt": AS_OF,
        "tool": om.tool_identity(),
        "delegatedTools": [
            {"path": "forensics/tools/dsse.py",
             "sha256": om.sha256_file(TOOLS / "dsse.py")},
        ],
    }


# ---------------------------------------------------------------------------
# The two real cycles.
# ---------------------------------------------------------------------------


def freeze_a15() -> dict[str, Any]:
    members = [
        {
            "id": member_id,
            "path": path,
            "predicate": predicate,
            "required": True,
            "phase": "A15",
            "expectedDigest": om.sha256_file(REPO_ROOT / path),
        }
        for member_id, path, predicate in A15_MEMBERS
    ]
    plan = {"id": "a15-closed-cycle", "state": om.STATE_FROZEN, "members": members}
    return om.freeze(plan, A15_FROZEN_AT, CANDIDATE)


def freeze_forward() -> dict[str, Any]:
    members = [
        {
            "id": member_id,
            "path": path,
            "predicate": predicate,
            "required": True,
            "phase": phase,
        }
        for member_id, path, predicate, phase in FORWARD_MEMBERS
    ]
    plan = {"id": "forward-open-freeze", "state": om.STATE_OPEN, "members": members}
    return om.freeze(plan, FORWARD_FROZEN_AT, CANDIDATE)


def rerun_a15() -> Path:
    """Re-run the A15 producer into a fresh temporary directory (read-only)."""
    workdir = Path(tempfile.mkdtemp(prefix="a17-a15-rerun-"))
    completed = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "evidence/a15/build_evidence.py"),
            "--out",
            str(workdir),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"the A15 re-run failed ({completed.returncode}): {completed.stderr}"
        )
    return workdir


def close_a15(frozen: Mapping[str, Any]) -> dict[str, Any]:
    workdir = rerun_a15()
    reconciliation = om.close(
        frozen,
        observed_dir=workdir,
        recorded_at=A15_OBSERVED_AT,
        closed_at=A15_OBSERVED_AT,
    )
    summary = reconciliation["summary"]
    if summary["produced"] != 5 or summary["missing"] != 0:
        raise SystemExit(f"the A15 cycle did not produce all five members: {summary}")
    for row in reconciliation["members"]:
        committed = om.sha256_file(REPO_ROOT / row["path"])
        if row["digest"] != committed:
            raise SystemExit(
                f"{row['id']}: produced digest {row['digest']} != committed {committed}"
            )
    if not summary["pass"]:
        raise SystemExit("the A15 cycle is not a passing closure")
    return reconciliation


def status_document(
    frozen_a15: Mapping[str, Any],
    frozen_forward: Mapping[str, Any],
    reconciliation: Mapping[str, Any],
    verified: Mapping[str, Any],
) -> dict[str, Any]:
    present_today = sum(
        1
        for member in frozen_forward["members"]
        if (REPO_ROOT / member["path"]).is_file()
    )
    summary = reconciliation["summary"]
    return {
        "schema": "openssl-rs/a17/status/1",
        "item": ITEM,
        "asOf": AS_OF,
        "candidate": CANDIDATE,
        "sourceIdentity": source_identity(),
        "cycles": [
            {
                "id": "a15-closed-cycle",
                "label": "real closed cycle (backward): freeze, re-run, close, sign, verify",
                "kind": "CLOSED",
                "freeze": "evidence/a17/FREEZE-a15.json",
                "reconciliation": "evidence/a17/RECONCILIATION-a15.json",
                "envelope": "evidence/a17/RECONCILIATION-a15.envelope.json",
                "freezeDigest": frozen_a15["digest"],
                "expected": summary["expected"],
                "produced": summary["produced"],
                "missing": summary["missing"],
                "unreadable": summary["unreadable"],
                "digestMismatch": summary["digestMismatch"],
                "unexpected": summary["unexpected"],
                "pass": summary["pass"],
                "verified": verified["code"] == om.CODE_VERIFIED,
                "signer": verified["keyid"],
                "note": (
                    "all five produced, zero missing, every produced digest equals "
                    "the committed one; the signature is test-only and proves the "
                    "bytes are unchanged, not an independent closure"
                ),
            },
            {
                "id": "forward-open-freeze",
                "label": "real forward freeze (forward): declared before the work exists",
                "kind": "OPEN",
                "state": frozen_forward["state"],
                "freeze": "evidence/a17/FREEZE-forward.json",
                "expected": frozen_forward["memberCount"],
                "presentToday": present_today,
                "missingToday": frozen_forward["memberCount"] - present_today,
                "closed": False,
                "reconciliation": None,
                "note": (
                    "NOT CLOSED. A missing member today is expected: these items "
                    "are TODO. This freeze is the mechanism that will detect a "
                    "future omission; it is not evidence that any of these items "
                    "is done."
                ),
            },
        ],
        "forwardFreeze": {
            "path": "evidence/a17/FREEZE-forward.json",
            "state": frozen_forward["state"],
            "members": frozen_forward["memberCount"],
            "closed": False,
            "reconciliation": None,
        },
    }


# ---------------------------------------------------------------------------
# Controls.
# ---------------------------------------------------------------------------


def _fixture() -> Path:
    directory = Path(tempfile.mkdtemp(prefix="a17-control-"))
    (directory / "a.json").write_bytes(b"control-only bytes\n")
    return directory


def _plan(members: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    if members is None:
        members = [
            {
                "id": "a",
                "path": "evidence/x/a.json",
                "predicate": "the control-only artefact exists",
                "required": True,
                "phase": "control",
            }
        ]
    return {"id": "a17-control", "state": om.STATE_FROZEN, "members": list(members)}


def _freeze(
    plan: Mapping[str, Any] | None = None, frozen_at: str = A15_FROZEN_AT
) -> dict[str, Any]:
    return om.freeze(plan or _plan(), frozen_at, CANDIDATE)


def _observed(
    directory: Path, *, file: str = "a.json", **overrides: Any
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": "a",
        "path": "evidence/x/a.json",
        "file": str(directory / file),
        "readable": True,
        "recordedAt": A15_OBSERVED_AT,
    }
    entry.update(overrides)
    return {"artefacts": [entry]}


def _code(call: Callable[[], Any]) -> str:
    try:
        call()
    except om.Refusal as refusal:
        return refusal.code
    return "NO_REFUSAL"


def _control(
    control_id: str,
    code: str,
    purpose: str,
    call: Callable[[], Any],
) -> dict[str, Any]:
    observed = _code(call)
    return {
        "id": control_id,
        "code": code,
        "controlOnly": True,
        "prevents": om.REFUSALS[code]["prevents"],
        "purpose": purpose,
        "observed": {"codes": [observed]},
    }


def controls_document() -> dict[str, Any]:
    fixture = _fixture()
    frozen = _freeze()
    observed = _observed(fixture)
    good = om.close(frozen, observed, closed_at=A15_OBSERVED_AT)
    missing = om.close(
        frozen,
        _observed(fixture, file="absent.json"),
        closed_at=A15_OBSERVED_AT,
    )
    unreadable = om.close(
        frozen,
        _observed(fixture, readable=False),
        closed_at=A15_OBSERVED_AT,
    )
    extra_observed = {
        "artefacts": observed["artefacts"]
        + [
            {
                "id": "z",
                "path": "evidence/x/z.json",
                "recordedAt": A15_OBSERVED_AT,
            }
        ]
    }
    extra = om.close(frozen, extra_observed, closed_at=A15_OBSERVED_AT)
    digest_mismatch = om.close(
        frozen,
        _observed(fixture, digest="0" * 64),
        closed_at=A15_OBSERVED_AT,
    )
    envelope = om.sign(good)

    controls: list[dict[str, Any]] = []

    controls.append(
        _control(
            "freeze-absent",
            om.OM_REFUSED_FREEZE_ABSENT,
            "closing against no freeze",
            lambda: om.close(None),
        )
    )

    after_execution = _freeze(frozen_at="2026-11-24T02:00:00Z")
    controls.append(
        _control(
            "freeze-after-execution",
            om.OM_REFUSED_FREEZE_AFTER_EXECUTION,
            "frozenAt is later than the earliest produced artefact",
            lambda: om.close(after_execution, observed),
        )
    )

    amended = copy.deepcopy(frozen)
    amended["members"][0]["predicate"] = "changed after execution"
    controls.append(
        _control(
            "freeze-amended",
            om.OM_REFUSED_FREEZE_AMENDED,
            "the freeze bytes no longer hash to the recorded digest",
            lambda: om.close(amended, observed),
        )
    )

    silent = copy.deepcopy(missing)
    silent["members"] = []
    silent["summary"]["missing"] = 0
    silent["summary"]["missingIds"] = []
    controls.append(
        _control(
            "missing-silent",
            om.OM_REFUSED_MISSING_SILENT,
            "the closure omits the MISSING member",
            lambda: om.check(frozen, silent),
        )
    )

    undeclared = copy.deepcopy(extra)
    undeclared["unexpected"] = []
    undeclared["summary"]["unexpected"] = 0
    controls.append(
        _control(
            "unexpected-undeclared",
            om.OM_REFUSED_UNEXPECTED_UNDECLARED,
            "an observed artefact is neither declared nor recorded as UNEXPECTED",
            lambda: om.check(frozen, undeclared, observed=extra_observed),
        )
    )

    controls.append(
        _control(
            "reconciliation-unsigned",
            om.OM_REFUSED_RECONCILIATION_UNSIGNED,
            "verification without an envelope",
            lambda: om.verify(frozen, good, None),
        )
    )

    mutated = copy.deepcopy(good)
    mutated["members"][0]["predicate"] = "mutated after signing"
    controls.append(
        _control(
            "reconciliation-mutated",
            om.OM_REFUSED_RECONCILIATION_MUTATED,
            "the signed bytes and the manifest differ",
            lambda: om.verify(frozen, mutated, envelope),
        )
    )

    duplicate = _plan(
        [
            {
                "id": "a",
                "path": "evidence/x/a.json",
                "predicate": "first",
                "required": True,
                "phase": "control",
            },
            {
                "id": "a",
                "path": "evidence/x/b.json",
                "predicate": "second",
                "required": True,
                "phase": "control",
            },
        ]
    )
    controls.append(
        _control(
            "duplicate-expected",
            om.OM_REFUSED_DUPLICATE_EXPECTED,
            "one expected identity is declared twice",
            lambda: om.freeze(duplicate, A15_FROZEN_AT, CANDIDATE),
        )
    )

    passing_mismatch = copy.deepcopy(digest_mismatch)
    passing_mismatch["summary"]["pass"] = True
    controls.append(
        _control(
            "digest-mismatch",
            om.OM_REFUSED_DIGEST_MISMATCH,
            "a passing summary contains a DIGEST_MISMATCH member",
            lambda: om.check(frozen, passing_mismatch),
        )
    )

    controls.append(
        _control(
            "exit-as-produced",
            om.OM_REFUSED_EXIT_AS_PRODUCED,
            "a non-zero exit is treated as production",
            lambda: om.close(
                frozen, _observed(fixture, exitCode=1), closed_at=A15_OBSERVED_AT
            ),
        )
    )

    passing_missing = copy.deepcopy(missing)
    passing_missing["summary"]["pass"] = True
    controls.append(
        _control(
            "pass-with-missing",
            om.OM_REFUSED_PASS_WITH_MISSING,
            "a PASS summary over a MISSING required member",
            lambda: om.check(frozen, passing_missing),
        )
    )

    controls.append(
        _control(
            "population-drift",
            om.OM_REFUSED_POPULATION_DRIFT,
            "the observed identity differs from the frozen path",
            lambda: om.close(
                frozen,
                {
                    "artefacts": [
                        {
                            "id": "a",
                            "path": "evidence/x/other.json",
                            "file": str(fixture / "a.json"),
                            "recordedAt": A15_OBSERVED_AT,
                        }
                    ]
                },
            ),
        )
    )

    unreadable_as_missing = copy.deepcopy(unreadable)
    unreadable_as_missing["members"][0]["state"] = om.STATE_MISSING
    unreadable_as_missing["summary"]["unreadable"] = 0
    unreadable_as_missing["summary"]["missing"] = 1
    unreadable_as_missing["summary"]["unreadableIds"] = []
    unreadable_as_missing["summary"]["missingIds"] = ["a"]
    controls.append(
        _control(
            "unreadable-as-absent",
            om.OM_REFUSED_UNREADABLE_AS_ABSENT,
            "an unreadable artefact is closed as MISSING",
            lambda: om.check(
                frozen,
                unreadable_as_missing,
                observed=_observed(fixture, readable=False),
            ),
        )
    )

    absent_as_unreadable = copy.deepcopy(missing)
    absent_as_unreadable["members"][0]["state"] = om.STATE_UNREADABLE
    absent_as_unreadable["summary"]["missing"] = 0
    absent_as_unreadable["summary"]["unreadable"] = 1
    absent_as_unreadable["summary"]["missingIds"] = []
    absent_as_unreadable["summary"]["unreadableIds"] = ["a"]
    controls.append(
        _control(
            "absent-as-unreadable",
            om.OM_REFUSED_UNREADABLE_AS_ABSENT,
            "an absent artefact is closed as UNREADABLE",
            lambda: om.check(
                frozen,
                absent_as_unreadable,
                observed=_observed(fixture, file="absent.json"),
            ),
        )
    )

    unbalanced = copy.deepcopy(good)
    unbalanced["summary"]["produced"] = 0
    unbalanced["summary"]["missing"] = 1
    controls.append(
        _control(
            "count-unbalanced",
            om.OM_REFUSED_COUNT_UNBALANCED,
            "the summary's counts do not reconcile with the member rows",
            lambda: om.check(frozen, unbalanced),
        )
    )

    controls.append(
        _control(
            "manifest-invalid",
            om.OM_REFUSED_MANIFEST_INVALID,
            "a freeze plan with no members is not a manifest",
            lambda: om.freeze({}, A15_FROZEN_AT, CANDIDATE),
        )
    )

    tampered = copy.deepcopy(envelope)
    tampered["signatures"][0]["sig"] = dsse.strict_b64encode(b"\x00" * 32)
    controls.append(
        _control(
            "signature-invalid",
            om.OM_REFUSED_SIGNATURE_INVALID,
            "the envelope signature does not verify",
            lambda: om.verify(frozen, good, tampered),
        )
    )

    codes = {control["code"] for control in controls}
    if codes != set(om.REFUSALS):
        missing_codes = sorted(set(om.REFUSALS) - codes)
        raise SystemExit(f"controls do not cover every code: {missing_codes}")
    for control in controls:
        if control["observed"]["codes"] != [control["code"]]:
            raise SystemExit(
                f"control {control['id']} observed {control['observed']['codes']}, "
                f"expected {control['code']}"
            )

    positive = om.verify(frozen, good, envelope)
    return {
        "schema": "openssl-rs/a17/controls/1",
        "item": ITEM,
        "asOf": AS_OF,
        "candidate": CANDIDATE,
        "note": (
            "Every control here is control-only: a synthetic freeze, a synthetic "
            "artefact in a temporary directory and a synthetic reconciliation, all "
            "built in memory from the same code paths the real cycle uses. A "
            "control that fires proves the refusal works; it is not a defect "
            "report and not evidence that the substituted form occurs in the tree. "
            "The positive control establishes the decision procedure, not a real "
            "closure."
        ),
        "controls": controls,
        "positive": {
            "id": "signed-reconciliation-verifies",
            "controlOnly": True,
            "purpose": "a well-formed signed reconciliation reaches OM_VERIFIED",
            "observed": {
                "codes": [positive["code"]],
                "pass": positive["summary"]["pass"],
            },
        },
    }


# ---------------------------------------------------------------------------
# Composition.
# ---------------------------------------------------------------------------


def build() -> tuple[dict[str, Any], ...]:
    frozen_a15 = freeze_a15()
    frozen_forward = freeze_forward()
    reconciliation = close_a15(frozen_a15)
    envelope = om.sign(reconciliation)
    verified = om.verify(frozen_a15, reconciliation, envelope)
    if verified["code"] != om.CODE_VERIFIED:
        raise SystemExit(f"the A15 cycle did not verify: {verified['code']}")
    status = status_document(frozen_a15, frozen_forward, reconciliation, verified)
    controls = controls_document()
    return frozen_a15, frozen_forward, reconciliation, envelope, status, controls


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(A17))
    args = parser.parse_args(argv)

    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)
    frozen_a15, frozen_forward, reconciliation, envelope, status, controls = build()

    write_json(output / "FREEZE-a15.json", frozen_a15)
    write_json(output / "FREEZE-forward.json", frozen_forward)
    write_json(output / "RECONCILIATION-a15.json", reconciliation)
    (output / "RECONCILIATION-a15.envelope.json").write_bytes(
        dsse.encode_envelope(envelope)
    )
    write_json(output / "STATUS.json", status)
    write_json(output / "CONTROLS.json", controls)

    summary = reconciliation["summary"]
    print(
        f"a17: a15 expected={summary['expected']} produced={summary['produced']} "
        f"missing={summary['missing']} unreadable={summary['unreadable']} "
        f"digestMismatch={summary['digestMismatch']} unexpected={summary['unexpected']} "
        f"pass={str(summary['pass']).lower()} forward={frozen_forward['memberCount']} "
        f"forwardState={frozen_forward['state']} "
        f"controls={controls['controls'].__len__()} codes={len(om.REFUSALS)} "
        f"commit={BASE_COMMIT_SHORT}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
