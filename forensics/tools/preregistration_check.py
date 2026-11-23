#!/usr/bin/env python3
"""Refuse a timing receipt whose run does not match its preregistration.

The checker normalises a receipt through the adapter named by the selected
preregistration instance, then requires:

* the preregistration digest recorded by a prospective receipt;
* the instance identity and the measured artefact digest;
* the harness source digest and a recorded harness binary digest when the
  instance requires harness identity;
* every declared mode, and no undeclared mode;
* a whole number of batches, inside the registered batch budget, with the
  reported count equal to total/per_batch;
* no failed operation inside a measured mode;
* the positive control to leave its registered direction and the negative
  control to stay in its registered direction;
* the exclusion set not to have changed after the run.

A failure prints a named code and exits 1. `--self-test` proves that the
committed prospective and reconstructed receipts pass and that ten mutations
are refused.

Run inside the court:

    python3 forensics/tools/preregistration_check.py \
        --prereg evidence/etp-t7/PREREGISTRATION.json \
        --instance ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1 \
        --receipt evidence/etp-t7/DUDECT-ETP-T7.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

PREREG_SCHEMA = "openssl-rs/etp-t7/preregistration/1"


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _from_log(name: str, entry: dict, repo_root: Path) -> tuple[int, int, int]:
    """Read total, batches and per_batch from a recorded dudect transcript."""
    import hashlib
    import re

    log = entry.get("log") or {}
    path_text = log.get("path")
    if not isinstance(path_text, str):
        raise ValueError(f"{name}: no ops count and no recorded log")
    path = repo_root / path_text
    if not path.is_file():
        raise ValueError(f"{name}: recorded log {path_text} is absent")
    raw = path.read_bytes()
    if log.get("sha256") and hashlib.sha256(raw).hexdigest() != log["sha256"]:
        raise ValueError(f"{name}: recorded log digest does not match")
    match = re.search(
        rf"dudect\.executed mode={re.escape(name)} per_batch=(\d+) batches_run=(\d+) total_measurements=(\d+)",
        raw.decode("utf-8", errors="replace"),
    )
    if match is None:
        raise ValueError(f"{name}: the log has no dudect.executed line for this mode")
    per_batch, batches, total = (int(value) for value in match.groups())
    return total, batches, per_batch


def _normalise(
    receipt: dict, adapter: str, per_batch: int, repo_root: Path
) -> dict[str, dict]:
    raw = receipt.get("modes")
    if not isinstance(raw, dict):
        raise ValueError("receipt has no modes object")
    modes: dict[str, dict] = {}
    for name, entry in raw.items():
        if adapter == "native_v1":
            total = entry.get("total_measurements")
            batches = entry.get("batches_run")
            failures = entry.get("failures", 0)
        elif adapter == "dudect_modes_v1":
            ops = entry.get("ops")
            if isinstance(ops, str) and "/" in ops:
                total_text, failures_text = ops.split("/", 1)
                total = int(total_text)
                failures = int(failures_text)
                if total % per_batch != 0:
                    raise ValueError(f"{name}: total {total} is not a multiple of {per_batch}")
                batches = total // per_batch
            else:
                total, batches, log_per_batch = _from_log(name, entry, repo_root)
                failures = 0
                if log_per_batch != per_batch:
                    raise ValueError(
                        f"{name}: log per_batch {log_per_batch} disagrees with the registered {per_batch}"
                    )
        else:
            raise ValueError(f"unknown adapter {adapter}")
        if not isinstance(total, int) or not isinstance(batches, int):
            raise ValueError(f"{name}: total/batches are not integers")
        modes[name] = {
            "total": total,
            "batches": batches,
            "failures": int(failures),
            "state": entry.get("state"),
        }
    return modes


def check(
    prereg_path: Path,
    receipt_path: Path,
    instance_id: str | None = None,
    repo_root: Path | None = None,
) -> list[tuple[str, str]]:
    if repo_root is None:
        repo_root = prereg_path.resolve().parents[2]
    prereg = load_json(prereg_path)
    receipt = load_json(receipt_path)
    problems: list[tuple[str, str]] = []

    if prereg.get("schema") != PREREG_SCHEMA:
        return [("PR_BAD_RECEIPT", f"prereg schema is {prereg.get('schema')!r}")]
    instances = prereg.get("instances") or []
    if instance_id is None:
        instance_id = receipt.get("instance_id")
    instance = next((item for item in instances if item.get("id") == instance_id), None)
    if instance is None:
        return [("PR_INSTANCE_MISMATCH", f"no instance {instance_id!r} in the preregistration")]

    adapter = instance.get("receipt_adapter")
    geometry = instance.get("geometry") or {}
    per_batch = geometry.get("per_batch")
    max_batches = geometry.get("max_batches")
    if not isinstance(per_batch, int) or not isinstance(max_batches, int):
        return [("PR_BAD_RECEIPT", "the instance has no usable geometry")]

    if instance.get("status") == "PROSPECTIVE":
        declared = instance.get("registered_at") is not None
        if not declared:
            problems.append(("PR_BAD_RECEIPT", "a prospective instance has no registered_at"))
        expected_digest = hashlib.sha256(prereg_path.read_bytes()).hexdigest()
        if receipt.get("preregistration_sha256") != expected_digest:
            problems.append(
                (
                    "PR_PREREG_DIGEST_MISMATCH",
                    f"receipt quotes {receipt.get('preregistration_sha256')!r}, now {expected_digest}",
                )
            )
        if receipt.get("instance_id") != instance["id"]:
            problems.append(
                ("PR_INSTANCE_MISMATCH", f"receipt instance {receipt.get('instance_id')!r}")
            )

    candidate = instance.get("candidate") or {}
    expected_dso = candidate.get("libcrypto_sha256")
    if expected_dso:
        got = (receipt.get("candidate") or {}).get("libcrypto_sha256")
        if got != expected_dso:
            problems.append(
                ("PR_CANDIDATE_MISMATCH", f"receipt artefact {got!r}, registered {expected_dso!r}")
            )

    if instance.get("require_harness_identity") is True:
        harness = receipt.get("harness") or {}
        instrument = instance.get("instrument") or {}
        if harness.get("source_sha256") != instrument.get("harness_sha256"):
            problems.append(
                (
                    "PR_HARNESS_SOURCE_MISMATCH",
                    f"receipt harness {harness.get('source_sha256')!r}, registered {instrument.get('harness_sha256')!r}",
                )
            )
        if not harness.get("binary_sha256"):
            problems.append(("PR_HARNESS_BINARY_MISSING", "no harness binary digest in the receipt"))

    try:
        modes = _normalise(receipt, adapter, per_batch, repo_root)
    except ValueError as error:
        return problems + [("PR_BAD_RECEIPT", str(error))]

    declared_modes = [item.get("id") for item in instance.get("workloads") or []]
    for name in declared_modes:
        if name not in modes:
            problems.append(("PR_MISSING_MODE", f"declared mode {name!r} is absent from the receipt"))
    for name in modes:
        if name not in declared_modes:
            problems.append(("PR_UNDECLARED_MODE", f"mode {name!r} was not preregistered"))

    for name, mode in modes.items():
        if mode["failures"] != 0:
            problems.append(
                ("PR_FAILED_OPERATION", f"{name}: {mode['failures']} failed operation(s) inside a measured mode")
            )
        if mode["total"] % per_batch != 0:
            problems.append(
                ("PR_TOTAL_NOT_MULTIPLE", f"{name}: total {mode['total']} is not a multiple of {per_batch}")
            )
            continue
        expected_batches = mode["total"] // per_batch
        if not 1 <= expected_batches <= max_batches:
            problems.append(
                ("PR_BATCH_BUDGET", f"{name}: {expected_batches} batches outside 1..{max_batches}")
            )
        if mode["batches"] != expected_batches:
            problems.append(
                (
                    "PR_BATCH_MISMATCH",
                    f"{name}: batches_run {mode['batches']} disagrees with total/per_batch {expected_batches}",
                )
            )
        if expected_batches < max_batches and mode["state"] != 0:
            problems.append(
                (
                    "PR_EARLY_STOP_WITHOUT_LEAK",
                    f"{name}: stopped at {expected_batches} batches with state {mode['state']}",
                )
            )

    controls = instance.get("controls") or {}
    expected_controls = controls.get("expected") or {}
    positive = controls.get("positive")
    negative = controls.get("negative")
    if positive and positive in modes:
        want = 0 if "state 0" in str(expected_controls.get(positive, "state 0")) else 1
        if modes[positive]["state"] != want:
            problems.append(
                (
                    "PR_POSITIVE_CONTROL_DID_NOT_FIRE",
                    f"{positive}: state {modes[positive]['state']}, expected {want}",
                )
            )
    if negative and negative in modes:
        want = 0 if "state 0" in str(expected_controls.get(negative, "state 1")) else 1
        if modes[negative]["state"] != want:
            problems.append(
                (
                    "PR_NEGATIVE_CONTROL_FIRED",
                    f"{negative}: state {modes[negative]['state']}, expected {want}",
                )
            )

    if receipt.get("exclusions_changed_after_run") is True:
        problems.append(("PR_EXCLUSIONS_CHANGED", "the receipt says the exclusion set changed after the run"))
    if "exclusions" in receipt:
        expected_exclusions = set(instance.get("exclusion_rule_ids") or [])
        got_exclusions = set(receipt.get("exclusions") or [])
        if expected_exclusions and got_exclusions != expected_exclusions:
            problems.append(
                (
                    "PR_EXCLUSIONS_CHANGED",
                    f"receipt exclusions {sorted(got_exclusions)} do not match {sorted(expected_exclusions)}",
                )
            )
    return problems


def _self_test(repo_root: Path) -> int:
    prereg = repo_root / "evidence/etp-t7/PREREGISTRATION.json"
    prospective = repo_root / "evidence/etp-t7/DUDECT-ETP-T7.json"
    legacy = repo_root / "courts/phase18/timing/RECEIPT-dudect-modes.json"
    failures = 0

    def expect(name: str, problems: list[tuple[str, str]], code: str | None) -> None:
        nonlocal failures
        codes = [item[0] for item in problems]
        if code is None:
            ok = not problems
            detail = "accepted" if ok else f"unexpectedly refused: {problems}"
        else:
            ok = code in codes
            detail = f"refused {codes}" if ok else f"did not refuse with {code}: {codes}"
        print(f"CONTROL {name}: {'PASS' if ok else 'FAIL'} ({detail})")
        if not ok:
            failures += 1

    expect(
        "prospective receipt passes",
        check(prereg, prospective, "ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1"),
        None,
    )
    expect(
        "reconstructed receipt passes",
        check(prereg, legacy, "ETP-T7-DUDECT-LEGACY-RECONSTRUCTED"),
        None,
    )

    def mutated_receipt() -> dict:
        return json.loads(prospective.read_text(encoding="utf-8"))

    import tempfile

    def with_receipt(document: dict, code: str, name: str) -> None:
        with tempfile.TemporaryDirectory(prefix="etp-t7-prereg-") as tmp:
            path = Path(tmp) / "receipt.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            expect(name, check(prereg, path, "ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1"), code)

    document = mutated_receipt()
    document["preregistration_sha256"] = "0" * 64
    with_receipt(document, "PR_PREREG_DIGEST_MISMATCH", "changed preregistration digest refused")

    document = mutated_receipt()
    document["candidate"]["libcrypto_sha256"] = "f" * 64
    with_receipt(document, "PR_CANDIDATE_MISMATCH", "changed artefact digest refused")

    document = mutated_receipt()
    document["harness"]["source_sha256"] = "f" * 64
    with_receipt(document, "PR_HARNESS_SOURCE_MISMATCH", "changed harness source refused")

    document = mutated_receipt()
    document["harness"]["binary_sha256"] = ""
    with_receipt(document, "PR_HARNESS_BINARY_MISSING", "missing harness binary refused")

    document = mutated_receipt()
    document["modes"]["cmpcmp"]["total_measurements"] = 40000
    document["modes"]["cmpcmp"]["batches_run"] = 4
    with_receipt(document, "PR_BATCH_BUDGET", "batch budget exceeded refused")

    document = mutated_receipt()
    document["modes"]["cmpcmp"]["batches_run"] = 2
    with_receipt(document, "PR_BATCH_MISMATCH", "batch count inconsistent with total refused")

    document = mutated_receipt()
    document["modes"]["cmpnaive"]["state"] = 1
    with_receipt(document, "PR_POSITIVE_CONTROL_DID_NOT_FIRE", "quiet positive control refused")

    document = mutated_receipt()
    document["modes"]["cmpcmp"]["state"] = 0
    with_receipt(document, "PR_NEGATIVE_CONTROL_FIRED", "firing negative control refused")

    document = mutated_receipt()
    del document["modes"]["cmpnaive"]
    with_receipt(document, "PR_MISSING_MODE", "missing declared mode refused")

    document = mutated_receipt()
    document["modes"]["extra"] = {"total_measurements": 10000, "batches_run": 1, "state": 1, "exit": 1}
    with_receipt(document, "PR_UNDECLARED_MODE", "undeclared mode refused")

    legacy_document = json.loads(legacy.read_text(encoding="utf-8"))
    legacy_document["modes"]["cmpnaive"]["state"] = 1
    with tempfile.TemporaryDirectory(prefix="etp-t7-prereg-") as tmp:
        path = Path(tmp) / "legacy.json"
        path.write_text(json.dumps(legacy_document), encoding="utf-8")
        expect(
            "reconstructed positive control refused",
            check(prereg, path, "ETP-T7-DUDECT-LEGACY-RECONSTRUCTED"),
            "PR_POSITIVE_CONTROL_DID_NOT_FIRE",
        )

    print(f"SELF-TEST {'PASS' if failures == 0 else 'FAIL'} failures={failures}")
    return 0 if failures == 0 else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prereg", default="evidence/etp-t7/PREREGISTRATION.json")
    parser.add_argument("--instance")
    parser.add_argument("--receipt")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root).resolve()

    if args.self_test:
        return _self_test(repo_root)
    if not args.receipt:
        parser.error("--receipt is required unless --self-test is used")
    problems = check(Path(args.prereg), Path(args.receipt), args.instance, repo_root)
    for code, message in problems:
        print(f"{code}: {message}", file=sys.stderr)
    if problems:
        return 1
    print(f"PREREG_CHECK ok instance={args.instance or 'receipt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
