#!/usr/bin/env python3
"""verification_economics.py -- what the verification costs, on a stated machine.

Cost is a resource and a fact, never an argument.  This tool records one cost
record per verification step, each bound to the machine that produced it, and
compares the measured totals with a *declared* budget.  It refuses, with a
stable code, every way a cost figure can be made to say more than it measured:

* a number with no measurement and no citation;
* a cost whose machine is not stated;
* seconds against milliseconds, MB against MiB;
* a required check skipped because it costs time;
* reuse without an applicability identity;
* a figure for an unmeasured input derived from one measured point;
* an over-budget tier with no recorded waiver;
* a waiver treated as permission (there is no authority to grant one);
* a check that did not run recorded as costing nothing;
* a cost measured at another candidate presented for this one.

The units are fixed and part of the field names: ``wallSeconds`` and
``cpuSeconds`` are seconds, ``peakRssMiB`` is mebibytes, ``artefactsBytes`` is
bytes.  A record that declares another unit is refused rather than converted.

The measurement itself uses ``os.wait4`` so the wall time, the child's CPU time
and the child's peak resident set are observed together.  Where a reading cannot
be taken the field is ``null`` with a reason in ``unavailable``; it is never
invented.  A cost figure measured on one machine does not transfer to another,
which is why every record carries its machine.

Usage:

    python3 forensics/tools/verification_economics.py measure \
        --tier BATCH --method "..." --step NAME --command -- CMD ARGS...
    python3 forensics/tools/verification_economics.py report \
        --records evidence/a26/COSTS.json --policy evidence/a26/POLICY.json
    python3 forensics/tools/verification_economics.py budget \
        --records evidence/a26/COSTS.json --policy evidence/a26/POLICY.json

Exit status: 0 when nothing is refused, 1 when a refusal or an over-budget tier
is reported, 2 for a usage error.  Every path prints ``code=...``.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RECORDS = REPO_ROOT / "evidence/a26/COSTS.json"
DEFAULT_POLICY = REPO_ROOT / "evidence/a26/POLICY.json"

COSTS_SCHEMA = "openssl-rs/verification-economics/costs/1"
BUDGET_SCHEMA = "openssl-rs/verification-economics/budget/1"
REPORT_SCHEMA = "openssl-rs/verification-economics/report/1"
CONTROLS_SCHEMA = "openssl-rs/verification-economics/controls/1"

TIERS = ("FAST", "BATCH", "BOUNDARY", "SEAL", "EXTERNAL")
STATUSES = ("MEASURED", "NOT_RUN", "SKIPPED")
KINDS = ("wallSeconds", "cpuSeconds", "peakRssMiB", "artefactsBytes")

# The unit of each field, fixed by the field name.  Declared explicitly in every
# record so a record can be compared without guessing.
UNITS = {
    "wallSeconds": "s",
    "cpuSeconds": "s",
    "peakRssMiB": "MiB",
    "artefactsBytes": "bytes",
}

# The five fields an applicability identity must carry before a record may be
# reused.  The names follow the freshness/scheduling identity rather than
# inventing a second vocabulary.
REUSE_FIELDS = ("source", "tool", "instrument", "target", "population")

# Reasons that turn a skip into "we did not run it because it costs time".  A
# required check is never skipped for these; it is measured or recorded
# NOT_RUN with a technical reason.
COST_SKIP_REASONS = frozenset(
    {"cost", "time", "slow", "expensive", "budget", "duration", "wall-clock"}
)

MACHINE_FIELDS = ("identifier", "cores", "memGiB", "interpreter", "courtMemCapGiB")

RECORD_FIELDS = (
    "step",
    "tier",
    "wallSeconds",
    "cpuSeconds",
    "peakRssMiB",
    "artefactsBytes",
    "machine",
    "method",
    "measuredAt",
    "citedBy",
    "status",
    "candidate",
    "units",
)

# Stable refusal identifiers, each with the wrong conclusion it prevents.  The
# document table and the tests use this mapping so the prose cannot drift from
# the checks.
REFUSALS = {
    "EC_REFUSED_UNCITED_COST": (
        "a cost figure with no measurement and no citation; the number would be "
        "an assertion, not evidence"
    ),
    "EC_REFUSED_MACHINE_UNSTATED": (
        "a cost without its machine; a figure from an unstated machine cannot be "
        "compared with, or transferred to, another"
    ),
    "EC_REFUSED_UNIT_MISMATCH": (
        "seconds against milliseconds or MB against MiB; a silently converted "
        "figure is a different number presented as this one"
    ),
    "EC_REFUSED_SKIP_AS_SAVING": (
        "a required check skipped because it costs time; cost is a resource, not "
        "a reason to omit a check"
    ),
    "EC_REFUSED_CACHE_UNBOUND": (
        "reuse without an applicability identity; a result from another source, "
        "tool, instrument, target or population is not this check's result"
    ),
    "EC_REFUSED_EXTRAPOLATION": (
        "a figure for an unmeasured input derived from one measured point; one "
        "point is not a curve"
    ),
    "EC_REFUSED_BUDGET_OVER": (
        "an over-budget tier with no recorded waiver; the overage would be "
        "hidden rather than reported"
    ),
    "EC_REFUSED_WAIVER_UNRECORDED": (
        "an over-budget tier whose waiver is not recorded; an unrecorded "
        "exception is indistinguishable from an omission"
    ),
    "EC_REFUSED_WAIVER_AS_AUTHORITY": (
        "a waiver treated as permission; no authority exists to grant one, so a "
        "waiver is a recorded fact and never authorises a pass"
    ),
    "EC_REFUSED_NOT_RUN_AS_ZERO": (
        "a check that did not run recorded as costing nothing; a not-run is not "
        "free and is not a measured zero"
    ),
    "EC_REFUSED_STALE_MEASUREMENT": (
        "a cost measured at another candidate presented for this one; the "
        "measurement does not describe the candidate under discussion"
    ),
    "EC_REFUSED_RECORD_INVALID": (
        "a record that is not a cost record; reading it as one would invent "
        "fields the producer did not supply"
    ),
    "EC_REFUSED_USAGE": (
        "a malformed invocation; a tool that cannot say what it was asked to do "
        "must not report a result"
    ),
}


class Refusal(Exception):
    """A refusal with a stable code."""

    def __init__(self, code: str, detail: str) -> None:
        if code not in REFUSALS:
            raise ValueError(f"unknown refusal code {code!r}")
        super().__init__(detail)
        self.code = code
        self.detail = detail

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "detail": self.detail}


def canonical(document: Any) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


# ---------------------------------------------------------------------------
# The machine
# ---------------------------------------------------------------------------


def _cgroup(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _memory_max_bytes() -> int | None:
    text = _cgroup("/sys/fs/cgroup/memory.max")
    if text in (None, "", "max"):
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _cpu_quota() -> tuple[int | None, str | None]:
    """Return (cores, the raw ``cpu.max`` text)."""
    text = _cgroup("/sys/fs/cgroup/cpu.max")
    if not text or text == "max":
        return None, text
    parts = text.split()
    if len(parts) != 2:
        return None, text
    try:
        quota, period = int(parts[0]), int(parts[1])
    except ValueError:
        return None, text
    if quota <= 0 or period <= 0:
        return None, text
    return max(1, round(quota / period)), text


def machine(identifier: str | None = None, note: str | None = None) -> dict[str, Any]:
    """The machine as it can be read, never as it might be guessed.

    The container is the venue: its cgroup memory ceiling is the memory cap and
    its CPU quota is the core count.  A host CPU model is not readable from
    inside the container and is deliberately not invented; ``note`` says so.
    """
    inside = Path("/.dockerenv").exists()
    image = os.environ.get("OPENSSL_RS_COURT_IMAGE")
    hostname = os.uname().nodename
    if identifier is None:
        if image:
            identifier = f"{image} (container {hostname})"
        elif inside:
            identifier = f"container {hostname} (court image unrecorded)"
        else:
            identifier = f"host {hostname} (no court cap)"
    mem_bytes = _memory_max_bytes()
    cores, cpu_text = _cpu_quota()
    if cores is None:
        cores = os.cpu_count()
    cap_gib = round(mem_bytes / 1024 ** 3, 2) if mem_bytes is not None else None
    record: dict[str, Any] = {
        "identifier": identifier,
        "cores": cores,
        "memGiB": cap_gib,
        "interpreter": f"{platform.python_implementation()} {platform.python_version()}",
        "courtMemCapGiB": cap_gib if inside else None,
        "cpuQuota": cpu_text,
        "inContainer": inside,
        "hostCpuModel": None,
        "note": note
        or (
            "the venue is the container; memGiB and courtMemCapGiB are its cgroup "
            "memory ceiling and cores is its cpu.max quota. A host CPU model is "
            "not read and is not recorded"
        ),
    }
    return record


def machine_problems(record: dict[str, Any]) -> list[dict[str, str]]:
    """A cost without a machine is refused."""
    body = record.get("machine")
    if not isinstance(body, dict):
        return [_problem("EC_REFUSED_MACHINE_UNSTATED", "machine is an object")]
    missing = [
        field
        for field in MACHINE_FIELDS
        if body.get(field) in (None, "") or (
            field in ("cores", "memGiB", "courtMemCapGiB") and not _number(body.get(field))
        )
    ]
    if missing:
        return [
            _problem(
                "EC_REFUSED_MACHINE_UNSTATED",
                f"machine.{missing} must be populated; a cost without its machine is not comparable",
            )
        ]
    return []


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------


def _run_timed(
    command: Sequence[str] | str,
    *,
    cwd: str | Path | None = None,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run one command and observe wall, child CPU and peak RSS together.

    ``os.wait4`` reports the child's own rusage, so the peak resident set is not
    the maximum of every child this process has ever waited for.  Output is
    redirected to temporary files so a chatty suite cannot fill a pipe and
    deadlock the parent.
    """
    shell = isinstance(command, str)
    argv: Any = command if shell else list(command)
    environment = dict(os.environ if env is None else env)
    environment.setdefault("PYTHONDONTWRITEBYTECODE", "1")

    out_file = tempfile.TemporaryFile()
    err_file = tempfile.TemporaryFile()
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            cwd=str(cwd) if cwd is not None else None,
            shell=shell,
            stdout=out_file,
            stderr=err_file,
            env=environment,
            start_new_session=True,
        )
    except OSError as exc:
        out_file.close()
        err_file.close()
        return {
            "wallSeconds": None,
            "cpuSeconds": None,
            "peakRssMiB": None,
            "exitStatus": None,
            "timedOut": False,
            "commandError": f"{type(exc).__name__}: {exc}",
            "stdout": "",
            "stderr": "",
        }

    deadline = started + timeout if timeout else None
    timed_out = False
    try:
        while True:
            pid, status, rusage = os.wait4(process.pid, os.WNOHANG)
            if pid != 0:
                break
            if deadline is not None and time.monotonic() > deadline:
                timed_out = True
                try:
                    os.killpg(process.pid, 9)
                except OSError:
                    process.kill()
                pid, status, rusage = os.wait4(process.pid, 0)
                break
            time.sleep(0.02)
    finally:
        wall = time.monotonic() - started
        process.returncode = os.waitstatus_to_exitcode(status)
        out_file.seek(0)
        err_file.seek(0)
        stdout = out_file.read().decode("utf-8", "replace")
        stderr = err_file.read().decode("utf-8", "replace")
        out_file.close()
        err_file.close()

    return {
        "wallSeconds": round(wall, 6),
        "cpuSeconds": round(rusage.ru_utime + rusage.ru_stime, 6),
        "peakRssMiB": round(rusage.ru_maxrss / 1024.0, 3),
        "exitStatus": process.returncode,
        "timedOut": timed_out,
        "commandError": None,
        "stdout": stdout,
        "stderr": stderr,
    }


def _artefact_bytes(paths: Iterable[str | Path]) -> tuple[int, list[str]]:
    total = 0
    missing: list[str] = []
    for item in paths:
        path = Path(item)
        if not path.exists():
            missing.append(str(path))
            continue
        if path.is_dir():
            for child in path.rglob("*"):
                if child.is_file():
                    total += child.stat().st_size
        else:
            total += path.stat().st_size
    return total, missing


def record_from(
    command: Sequence[str] | str,
    tier: str,
    method: str,
    observation: dict[str, Any],
    *,
    step: str | None = None,
    candidate: str | None = None,
    cited_by: Iterable[str] = (),
    artefact_paths: Iterable[str | Path] = (),
    machine_identity: str | None = None,
) -> dict[str, Any]:
    """Build one cost record from an observation ``_run_timed`` already took.

    Separating the observation from the record lets a caller print the command's
    output (for a gate) without running the command twice, and keeps the record
    the only thing that is written.
    """
    if tier not in TIERS:
        raise Refusal("EC_REFUSED_RECORD_INVALID", f"tier {tier!r} is not one of {TIERS}")
    if not _nonempty(method):
        raise Refusal("EC_REFUSED_UNCITED_COST", "a record requires a method")
    argv = command if isinstance(command, str) else list(command)
    display = argv if isinstance(argv, str) else " ".join(argv)
    label = step or display
    observations = {
        "wallSeconds": observation.get("wallSeconds"),
        "cpuSeconds": observation.get("cpuSeconds"),
        "peakRssMiB": observation.get("peakRssMiB"),
    }
    unavailable: dict[str, str] = {}
    if observation.get("commandError"):
        for field in observations:
            unavailable[field] = observation["commandError"]
    artefacts, missing = _artefact_bytes(artefact_paths)
    for path in missing:
        unavailable[f"artefacts:{path}"] = "the declared artefact path does not exist"
    return {
        "step": label,
        "tier": tier,
        "wallSeconds": observations["wallSeconds"],
        "cpuSeconds": observations["cpuSeconds"],
        "peakRssMiB": observations["peakRssMiB"],
        "artefactsBytes": artefacts,
        "machine": machine(machine_identity),
        "method": method,
        "measuredAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "citedBy": [str(item) for item in cited_by],
        "status": "MEASURED",
        "candidate": candidate,
        "units": dict(UNITS),
        "command": display,
        "exitStatus": observation.get("exitStatus"),
        "timedOut": observation.get("timedOut", False),
        "unavailable": unavailable,
    }


def measure(
    command: Sequence[str] | str,
    tier: str,
    method: str,
    *,
    step: str | None = None,
    candidate: str | None = None,
    cited_by: Iterable[str] = (),
    cwd: str | Path | None = None,
    timeout: float | None = None,
    artefact_paths: Iterable[str | Path] = (),
    machine_identity: str | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run ``command`` and return one cost record.

    The wall, CPU and peak-RSS readings come from ``os.wait4``.  A field that
    could not be read is ``null`` with a reason in ``unavailable``.  The command
    may fail; its exit status is recorded and is not conflated with the
    measurement's own success.
    """
    argv = command if isinstance(command, str) else list(command)
    observation = _run_timed(argv, cwd=cwd, timeout=timeout, env=env)
    return record_from(
        argv,
        tier,
        method,
        observation,
        step=step,
        candidate=candidate,
        cited_by=cited_by,
        artefact_paths=artefact_paths,
        machine_identity=machine_identity,
    )


def not_run(
    step: str,
    tier: str,
    reason: str,
    method: str,
    *,
    candidate: str | None = None,
    cited_by: Iterable[str] = (),
    machine_identity: str | None = None,
) -> dict[str, Any]:
    """A check that did not run, with the technical reason it did not."""
    if tier not in TIERS:
        raise Refusal("EC_REFUSED_RECORD_INVALID", f"tier {tier!r} is not one of {TIERS}")
    return {
        "step": step,
        "tier": tier,
        "wallSeconds": None,
        "cpuSeconds": None,
        "peakRssMiB": None,
        "artefactsBytes": None,
        "machine": machine(machine_identity),
        "method": method,
        "measuredAt": None,
        "citedBy": [str(item) for item in cited_by],
        "status": "NOT_RUN",
        "candidate": candidate,
        "units": dict(UNITS),
        "notRunReason": reason,
        "unavailable": {
            "wallSeconds": "the check did not run, so it has no cost",
            "cpuSeconds": "the check did not run, so it has no cost",
            "peakRssMiB": "the check did not run, so it has no cost",
            "artefactsBytes": "the check did not run, so it produced no artefact",
        },
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _problem(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def unit_problems(record: dict[str, Any]) -> list[dict[str, str]]:
    """Units are fixed by the field name; a declared other unit is refused."""
    problems: list[dict[str, str]] = []
    for bad in ("wallMs", "cpuMs", "peakRssMB", "artefactsKB"):
        if bad in record:
            problems.append(
                _problem(
                    "EC_REFUSED_UNIT_MISMATCH",
                    f"{bad} is not an admitted field; use {KINDS} in their declared units",
                )
            )
    units = record.get("units")
    if units is not None:
        if not isinstance(units, dict):
            problems.append(_problem("EC_REFUSED_UNIT_MISMATCH", "units is an object"))
        else:
            for field, expected in UNITS.items():
                declared = units.get(field)
                if declared != expected:
                    problems.append(
                        _problem(
                            "EC_REFUSED_UNIT_MISMATCH",
                            f"units.{field} is {declared!r}, the field is {expected!r}; "
                            "a converted figure is not this figure",
                        )
                    )
    return problems


def record_problems(record: Any) -> list[dict[str, str]]:
    """Every way one record can fail to be a cost record."""
    if not isinstance(record, dict):
        return [_problem("EC_REFUSED_RECORD_INVALID", "a record is an object")]
    problems: list[dict[str, str]] = []
    missing = [field for field in RECORD_FIELDS if field not in record]
    if missing:
        return [
            _problem("EC_REFUSED_RECORD_INVALID", f"missing field(s) {missing}")
        ]
    if record.get("tier") not in TIERS:
        problems.append(
            _problem("EC_REFUSED_RECORD_INVALID", f"tier {record.get('tier')!r} is not declared")
        )
    if record.get("status") not in STATUSES:
        problems.append(
            _problem("EC_REFUSED_RECORD_INVALID", f"status {record.get('status')!r} is not declared")
        )
    if not _nonempty(record.get("step")):
        problems.append(_problem("EC_REFUSED_RECORD_INVALID", "step is a non-empty string"))
    if not isinstance(record.get("citedBy"), list) or not all(
        isinstance(item, str) for item in record.get("citedBy", [])
    ):
        problems.append(_problem("EC_REFUSED_RECORD_INVALID", "citedBy is a list of strings"))
    if not isinstance(record.get("units"), dict):
        problems.append(_problem("EC_REFUSED_RECORD_INVALID", "units is an object"))
    if record.get("status") == "NOT_RUN" and not _nonempty(record.get("notRunReason")):
        problems.append(
            _problem("EC_REFUSED_RECORD_INVALID", "a NOT_RUN record states why it did not run")
        )

    problems.extend(machine_problems(record))
    problems.extend(unit_problems(record))

    status = record.get("status")
    if status == "NOT_RUN":
        for field in KINDS:
            if record.get(field) is not None:
                problems.append(
                    _problem(
                        "EC_REFUSED_NOT_RUN_AS_ZERO",
                        f"{field} is {record.get(field)!r} on a NOT_RUN record; a check that "
                        "did not run has no measured cost",
                    )
                )
        if record.get("countedAsZero") is True:
            problems.append(
                _problem(
                    "EC_REFUSED_NOT_RUN_AS_ZERO",
                    "a NOT_RUN record counted as zero; a not-run is not free",
                )
            )
    if status in ("MEASURED", "SKIPPED"):
        unavailable = record.get("unavailable") or {}
        if not isinstance(unavailable, dict):
            problems.append(_problem("EC_REFUSED_RECORD_INVALID", "unavailable is an object"))
            unavailable = {}
        numeric = 0
        for field in KINDS:
            value = record.get(field)
            if value is None:
                if field not in unavailable:
                    problems.append(
                        _problem(
                            "EC_REFUSED_RECORD_INVALID",
                            f"{field} is null without a reason in unavailable; a missing "
                            "reading is stated, never silent",
                        )
                    )
            elif not _number(value) or value < 0:
                problems.append(
                    _problem("EC_REFUSED_RECORD_INVALID", f"{field} is a non-negative number or null")
                )
            else:
                numeric += 1
        if status == "MEASURED" and numeric == 0:
            if not (_nonempty(record.get("method")) and record.get("citedBy")):
                problems.append(
                    _problem(
                        "EC_REFUSED_UNCITED_COST",
                        "no numeric reading and no citation; the figure is an assertion",
                    )
                )
        if status == "SKIPPED":
            reason = str(record.get("skippedBecause", "")).strip().lower()
            if record.get("skippedForCost") is True or reason in COST_SKIP_REASONS:
                problems.append(
                    _problem(
                        "EC_REFUSED_SKIP_AS_SAVING",
                        "a required check skipped because it costs time; cost is not a "
                        "reason to omit a check",
                    )
                )

    if record.get("reused"):
        identity = record.get("reuseIdentity")
        if not isinstance(identity, dict):
            problems.append(
                _problem("EC_REFUSED_CACHE_UNBOUND", "reuse requires an applicability identity")
            )
        else:
            absent = [field for field in REUSE_FIELDS if not _nonempty(identity.get(field))]
            if absent:
                problems.append(
                    _problem(
                        "EC_REFUSED_CACHE_UNBOUND",
                        f"reuse identity is missing {absent}; reuse is bound to the "
                        "complete five-field identity",
                    )
                )

    if record.get("derived") is True or record.get("extrapolated") is True:
        basis = record.get("basis")
        if not isinstance(basis, list) or len(basis) < 2:
            problems.append(
                _problem(
                    "EC_REFUSED_EXTRAPOLATION",
                    "a derived figure needs at least two measured points; one point is not a curve",
                )
            )

    return problems


def record_codes(problems: Iterable[dict[str, str]]) -> list[str]:
    return sorted({item["code"] for item in problems})


def validate_records(
    records: Sequence[dict[str, Any]], policy: dict[str, Any]
) -> list[dict[str, str]]:
    """Validate every record against the candidate the policy names."""
    problems: list[dict[str, str]] = []
    current = policy.get("candidate")
    if not _nonempty(current):
        problems.append(
            _problem("EC_REFUSED_RECORD_INVALID", "the policy names the candidate under discussion")
        )
    seen: set[str] = set()
    for record in records:
        for item in record_problems(record):
            problems.append(item)
        if not isinstance(record, dict):
            continue
        step = record.get("step")
        if isinstance(step, str):
            if step in seen:
                problems.append(
                    _problem("EC_REFUSED_RECORD_INVALID", f"step {step!r} is recorded twice")
                )
            seen.add(step)
        if _nonempty(current) and record.get("candidate") != current:
            problems.append(
                _problem(
                    "EC_REFUSED_STALE_MEASUREMENT",
                    f"{record.get('step')!r} was measured at {record.get('candidate')!r}, "
                    f"the policy is about {current!r}",
                )
            )
    return problems


# ---------------------------------------------------------------------------
# Totals and the budget
# ---------------------------------------------------------------------------


def _totals(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    measured = [r for r in records if r.get("status") == "MEASURED"]
    time_like = [r for r in records if r.get("status") == "MEASURED"]
    return {
        "wallSeconds": round(sum(r.get("wallSeconds") or 0.0 for r in time_like), 6),
        "cpuSeconds": round(sum(r.get("cpuSeconds") or 0.0 for r in time_like), 6),
        "peakRssMiB": round(max((r.get("peakRssMiB") or 0.0 for r in measured), default=0.0), 3),
        "artefactsBytes": sum(r.get("artefactsBytes") or 0 for r in measured),
        "measuredSteps": len(measured),
        "notRunSteps": sum(1 for r in records if r.get("status") == "NOT_RUN"),
    }


def _waiver_problems(tier: str, waiver: Any) -> list[dict[str, str]]:
    if not isinstance(waiver, dict):
        return [
            _problem("EC_REFUSED_WAIVER_UNRECORDED", f"{tier}: a waiver is a recorded object")
        ]
    problems: list[dict[str, str]] = []
    if waiver.get("recorded") is not True:
        problems.append(
            _problem(
                "EC_REFUSED_WAIVER_UNRECORDED",
                f"{tier}: an over-budget exception must be recorded, not implied",
            )
        )
    if (
        waiver.get("authority") not in (None, "")
        or waiver.get("grantsPermission") is True
        or waiver.get("convertsToPass") is True
    ):
        problems.append(
            _problem(
                "EC_REFUSED_WAIVER_AS_AUTHORITY",
                f"{tier}: a waiver is a recorded fact, not permission; no authority "
                "exists to grant one",
            )
        )
    return problems


def budget(
    records: Sequence[dict[str, Any]], policy: dict[str, Any]
) -> dict[str, Any]:
    """Compare measured totals with the declared budget, per tier and total.

    An over-budget tier is ``OVER`` and carries its excess.  A recorded waiver
    is reported beside it and never changes the status or the excess: there is
    no authority to grant one.
    """
    problems = validate_records(records, policy)
    declared = policy.get("budget")
    if not isinstance(declared, dict):
        raise Refusal("EC_REFUSED_RECORD_INVALID", "the policy declares a budget object")
    waivers = policy.get("waivers") or {}
    if not isinstance(waivers, dict):
        raise Refusal("EC_REFUSED_RECORD_INVALID", "the policy declares waivers as an object")

    tiers: dict[str, Any] = {}
    any_over = False
    all_records = list(records)
    for tier in TIERS + ("TOTAL",):
        subset = all_records if tier == "TOTAL" else [
            r for r in all_records if isinstance(r, dict) and r.get("tier") == tier
        ]
        measured = _totals(subset)
        cap = declared.get(tier)
        if not isinstance(cap, dict):
            problems.append(
                _problem("EC_REFUSED_RECORD_INVALID", f"{tier}: the budget declares this tier")
            )
            cap = {}
        excess: dict[str, float] = {}
        for field in KINDS:
            if field in cap and measured[field] > cap[field]:
                excess[field] = round(measured[field] - cap[field], 6)
        over = bool(excess)
        any_over = any_over or over
        waiver = waivers.get(tier)
        if over:
            if waiver is None:
                problems.append(
                    _problem(
                        "EC_REFUSED_BUDGET_OVER",
                        f"{tier}: over budget by {excess} with no recorded waiver",
                    )
                )
            else:
                problems.extend(_waiver_problems(tier, waiver))
        tiers[tier] = {
            "status": "OVER" if over else "UNDER",
            "measured": measured,
            "declaredBudget": cap,
            "excess": excess,
            "waiver": (
                {
                    "recorded": waiver.get("recorded") is True,
                    "note": waiver.get("note"),
                    "authorising": False,
                }
                if isinstance(waiver, dict)
                else None
            ),
        }

    codes = record_codes(problems)
    return {
        "schema": BUDGET_SCHEMA,
        "candidate": policy.get("candidate"),
        "units": dict(UNITS),
        "declaredBudget": declared,
        "tiers": tiers,
        "overall": "OVER" if any_over else "UNDER",
        "refusals": sorted(problems, key=lambda item: (item["code"], item["detail"])),
        "codes": codes or ["EC_OK"],
    }


def costs_document(
    records: Sequence[dict[str, Any]],
    *,
    candidate: str,
    units: dict[str, str] | None = None,
) -> dict[str, Any]:
    order = {tier: index for index, tier in enumerate(TIERS)}
    ordered = sorted(
        records,
        key=lambda r: (order.get(r.get("tier"), len(TIERS)), str(r.get("step", ""))),
    )
    return {
        "schema": COSTS_SCHEMA,
        "candidate": candidate,
        "units": dict(units or UNITS),
        "records": ordered,
        "totals": _totals(ordered),
        "codes": ["EC_OK"],
    }


def report(
    records: Sequence[dict[str, Any]], policy: dict[str, Any]
) -> dict[str, Any]:
    """The cost record and the budget result in one document."""
    problems = validate_records(records, policy)
    result = budget(records, policy)
    codes = record_codes(problems + result["refusals"])
    order = {tier: index for index, tier in enumerate(TIERS)}
    ordered = sorted(
        records,
        key=lambda r: (order.get(r.get("tier"), len(TIERS)), str(r.get("step", ""))),
    )
    return {
        "schema": REPORT_SCHEMA,
        "candidate": policy.get("candidate"),
        "units": dict(UNITS),
        "records": ordered,
        "notRun": [
            {"step": r.get("step"), "tier": r.get("tier"), "reason": r.get("notRunReason")}
            for r in ordered
            if r.get("status") == "NOT_RUN"
        ],
        "totals": _totals(records),
        "budget": result,
        "overall": result["overall"],
        "refusals": sorted(
            {json.dumps(item, sort_keys=True): item for item in problems + result["refusals"]}.values(),
            key=lambda item: (item["code"], item["detail"]),
        ),
        "codes": codes or ["EC_OK"],
    }


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

CONTROL_MACHINE = {
    "identifier": "control-only court",
    "cores": 4,
    "memGiB": 6.0,
    "interpreter": "CPython 3.11.2",
    "courtMemCapGiB": 6.0,
    "cpuQuota": "400000 100000",
    "inContainer": True,
    "hostCpuModel": None,
    "note": "synthetic control machine; not a measurement",
}


def _control_policy(candidate: str = "control-candidate", **budget_overrides: Any) -> dict[str, Any]:
    full = {
        "FAST": {"wallSeconds": 10.0, "cpuSeconds": 10.0, "peakRssMiB": 100.0, "artefactsBytes": 10},
        "BATCH": {"wallSeconds": 10.0, "cpuSeconds": 10.0, "peakRssMiB": 100.0, "artefactsBytes": 10},
        "BOUNDARY": {"wallSeconds": 10.0, "cpuSeconds": 10.0, "peakRssMiB": 100.0, "artefactsBytes": 10},
        "SEAL": {"wallSeconds": 10.0, "cpuSeconds": 10.0, "peakRssMiB": 100.0, "artefactsBytes": 10},
        "EXTERNAL": {"wallSeconds": 10.0, "cpuSeconds": 10.0, "peakRssMiB": 100.0, "artefactsBytes": 10},
        "TOTAL": {"wallSeconds": 10.0, "cpuSeconds": 10.0, "peakRssMiB": 100.0, "artefactsBytes": 10},
    }
    full.update(budget_overrides)
    return {"candidate": candidate, "units": dict(UNITS), "budget": full, "waivers": {}}


def _control_record(**overrides: Any) -> dict[str, Any]:
    record = {
        "step": "control-step",
        "tier": "BATCH",
        "wallSeconds": 1.0,
        "cpuSeconds": 1.0,
        "peakRssMiB": 1.0,
        "artefactsBytes": 1,
        "machine": dict(CONTROL_MACHINE),
        "method": "control-only fixture",
        "measuredAt": "2026-01-01T00:00:00Z",
        "citedBy": ["control-only"],
        "status": "MEASURED",
        "candidate": "control-candidate",
        "units": dict(UNITS),
        "unavailable": {},
    }
    record.update(overrides)
    return record


def build_controls() -> dict[str, Any]:
    """One control per refusal code, every one ``controlOnly``.

    A control mutates a record, a policy or an invocation in memory.  It is not
    a source change and not a defect report: it proves the refusal fires.
    """
    controls: list[dict[str, Any]] = []

    def add(name: str, code: str, observed: list[str], detail: str) -> None:
        controls.append(
            {
                "id": name,
                "code": code,
                "controlOnly": True,
                "observed": sorted(observed),
                "matched": observed == [code],
                "detail": detail,
            }
        )

    record = _control_record(machine={})
    add(
        "machine-unstated",
        "EC_REFUSED_MACHINE_UNSTATED",
        record_codes(record_problems(record)),
        "a record whose machine is empty; a cost from an unstated machine is refused",
    )

    record = _control_record(wallSeconds=None, cpuSeconds=None, peakRssMiB=None,
                             artefactsBytes=None, citedBy=[],
                             unavailable={k: "not read" for k in KINDS})
    add(
        "uncited-cost",
        "EC_REFUSED_UNCITED_COST",
        record_codes(record_problems(record)),
        "no numeric reading and no citation; the figure is an assertion",
    )

    record = _control_record(units=dict(UNITS, wallSeconds="ms"))
    add(
        "unit-mismatch",
        "EC_REFUSED_UNIT_MISMATCH",
        record_codes(record_problems(record)),
        "wallSeconds declared in milliseconds; the field is seconds",
    )

    record = _control_record(status="SKIPPED", skippedBecause="cost")
    add(
        "skip-as-saving",
        "EC_REFUSED_SKIP_AS_SAVING",
        record_codes(record_problems(record)),
        "a required check skipped because it costs time",
    )

    record = _control_record(reused=True, reuseIdentity={"source": "abc"})
    add(
        "cache-unbound",
        "EC_REFUSED_CACHE_UNBOUND",
        record_codes(record_problems(record)),
        "reuse naming a source but no tool, instrument, target or population",
    )

    record = _control_record(derived=True, basis=["one measured point"])
    add(
        "single-point-extrapolation",
        "EC_REFUSED_EXTRAPOLATION",
        record_codes(record_problems(record)),
        "a derived figure with one measured point; one point is not a curve",
    )

    over_policy = _control_policy(BATCH={"wallSeconds": 0.5})
    over_budget = budget([_control_record()], over_policy)
    add(
        "budget-over",
        "EC_REFUSED_BUDGET_OVER",
        over_budget["codes"],
        "a BATCH tier over its declared wall budget with no recorded waiver",
    )

    waiver_policy = _control_policy(BATCH={"wallSeconds": 0.5})
    waiver_policy["waivers"] = {"BATCH": {"recorded": False, "note": "not recorded"}}
    add(
        "waiver-unrecorded",
        "EC_REFUSED_WAIVER_UNRECORDED",
        budget([_control_record()], waiver_policy)["codes"],
        "an over-budget tier whose waiver is not recorded",
    )

    authority_policy = _control_policy(BATCH={"wallSeconds": 0.5})
    authority_policy["waivers"] = {
        "BATCH": {"recorded": True, "note": "signed off", "authority": "self"}
    }
    add(
        "waiver-as-authority",
        "EC_REFUSED_WAIVER_AS_AUTHORITY",
        budget([_control_record()], authority_policy)["codes"],
        "a waiver naming an authority, presented as permission",
    )

    record = _control_record(status="NOT_RUN", wallSeconds=0.0, cpuSeconds=0.0,
                             peakRssMiB=0.0, artefactsBytes=0,
                             notRunReason="the check did not run")
    add(
        "not-run-as-zero",
        "EC_REFUSED_NOT_RUN_AS_ZERO",
        record_codes(record_problems(record)),
        "a NOT_RUN recorded with zero cost; a not-run is not a measured zero",
    )

    record = _control_record(candidate="another-candidate")
    policy = _control_policy(candidate="control-candidate")
    add(
        "stale-measurement",
        "EC_REFUSED_STALE_MEASUREMENT",
        record_codes(validate_records([record], policy)),
        "a cost measured at another candidate presented for this one",
    )

    record = _control_record(tier="NOT-A-TIER")
    add(
        "record-invalid",
        "EC_REFUSED_RECORD_INVALID",
        record_codes(record_problems(record)),
        "a record whose tier is not in the closed vocabulary",
    )

    usage = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "not-a-command"],
        capture_output=True,
        text=True,
        check=False,
    )
    observed_usage = (
        ["EC_REFUSED_USAGE"]
        if usage.returncode == 2 and "EC_REFUSED_USAGE" in usage.stdout
        else []
    )
    add(
        "malformed-invocation",
        "EC_REFUSED_USAGE",
        observed_usage,
        "the tool invoked with an unknown command; it refuses and prints its code",
    )

    covered = {row["code"] for row in controls}
    return {
        "schema": CONTROLS_SCHEMA,
        "controlOnly": True,
        "codes": sorted(REFUSALS),
        "controls": controls,
        "coversEveryCode": covered == set(REFUSALS),
        "failing": sorted(row["id"] for row in controls if not row["matched"]),
    }


# ---------------------------------------------------------------------------
# Document loading and the command line
# ---------------------------------------------------------------------------


def load_document(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise Refusal("EC_REFUSED_USAGE", f"{path}: {exc}") from exc
    except ValueError as exc:
        raise Refusal("EC_REFUSED_USAGE", f"{path}: {exc}") from exc


def records_from(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, dict) and isinstance(document.get("records"), list):
        return document["records"]
    if isinstance(document, list):
        return document
    raise Refusal("EC_REFUSED_RECORD_INVALID", "the records document holds a records list")


def _print_codes(codes: Iterable[str]) -> None:
    print(f"verification-economics: codes={','.join(codes)}")


def _summary(result: dict[str, Any]) -> None:
    for tier, row in result["tiers"].items():
        measured = row["measured"]
        print(
            f"verification-economics: {tier} {row['status']} "
            f"wall={measured['wallSeconds']}s cpu={measured['cpuSeconds']}s "
            f"rss={measured['peakRssMiB']}MiB artefacts={measured['artefactsBytes']}B "
            f"measured={measured['measuredSteps']} notRun={measured['notRunSteps']}"
            + (f" excess={row['excess']}" if row["excess"] else "")
        )
    print(f"verification-economics: overall={result['overall']}")


def _load_policy(path: str | Path) -> dict[str, Any]:
    document = load_document(path)
    if not isinstance(document, dict):
        raise Refusal("EC_REFUSED_RECORD_INVALID", "the policy is a JSON object")
    return document


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verification_economics.py",
        description="record what verification costs, on a stated machine, against a budget",
    )
    subparsers = parser.add_subparsers(dest="command")

    measure_parser = subparsers.add_parser("measure", help="run one command and record its cost")
    measure_parser.add_argument("--tier", required=True)
    measure_parser.add_argument("--method", required=True)
    measure_parser.add_argument("--step", default=None)
    measure_parser.add_argument("--candidate", default=None)
    measure_parser.add_argument("--cite", action="append", default=[])
    measure_parser.add_argument("--cwd", default=None)
    measure_parser.add_argument("--timeout", type=float, default=None)
    measure_parser.add_argument("--artefact", action="append", default=[])
    measure_parser.add_argument("--machine", default=None)
    measure_parser.add_argument("argv", nargs=argparse.REMAINDER)

    for name, help_text in (
        ("report", "the cost record and the budget result"),
        ("budget", "the budget result only"),
    ):
        step_parser = subparsers.add_parser(name, help=help_text)
        step_parser.add_argument("--records", default=str(DEFAULT_RECORDS))
        step_parser.add_argument("--policy", default=str(DEFAULT_POLICY))
        step_parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    try:
        parsed = parser.parse_args(arguments)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
        if code != 0:
            _print_codes(["EC_REFUSED_USAGE"])
        return code

    if parsed.command == "measure":
        command = list(parsed.argv)
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            print("verification-economics: usage measure ... -- CMD [ARGS...]")
            _print_codes(["EC_REFUSED_USAGE"])
            return 2
        try:
            record = measure(
                command,
                parsed.tier,
                parsed.method,
                step=parsed.step,
                candidate=parsed.candidate,
                cited_by=parsed.cite,
                cwd=parsed.cwd,
                timeout=parsed.timeout,
                artefact_paths=parsed.artefact,
                machine_identity=parsed.machine,
            )
        except Refusal as refusal:
            print(f"verification-economics: refused {refusal.detail}")
            _print_codes([refusal.code])
            return 1
        problems = record_problems(record)
        print(canonical(record), end="")
        codes = record_codes(problems) or ["EC_OK"]
        if record.get("timedOut"):
            codes = sorted(set(codes) | {"EC_REFUSED_RECORD_INVALID"})
        _print_codes(codes)
        return 0 if codes == ["EC_OK"] else 1

    if parsed.command in ("report", "budget"):
        try:
            records = records_from(load_document(parsed.records))
            policy = _load_policy(parsed.policy)
            result = report(records, policy) if parsed.command == "report" else budget(records, policy)
        except Refusal as refusal:
            print(f"verification-economics: refused {refusal.detail}")
            _print_codes([refusal.code])
            return 2 if refusal.code == "EC_REFUSED_USAGE" else 1
        if parsed.json:
            print(canonical(result), end="")
        else:
            _summary(result if parsed.command == "budget" else result["budget"])
        codes = result.get("codes") or ["EC_OK"]
        _print_codes(codes)
        failing = codes != ["EC_OK"] or result.get("overall") == "OVER"
        return 1 if failing else 0

    print("verification-economics: usage measure|report|budget")
    _print_codes(["EC_REFUSED_USAGE"])
    return 2


if __name__ == "__main__":
    sys.exit(main())
