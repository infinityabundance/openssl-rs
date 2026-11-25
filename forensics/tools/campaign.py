#!/usr/bin/env python3
"""campaign.py -- a campaign that must account for every check it planned.

The normative document is `docs/CAMPAIGN-ACCOUNTABILITY.md`, which implements
`docs/ETP-ADDENDUM-B.md` B.13-B.14.  The rule it states is temporal and
omission-sensitive:

  * an **opening** freezes the plan *before* the work: every check the campaign
    intends to run, and whether a closure must account for it;
  * **amendments** are bound, dated events that may add or withdraw a check
    prospectively, never rewrite an outcome or shrink the plan after execution;
  * exactly one **terminator** exists: a `closure` that reports every planned
    check, or an `abandonment` that says which required checks were not done and
    why.  A campaign with no terminator is `OPEN`, not finished.

A closure may record a `FAIL`, a `SKIP` or a `NOT_RUN`.  What it may not do is
leave an applicable failure *absent*: an outcome the plan required and the
closure omitted is refused, and a summary that claims success over a recorded
failure, skip or not-run is refused.  A clean summary is a statement about the
outcomes that are present; it is not evidence that a missing check passed.

What this module does
---------------------
* `validate(campaign)` applies the opening, amendment and terminator contracts
  in a fixed order and raises `Refusal` with a stable `AC_REFUSED_*` code naming
  the wrong conclusion it prevents.
* `state(campaign)` / `evaluate(campaign)` report one of `OPEN`,
  `CLOSED_CLEAN`, `CLOSED_WITH_FAILURES`, `ABANDONED` or `INVALID`.
* `reconcile(campaign, independent, root=..., as_of=..., tree=...)` compares the
  campaign's effective plan with an independent plan (the A17 forward freeze, or
  a registry such as A22's eight experiments) and refuses a campaign that
  narrowed its plan.  It also reports the produced and missing members of the
  independent plan.  A **record** is bound to a declared commit (``as_of``): the
  members are resolved from that commit's tree, not from the working tree, so a
  later item that adds a member cannot change the record.  The working tree is
  read only when the caller asks for a **live view** (``as_of=None``); a live
  view is labelled as such, is never written as a record, and is never a closure
  of the independent freeze.
* `build_controls()` builds one in-memory `control-only` fixture per refusal
  code.  A control that fires proves the refusal works; it is not a defect
  report and not evidence that the substituted form occurs in the tree.

What this module does not do
---------------------------
It does not decide whether a check's evidence is true, whether the plan was
complete, or whether a campaign that closed cleanly succeeded.  It detects
omission **relative to a declared plan**; it does not establish that the plan
itself was adequate.  A `PASS` is the campaign's recorded result, not a safety,
compatibility or cryptographic finding.

Usage
-----
    python3 forensics/tools/campaign.py open --out FILE --id ID --at TIME --plan FILE
    python3 forensics/tools/campaign.py amend --campaign FILE --amendment FILE
    python3 forensics/tools/campaign.py close --campaign FILE --closure FILE
    python3 forensics/tools/campaign.py abandon --campaign FILE --abandonment FILE
    python3 forensics/tools/campaign.py reconcile --campaign FILE --plan FILE --as-of COMMIT [--root DIR] [--out FILE]
    python3 forensics/tools/campaign.py reconcile --campaign FILE --plan FILE --live [--root DIR]
    python3 forensics/tools/campaign.py status [--campaign FILE | --campaigns FILE]

Exit status: 0 for a valid record or report, 1 for a refusal, 2 for a usage or
I/O error.  The code is always printed.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = "forensics/tools/campaign.py"

MODEL_ID = "b3/v1"
CAMPAIGN_SCHEMA = "openssl-rs/b3/campaign/1"
CAMPAIGNS_SCHEMA = "openssl-rs/b3/campaigns/1"
RECONCILIATION_SCHEMA = "openssl-rs/b3/reconciliation/1"
CONTROLS_SCHEMA = "openssl-rs/b3/controls/1"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

# --------------------------------------------------------------------------
# Vocabulary.  States and results are stable; a document, receipt or test
# cites them.
# --------------------------------------------------------------------------

R_PASS = "PASS"
R_FAIL = "FAIL"
R_SKIP = "SKIP"
R_NOT_RUN = "NOT_RUN"

RESULTS = (R_PASS, R_FAIL, R_SKIP, R_NOT_RUN)
NON_PASS = (R_FAIL, R_SKIP, R_NOT_RUN)

S_OPEN = "OPEN"
S_CLOSED_CLEAN = "CLOSED_CLEAN"
S_CLOSED_WITH_FAILURES = "CLOSED_WITH_FAILURES"
S_ABANDONED = "ABANDONED"
S_INVALID = "INVALID"

STATES = (S_OPEN, S_CLOSED_CLEAN, S_CLOSED_WITH_FAILURES, S_ABANDONED, S_INVALID)
TERMINAL_STATES = (S_CLOSED_CLEAN, S_CLOSED_WITH_FAILURES, S_ABANDONED)

# Outcome codes that are not refusals.  A refusal code always starts with
# AC_REFUSED_; no other code may.
AC_OK = "AC_OK"
AC_USAGE = "AC_USAGE"
AC_INVALID = "AC_INVALID"
AC_OPEN = "AC_OPEN"
AC_CLOSED_CLEAN = "AC_CLOSED_CLEAN"
AC_CLOSED_WITH_FAILURES = "AC_CLOSED_WITH_FAILURES"
AC_ABANDONED = "AC_ABANDONED"

STATE_CODES = {
    S_OPEN: AC_OPEN,
    S_CLOSED_CLEAN: AC_CLOSED_CLEAN,
    S_CLOSED_WITH_FAILURES: AC_CLOSED_WITH_FAILURES,
    S_ABANDONED: AC_ABANDONED,
    S_INVALID: AC_INVALID,
}

# --------------------------------------------------------------------------
# Refusals.  Each code names the wrong conclusion it prevents.
# --------------------------------------------------------------------------

R_NO_OPENING = "AC_REFUSED_NO_OPENING"
R_DOUBLE_OPENING = "AC_REFUSED_DOUBLE_OPENING"
R_NO_TERMINATOR = "AC_REFUSED_NO_TERMINATOR"
R_DOUBLE_TERMINATOR = "AC_REFUSED_DOUBLE_TERMINATOR"
R_RETROACTIVE_AMENDMENT = "AC_REFUSED_RETROACTIVE_AMENDMENT"
R_UNBOUND_AMENDMENT = "AC_REFUSED_UNBOUND_AMENDMENT"
R_OMITTED_CHECK = "AC_REFUSED_OMITTED_CHECK"
R_FAILURE_OMITTED = "AC_REFUSED_FAILURE_OMITTED"
R_SKIP_AS_PASS = "AC_REFUSED_SKIP_AS_PASS"
R_NOT_RUN_AS_PASS = "AC_REFUSED_NOT_RUN_AS_PASS"
R_UNPLANNED_OUTCOME = "AC_REFUSED_UNPLANNED_OUTCOME"
R_DUPLICATE_OUTCOME = "AC_REFUSED_DUPLICATE_OUTCOME"
R_ABANDONMENT_SILENT = "AC_REFUSED_ABANDONMENT_SILENT"
R_ORDER = "AC_REFUSED_ORDER"
R_COUNT_MISMATCH = "AC_REFUSED_COUNT_MISMATCH"
R_PLAN_NARROWED = "AC_REFUSED_PLAN_NARROWED"
R_MANIFEST_INVALID = "AC_REFUSED_MANIFEST_INVALID"

REFUSALS: dict[str, str] = {
    R_NO_OPENING: "a campaign with no frozen plan read as accountable",
    R_DOUBLE_OPENING: "two plans, so the later one can be chosen after execution",
    R_NO_TERMINATOR: "an unfinished campaign read as finished",
    R_DOUBLE_TERMINATOR: "a closure and an abandonment, so either can be cited later",
    R_RETROACTIVE_AMENDMENT: "an amendment that rewrites an outcome already recorded",
    R_UNBOUND_AMENDMENT: "an amendment that binds to no planned check",
    R_OMITTED_CHECK: "a closure that leaves a required planned check absent",
    R_FAILURE_OMITTED: "a success summary over a recorded FAIL",
    R_SKIP_AS_PASS: "a success summary over a recorded SKIP",
    R_NOT_RUN_AS_PASS: "a success summary over a recorded NOT_RUN",
    R_UNPLANNED_OUTCOME: "an outcome for a check the plan never contained",
    R_DUPLICATE_OUTCOME: "two results for one check, so a reader can choose",
    R_ABANDONMENT_SILENT: "an abandonment that does not say which required checks were not done",
    R_ORDER: "a closure before its opening, or an amendment after the terminator",
    R_COUNT_MISMATCH: "a summary whose counts do not reconcile with its outcomes",
    R_PLAN_NARROWED: "a campaign that silently dropped a required independent check",
    R_MANIFEST_INVALID: "a malformed record read as a campaign",
}

REFUSAL_CODES = tuple(sorted(REFUSALS))


class Refusal(Exception):
    """A record is refused, with a stable code and a human-readable detail."""

    def __init__(self, code: str, detail: str) -> None:
        if code not in REFUSALS:
            raise AssertionError(f"undeclared refusal code {code}")
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> None:
    raise Refusal(code, detail)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def canonical_bytes(document: Any) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path | str) -> str:
    return sha256_bytes(Path(path).read_bytes())


# --------------------------------------------------------------------------
# Declared trees.  A reconciliation record is bound to a commit, so the paths it
# reports are read from that commit's tree; the working tree is a separate view.
# --------------------------------------------------------------------------


def resolve_commit(ref: str, root: Path | str = REPO_ROOT) -> str:
    """Resolve ``ref`` to the full commit id, or raise ``ValueError``.

    A short or symbolic ref must never be recorded as if it were an identity,
    and an unresolvable ref must never fall back to the working tree.
    """
    completed = subprocess.run(
        [
            "git",
            "-c",
            "safe.directory=*",
            "-C",
            str(root),
            "rev-parse",
            "--verify",
            f"{ref}^{{commit}}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(
            f"cannot resolve {ref!r} to a commit: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def commit_paths(commit: str, root: Path | str = REPO_ROOT) -> set[str]:
    """The repo-relative paths of ``commit``'s tree, from `git ls-tree`."""
    completed = subprocess.run(
        [
            "git",
            "-c",
            "safe.directory=*",
            "-C",
            str(root),
            "ls-tree",
            "-r",
            "--name-only",
            commit,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(
            f"cannot read the tree of {commit!r}: {completed.stderr.strip()}"
        )
    return {line.strip() for line in completed.stdout.splitlines() if line.strip()}


def tool_identity() -> dict[str, str]:
    return {"path": TOOL_PATH, "sha256": sha256_file(REPO_ROOT / TOOL_PATH)}


def _as_document(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(R_MANIFEST_INVALID, f"{what} is not an object")
    return value


def _require_text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(R_MANIFEST_INVALID, f"{what} must be a non-empty string")
    return value


def _require_bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        _fail(R_MANIFEST_INVALID, f"{what} must be a boolean")
    return value


def _require_list(value: Any, what: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(R_MANIFEST_INVALID, f"{what} must be a list")
    return value


def _parse_time(value: Any, what: str) -> datetime:
    text = _require_text(value, what)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        _fail(R_MANIFEST_INVALID, f"{what} is not an ISO-8601 instant: {text!r}")
    if parsed.tzinfo is None:
        _fail(R_MANIFEST_INVALID, f"{what} carries no timezone: {text!r}")
    return parsed


def _text_list(value: Any, what: str) -> list[str]:
    entries = _require_list(value, what)
    for index, entry in enumerate(entries):
        if not isinstance(entry, str) or not entry.strip():
            _fail(R_MANIFEST_INVALID, f"{what}[{index}] must be a non-empty string")
    return list(entries)


# --------------------------------------------------------------------------
# Opening and plan
# --------------------------------------------------------------------------


def _opening_records(campaign: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return the opening records, preserving a duplicate so it is detectable.

    The canonical record carries one `opening` object.  A list (or an
    `openings` list alongside an `opening` object) is preserved rather than
    collapsed: two frozen plans are a refusal, not a preference for one.
    """
    records: list[dict[str, Any]] = []
    opening = campaign.get("opening")
    if opening is None:
        pass
    elif isinstance(opening, list):
        records.extend(opening)
    else:
        records.append(opening)
    openings = campaign.get("openings")
    if openings is not None:
        if isinstance(openings, list):
            records.extend(openings)
        else:
            records.append(openings)
    return records


def _normalise_plan(plan: Any) -> list[dict[str, Any]]:
    entries = _require_list(plan, "opening.plan")
    seen: set[str] = set()
    normalised: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if isinstance(entry, str):
            check_id = _require_text(entry, f"opening.plan[{index}]")
            description = ""
            required = True
        else:
            entry = _as_document(entry, f"opening.plan[{index}]")
            check_id = _require_text(entry.get("checkId"), f"opening.plan[{index}].checkId")
            description = entry.get("description", "")
            if not isinstance(description, str):
                _fail(R_MANIFEST_INVALID, f"opening.plan[{index}].description must be a string")
            required = _require_bool(entry.get("required"), f"opening.plan[{index}].required")
        if check_id in seen:
            _fail(R_MANIFEST_INVALID, f"opening.plan repeats checkId {check_id!r}")
        seen.add(check_id)
        normalised.append(
            {"checkId": check_id, "description": description, "required": required}
        )
    if not normalised:
        _fail(R_MANIFEST_INVALID, "opening.plan is empty; a campaign with no checks is not a campaign")
    return normalised


def _plan_map(plan: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    return {entry["checkId"]: dict(entry) for entry in plan}


# --------------------------------------------------------------------------
# Amendments
# --------------------------------------------------------------------------


def _normalise_amendment(
    amendment: Any, index: int, plan: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    amendment = _as_document(amendment, f"amendments[{index}]")
    at = _parse_time(amendment.get("at"), f"amendments[{index}].at")
    reason = _require_text(amendment.get("reason"), f"amendments[{index}].reason")
    by = _require_text(amendment.get("by"), f"amendments[{index}].by")

    def entries(field: str) -> list[Any]:
        value = amendment.get(field, [])
        return _require_list(value, f"amendments[{index}].{field}")

    adds_raw = entries("adds")
    removes = _text_list(entries("removes"), f"amendments[{index}].removes")
    supersedes = _text_list(entries("supersedes"), f"amendments[{index}].supersedes")

    adds: list[dict[str, Any]] = []
    for position, entry in enumerate(adds_raw):
        if isinstance(entry, str):
            check_id = _require_text(entry, f"amendments[{index}].adds[{position}]")
            candidate = {"checkId": check_id, "description": "", "required": True}
        else:
            entry = _as_document(entry, f"amendments[{index}].adds[{position}]")
            candidate = {
                "checkId": _require_text(
                    entry.get("checkId"), f"amendments[{index}].adds[{position}].checkId"
                ),
                "description": entry.get("description", ""),
                "required": _require_bool(
                    entry.get("required"), f"amendments[{index}].adds[{position}].required"
                ),
            }
            if not isinstance(candidate["description"], str):
                _fail(
                    R_MANIFEST_INVALID,
                    f"amendments[{index}].adds[{position}].description must be a string",
                )
        if candidate["checkId"] in plan:
            _fail(
                R_UNBOUND_AMENDMENT,
                f"amendment {index} adds {candidate['checkId']!r}, which the plan already contains",
            )
        adds.append(candidate)

    for check_id in removes:
        if check_id not in plan:
            _fail(
                R_UNBOUND_AMENDMENT,
                f"amendment {index} removes {check_id!r}, which the plan does not contain",
            )
    for check_id in supersedes:
        if check_id not in plan:
            _fail(
                R_UNBOUND_AMENDMENT,
                f"amendment {index} supersedes {check_id!r}, which the plan does not contain",
            )

    outcome_edits = amendment.get("outcomeEdits", [])
    outcome_edits = _text_list(outcome_edits, f"amendments[{index}].outcomeEdits")

    if not adds and not removes and not supersedes and not outcome_edits:
        _fail(
            R_UNBOUND_AMENDMENT,
            f"amendment {index} adds, removes and supersedes nothing; it is bound to no check",
        )

    return {
        "at": at,
        "atText": amendment.get("at"),
        "reason": reason,
        "by": by,
        "adds": adds,
        "removes": removes,
        "supersedes": supersedes,
        "outcomeEdits": outcome_edits,
    }


def _apply_amendment(
    plan: dict[str, dict[str, Any]],
    amendment: Mapping[str, Any],
    label: str,
) -> None:
    for candidate in amendment["adds"]:
        plan[candidate["checkId"]] = {
            "checkId": candidate["checkId"],
            "description": candidate["description"],
            "required": candidate["required"],
        }
    for check_id in amendment["removes"]:
        plan.pop(check_id, None)
    for check_id in amendment["supersedes"]:
        entry = plan.get(check_id)
        if entry is not None:
            entry = dict(entry)
            history = list(entry.get("supersededBy", []))
            history.append(label)
            entry["supersededBy"] = history
            plan[check_id] = entry


def effective_plan(campaign: Any) -> list[dict[str, Any]]:
    """The plan after every amendment, keyed by checkId and in opening order.

    A superseded entry keeps its id and gains `supersededBy`; it is not deleted,
    so a closure still has to account for it.
    """
    campaign = _as_document(campaign, "campaign")
    openings = _opening_records(campaign)
    if len(openings) != 1:
        _fail(
            R_NO_OPENING if not openings else R_DOUBLE_OPENING,
            f"expected exactly one opening, found {len(openings)}",
        )
    plan = _plan_map(_normalise_plan(openings[0].get("plan")))
    raw = campaign.get("amendments", [])
    for index, amendment in enumerate(_require_list(raw, "amendments")):
        normalised = _normalise_amendment(amendment, index, plan)
        _apply_amendment(plan, normalised, f"amendments[{index}]")
    return list(plan.values())


# --------------------------------------------------------------------------
# Terminators
# --------------------------------------------------------------------------


def _terminator_records(campaign: Mapping[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    records: list[tuple[str, dict[str, Any]]] = []
    for kind in ("closure", "abandonment"):
        value = campaign.get(kind)
        if value is None:
            continue
        if isinstance(value, list):
            for entry in value:
                records.append((kind, _as_document(entry, kind)))
        else:
            records.append((kind, _as_document(value, kind)))
    return records


def _outcome_ids(closure: Mapping[str, Any]) -> list[str]:
    outcomes = closure.get("outcomes")
    if not isinstance(outcomes, list):
        return []
    return [
        outcome.get("checkId")
        for outcome in outcomes
        if isinstance(outcome, dict) and isinstance(outcome.get("checkId"), str)
    ]


def _normalise_history(campaign: Mapping[str, Any]) -> list[dict[str, Any]]:
    history: list[dict[str, Any]] = []
    for index, entry in enumerate(_require_list(campaign.get("closureHistory", []), "closureHistory")):
        entry = _as_document(entry, f"closureHistory[{index}]")
        at = _parse_time(entry.get("at"), f"closureHistory[{index}].at")
        outcomes = _require_list(entry.get("outcomes"), f"closureHistory[{index}].outcomes")
        seen: set[str] = set()
        normalised: list[dict[str, Any]] = []
        for position, outcome in enumerate(outcomes):
            outcome = _as_document(outcome, f"closureHistory[{index}].outcomes[{position}]")
            check_id = _require_text(
                outcome.get("checkId"), f"closureHistory[{index}].outcomes[{position}].checkId"
            )
            result = outcome.get("result")
            if result not in RESULTS:
                _fail(
                    R_MANIFEST_INVALID,
                    f"closureHistory[{index}].outcomes[{position}].result is not one of {RESULTS}",
                )
            if check_id in seen:
                _fail(
                    R_DUPLICATE_OUTCOME,
                    f"closureHistory[{index}] records {check_id!r} twice",
                )
            seen.add(check_id)
            normalised.append(
                {
                    "checkId": check_id,
                    "result": result,
                    "evidence": outcome.get("evidence", ""),
                    "reason": outcome.get("reason", ""),
                }
            )
        history.append(
            {
                "at": at,
                "atText": entry.get("at"),
                "outcomes": normalised,
                "summary": entry.get("summary"),
                "record": entry.get("record", ""),
            }
        )
    return history


# --------------------------------------------------------------------------
# Closure validation
# --------------------------------------------------------------------------


def _normalise_outcome(outcome: Any, where: str) -> dict[str, Any]:
    outcome = _as_document(outcome, where)
    check_id = _require_text(outcome.get("checkId"), f"{where}.checkId")
    result = outcome.get("result")
    if result not in RESULTS:
        _fail(R_MANIFEST_INVALID, f"{where}.result is not one of {RESULTS}: {result!r}")
    evidence = outcome.get("evidence", "")
    reason = outcome.get("reason", "")
    if not isinstance(evidence, str) or not isinstance(reason, str):
        _fail(R_MANIFEST_INVALID, f"{where}.evidence and .reason must be strings")
    if result in (R_PASS, R_FAIL) and not evidence.strip():
        _fail(R_MANIFEST_INVALID, f"{where} is {result} and carries no evidence")
    if result in (R_SKIP, R_NOT_RUN) and not reason.strip():
        _fail(R_MANIFEST_INVALID, f"{where} is {result} and carries no reason")
    history = outcome.get("history", [])
    history = _require_list(history, f"{where}.history")
    for position, entry in enumerate(history):
        entry = _as_document(entry, f"{where}.history[{position}]")
        _parse_time(entry.get("at"), f"{where}.history[{position}].at")
        if entry.get("result") not in RESULTS:
            _fail(
                R_MANIFEST_INVALID,
                f"{where}.history[{position}].result is not one of {RESULTS}",
            )
        _require_text(entry.get("evidence"), f"{where}.history[{position}].evidence")
        _require_text(entry.get("reason"), f"{where}.history[{position}].reason")
    return {
        "checkId": check_id,
        "result": result,
        "evidence": evidence,
        "reason": reason,
        "history": history,
    }


def _validate_closure(
    closure: Mapping[str, Any], plan: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    _parse_time(closure.get("at"), "closure.at")
    raw_outcomes = _require_list(closure.get("outcomes"), "closure.outcomes")
    outcomes = [
        _normalise_outcome(outcome, f"closure.outcomes[{index}]")
        for index, outcome in enumerate(raw_outcomes)
    ]

    planned = {entry["checkId"]: entry for entry in plan}
    seen: set[str] = set()
    for index, outcome in enumerate(outcomes):
        check_id = outcome["checkId"]
        if check_id in seen:
            _fail(
                R_DUPLICATE_OUTCOME,
                f"closure.outcomes records {check_id!r} more than once",
            )
        seen.add(check_id)
        if check_id not in planned:
            _fail(
                R_UNPLANNED_OUTCOME,
                f"closure records {check_id!r}, which the plan does not contain",
            )

    required = [entry["checkId"] for entry in plan if entry["required"]]
    omitted = [check_id for check_id in required if check_id not in seen]
    if omitted:
        _fail(
            R_OMITTED_CHECK,
            "closure omits required planned check(s): " + ", ".join(sorted(omitted)),
        )

    tally = {result: 0 for result in RESULTS}
    for outcome in outcomes:
        tally[outcome["result"]] += 1

    summary = _as_document(closure.get("summary"), "closure.summary")
    counts = _as_document(summary.get("counts"), "closure.summary.counts")
    required_counts = ("pass", "fail", "skip", "notRun", "planned", "accounted")
    for field in required_counts:
        if field not in counts:
            _fail(R_COUNT_MISMATCH, f"closure.summary.counts has no {field!r}")
        if not isinstance(counts[field], int) or isinstance(counts[field], bool):
            _fail(R_COUNT_MISMATCH, f"closure.summary.counts.{field} is not an integer")

    observed = {
        "pass": tally[R_PASS],
        "fail": tally[R_FAIL],
        "skip": tally[R_SKIP],
        "notRun": tally[R_NOT_RUN],
    }
    for field, value in observed.items():
        if counts[field] != value:
            _fail(
                R_COUNT_MISMATCH,
                f"summary {field}={counts[field]} but the outcomes contain {value}",
            )
    if counts["planned"] != len(plan):
        _fail(
            R_COUNT_MISMATCH,
            f"summary planned={counts['planned']} but the effective plan has {len(plan)}",
        )
    if counts["accounted"] != len(outcomes):
        _fail(
            R_COUNT_MISMATCH,
            f"summary accounted={counts['accounted']} but there are {len(outcomes)} outcomes",
        )
    if counts["accounted"] != sum(observed.values()):
        _fail(
            R_COUNT_MISMATCH,
            "summary accounted does not equal pass + fail + skip + notRun",
        )
    if counts["accounted"] > counts["planned"]:
        _fail(R_COUNT_MISMATCH, "summary accounts for more checks than were planned")

    claims_success = _require_bool(summary.get("claimsSuccess"), "closure.summary.claimsSuccess")
    if claims_success:
        if observed["fail"]:
            _fail(
                R_FAILURE_OMITTED,
                f"summary claims success while {observed['fail']} outcome(s) are FAIL",
            )
        if observed["skip"]:
            _fail(
                R_SKIP_AS_PASS,
                f"summary claims success while {observed['skip']} outcome(s) are SKIP",
            )
        if observed["notRun"]:
            _fail(
                R_NOT_RUN_AS_PASS,
                f"summary claims success while {observed['notRun']} outcome(s) are NOT_RUN",
            )

    clean = (
        claims_success
        and observed["pass"] == len(plan)
        and counts["accounted"] == counts["planned"]
    )
    state = S_CLOSED_CLEAN if clean else S_CLOSED_WITH_FAILURES
    return {
        "state": state,
        "outcomes": observed,
        "planned": len(plan),
        "accounted": len(outcomes),
        "claimsSuccess": claims_success,
        "clean": clean,
    }


def _validate_abandonment(
    abandonment: Mapping[str, Any], plan: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    _parse_time(abandonment.get("at"), "abandonment.at")
    _require_text(abandonment.get("reason"), "abandonment.reason")
    raw = _require_list(abandonment.get("notDone"), "abandonment.notDone")
    planned = {entry["checkId"]: entry for entry in plan}
    seen: set[str] = set()
    for index, entry in enumerate(raw):
        entry = _as_document(entry, f"abandonment.notDone[{index}]")
        check_id = _require_text(entry.get("checkId"), f"abandonment.notDone[{index}].checkId")
        _require_text(entry.get("why"), f"abandonment.notDone[{index}].why")
        if check_id in seen:
            _fail(
                R_MANIFEST_INVALID,
                f"abandonment.notDone records {check_id!r} more than once",
            )
        seen.add(check_id)
        if check_id not in planned:
            _fail(
                R_MANIFEST_INVALID,
                f"abandonment.notDone records {check_id!r}, which the plan does not contain",
            )
    missing = [
        entry["checkId"] for entry in plan if entry["required"] and entry["checkId"] not in seen
    ]
    if missing:
        _fail(
            R_ABANDONMENT_SILENT,
            "abandonment does not say why required check(s) were not done: "
            + ", ".join(sorted(missing)),
        )
    return {"state": S_ABANDONED, "notDone": len(raw), "planned": len(plan)}


# --------------------------------------------------------------------------
# The contract
# --------------------------------------------------------------------------


def validate(campaign: Any, require_terminator: bool = False) -> dict[str, Any]:
    """Apply the contract in a fixed order.  Raises `Refusal` on the first violation.

    An opening with no terminator is a valid **open** campaign and reports
    `OPEN`.  `require_terminator=True` is for a caller that asked for a finished
    record (for example a closure operation); it refuses the same record with
    `AC_REFUSED_NO_TERMINATOR`.  A record that *claims* a terminal state while
    carrying no terminator is always refused.
    """
    campaign = _as_document(campaign, "campaign")
    campaign_id = _require_text(campaign.get("campaignId"), "campaignId")

    openings = _opening_records(campaign)
    if not openings:
        _fail(R_NO_OPENING, "the campaign has no opening record")
    if len(openings) > 1:
        _fail(R_DOUBLE_OPENING, f"the campaign has {len(openings)} opening records")
    opening = _as_document(openings[0], "opening")
    if opening.get("campaignId") is not None and opening.get("campaignId") != campaign_id:
        _fail(
            R_MANIFEST_INVALID,
            f"opening.campaignId {opening.get('campaignId')!r} disagrees with {campaign_id!r}",
        )
    opened_at = _parse_time(opening.get("openedAt"), "opening.openedAt")
    opening_plan = _normalise_plan(opening.get("plan"))

    plan = _plan_map(opening_plan)
    amendments: list[dict[str, Any]] = []
    raw_amendments = _require_list(campaign.get("amendments", []), "amendments")
    for index, raw in enumerate(raw_amendments):
        amendment = _normalise_amendment(raw, index, plan)
        if amendment["at"] < opened_at:
            _fail(
                R_ORDER,
                f"amendment {index} at {amendment['atText']} precedes opening at "
                f"{opening.get('openedAt')}",
            )
        amendments.append(amendment)
        _apply_amendment(plan, amendment, f"amendments[{index}]")

    terminators = _terminator_records(campaign)
    claimed = campaign.get("state")
    if claimed is not None and claimed not in STATES:
        _fail(R_MANIFEST_INVALID, f"campaign.state {claimed!r} is not a known state")
    if not terminators:
        if require_terminator or claimed in TERMINAL_STATES:
            _fail(
                R_NO_TERMINATOR,
                "the record claims a terminated campaign but carries neither a closure "
                "nor an abandonment",
            )
        # An open campaign is a valid record: it is not closed, and that is the
        # state it reports.  Only a closure or abandonment can be a terminator.
        report = _report(campaign_id, S_OPEN, opening, opening_plan, plan, amendments, None)
        report = _with_state_claim(campaign, report)
        return report
    if claimed in (S_CLOSED_CLEAN, S_CLOSED_WITH_FAILURES) and terminators[0][0] != "closure":
        _fail(R_MANIFEST_INVALID, "campaign claims a closure but its terminator is an abandonment")
    if claimed == S_ABANDONED and terminators[0][0] != "abandonment":
        _fail(R_MANIFEST_INVALID, "campaign claims abandonment but its terminator is a closure")
    if len(terminators) > 1:
        _fail(
            R_DOUBLE_TERMINATOR,
            "the campaign has "
            + ", ".join(f"{kind} at {value.get('at')!r}" for kind, value in terminators),
        )

    kind, terminator = terminators[0]
    terminator_at = _parse_time(terminator.get("at"), f"{kind}.at")
    if terminator_at < opened_at:
        _fail(
            R_ORDER,
            f"{kind} at {terminator.get('at')} precedes opening at {opening.get('openedAt')}",
        )
    for index, amendment in enumerate(amendments):
        if amendment["at"] > terminator_at:
            _fail(
                R_ORDER,
                f"amendment {index} at {amendment['atText']} follows the terminator at "
                f"{terminator.get('at')}",
            )

    history = _normalise_history(campaign)
    for index, entry in enumerate(history):
        if entry["at"] > terminator_at:
            _fail(
                R_ORDER,
                f"closureHistory[{index}] at {entry['atText']} follows the terminator at "
                f"{terminator.get('at')}",
            )

    recorded: set[str] = set()
    if kind == "closure":
        recorded.update(_outcome_ids(terminator))
    for entry in history:
        recorded.update(outcome["checkId"] for outcome in entry["outcomes"])
    for index, amendment in enumerate(amendments):
        if amendment["outcomeEdits"]:
            _fail(
                R_RETROACTIVE_AMENDMENT,
                f"amendment {index} edits an outcome ({', '.join(amendment['outcomeEdits'])})",
            )
        touched = set(amendment["supersedes"]) | set(amendment["removes"])
        overlap = sorted(touched & recorded)
        if overlap:
            _fail(
                R_RETROACTIVE_AMENDMENT,
                f"amendment {index} supersedes or removes check(s) with a recorded outcome: "
                + ", ".join(overlap),
            )

    if kind == "closure":
        body = _validate_closure(terminator, list(plan.values()))
        report = _report(
            campaign_id, body["state"], opening, opening_plan, plan, amendments, body
        )
        report["historyCount"] = len(history)
        return _with_state_claim(campaign, report)

    body = _validate_abandonment(terminator, list(plan.values()))
    report = _report(campaign_id, body["state"], opening, opening_plan, plan, amendments, body)
    report["historyCount"] = len(history)
    return _with_state_claim(campaign, report)


def _with_state_claim(
    campaign: Mapping[str, Any], report: dict[str, Any]
) -> dict[str, Any]:
    """A record that names its own state must name the state it actually has."""
    claimed = campaign.get("state")
    if claimed is not None and claimed != report["state"]:
        _fail(
            R_MANIFEST_INVALID,
            f"campaign.state says {claimed!r} but the record validates to {report['state']!r}",
        )
    return report


def _report(
    campaign_id: str,
    state: str,
    opening: Mapping[str, Any],
    opening_plan: Sequence[Mapping[str, Any]],
    plan: Mapping[str, Mapping[str, Any]],
    amendments: Sequence[Mapping[str, Any]],
    body: Mapping[str, Any] | None,
) -> dict[str, Any]:
    required = sum(1 for entry in plan.values() if entry["required"])
    report: dict[str, Any] = {
        "campaignId": campaign_id,
        "state": state,
        "code": STATE_CODES[state],
        "openedAt": opening.get("openedAt"),
        "openingPlan": len(opening_plan),
        "planned": len(plan),
        "required": required,
        "amendments": len(amendments),
        "added": sorted(
            {
                candidate["checkId"]
                for amendment in amendments
                for candidate in amendment["adds"]
            }
        ),
        "removed": sorted(
            {check_id for amendment in amendments for check_id in amendment["removes"]}
        ),
        "superseded": sorted(
            {check_id for amendment in amendments for check_id in amendment["supersedes"]}
        ),
    }
    if body is not None:
        report.update(dict(body))
    return report


def evaluate(campaign: Any) -> dict[str, Any]:
    """Return the report, or `state=INVALID` with the refusal code and detail."""
    try:
        return validate(campaign)
    except Refusal as refusal:
        return {
            "campaignId": (campaign or {}).get("campaignId")
            if isinstance(campaign, dict)
            else None,
            "state": S_INVALID,
            "code": refusal.code,
            "detail": refusal.detail,
        }


def state(campaign: Any) -> str:
    return evaluate(campaign)["state"]


# --------------------------------------------------------------------------
# Reconciliation against an independent plan
# --------------------------------------------------------------------------


def _independent_plan(document: Any) -> list[dict[str, Any]]:
    """Normalise an independent plan.

    Accepted forms:

    * an A17 freeze (`{"members": [{id, phase, path, predicate, required}]}`);
    * `{"plan": [...]}`, `{"checks": [...]}` or a bare list of plan entries.
    """
    if isinstance(document, dict) and isinstance(document.get("members"), list):
        entries = []
        for index, member in enumerate(document["members"]):
            member = _as_document(member, f"independent.members[{index}]")
            check_id = member.get("phase") or member.get("checkId")
            check_id = _require_text(check_id, f"independent.members[{index}].phase")
            entries.append(
                {
                    "checkId": check_id,
                    "memberId": member.get("id"),
                    "description": member.get("predicate", ""),
                    "required": _require_bool(
                        member.get("required"), f"independent.members[{index}].required"
                    ),
                    "path": member.get("path"),
                }
            )
        return entries
    if isinstance(document, dict):
        for key in ("plan", "checks"):
            if isinstance(document.get(key), list):
                document = document[key]
                break
        else:
            _fail(R_MANIFEST_INVALID, "independent plan is an object with no plan or members")
    entries = _require_list(document, "independent plan")
    normalised: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if isinstance(entry, str):
            normalised.append(
                {
                    "checkId": entry,
                    "memberId": None,
                    "description": "",
                    "required": True,
                    "path": None,
                }
            )
            continue
        entry = _as_document(entry, f"independent[{index}]")
        check_id = _require_text(
            entry.get("checkId") or entry.get("phase") or entry.get("id"),
            f"independent[{index}].checkId",
        )
        required = entry.get("required", True)
        normalised.append(
            {
                "checkId": check_id,
                "memberId": entry.get("id"),
                "description": entry.get("description", entry.get("predicate", "")),
                "required": _require_bool(required, f"independent[{index}].required"),
                "path": entry.get("path"),
            }
        )
    return normalised


def reconcile(
    campaign: Any,
    independent: Any,
    root: Path | str = REPO_ROOT,
    as_of: str | None = None,
    tree: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Compare the effective plan with an independent plan.

    Raises `AC_REFUSED_PLAN_NARROWED` when a required independent check has no
    entry in the campaign's effective plan.

    ``as_of`` is the commit the record is about.  When it is given, ``tree``
    must be that commit's path set (see `commit_paths`), and produced/missing are
    resolved from **that tree**: a later commit, or the working tree, cannot move
    the record.  When ``as_of`` is None the view is **live** -- resolved from
    ``root`` and marked ``liveView: true`` -- and is reported, never committed as
    a record.
    """
    if as_of is not None and tree is None:
        raise ValueError(
            "a frozen reconciliation requires the declared commit's tree"
        )
    if as_of is None and tree is not None:
        raise ValueError("a path set without as_of is not a declared view")
    report = validate(campaign)
    root = Path(root)
    external = _independent_plan(independent)
    declared = set(tree) if tree is not None else None

    plan_report = effective_plan(campaign)
    campaign_ids = {entry["checkId"] for entry in plan_report}
    external_ids = {entry["checkId"] for entry in external}

    omitted = sorted(
        entry["checkId"]
        for entry in external
        if entry["required"] and entry["checkId"] not in campaign_ids
    )
    if omitted:
        _fail(
            R_PLAN_NARROWED,
            "the campaign plan omits required independent check(s): " + ", ".join(omitted),
        )

    outcome_by_id: dict[str, str] = {}
    closure = campaign.get("closure") if isinstance(campaign, dict) else None
    if isinstance(closure, dict):
        for outcome in closure.get("outcomes", []) or []:
            if isinstance(outcome, dict) and isinstance(outcome.get("checkId"), str):
                outcome_by_id[outcome["checkId"]] = outcome.get("result")

    produced: list[str] = []
    missing: list[str] = []
    not_passed: list[str] = []
    for entry in external:
        check_id = entry["checkId"]
        label = entry["memberId"] or check_id
        path = entry.get("path")
        if path:
            if declared is not None:
                present = path in declared
            else:
                present = (root / path).is_file()
            if present:
                produced.append(label)
            else:
                missing.append(label)
        else:
            if outcome_by_id.get(check_id) == R_PASS:
                produced.append(label)
            else:
                missing.append(label)
        if closure is not None and outcome_by_id.get(check_id) != R_PASS:
            not_passed.append(check_id)

    return {
        "schema": RECONCILIATION_SCHEMA,
        "campaignId": report["campaignId"],
        "campaignState": report["state"],
        "independent": {
            "kind": "A17-forward-freeze"
            if isinstance(independent, dict) and "members" in independent
            else "registry",
            "state": independent.get("state")
            if isinstance(independent, dict)
            else None,
            "id": independent.get("id") if isinstance(independent, dict) else None,
            "members": len(external),
            "required": sum(1 for entry in external if entry["required"]),
        },
        "campaignPlan": {
            "planned": len(plan_report),
            "required": sum(1 for entry in plan_report if entry["required"]),
        },
        "externalOnly": sorted(external_ids - campaign_ids),
        "campaignOnly": sorted(campaign_ids - external_ids),
        "omitted": omitted,
        "narrowed": False,
        "produced": sorted(produced),
        "missing": sorted(missing),
        "notPassed": sorted(not_passed),
        "asOfCommit": as_of,
        "liveView": as_of is None,
        "record": _record_description(as_of, external),
    }


def _record_description(
    as_of: str | None, external: Sequence[Mapping[str, Any]]
) -> str:
    if as_of is None:
        return (
            "live working-tree view, not a record and not a closure of the "
            "independent plan"
        )
    if any(entry.get("path") for entry in external):
        return (
            "frozen at asOfCommit: declared paths are read from that commit's "
            "tree, so later members are not in this view and their absence is "
            "not a finding that they are missing"
        )
    return (
        "frozen: produced/missing come from the campaign's recorded outcomes, "
        "so later activity does not change this record"
    )


# --------------------------------------------------------------------------
# Controls
# --------------------------------------------------------------------------

BASE_PLAN = [
    {"checkId": "C1", "description": "first check", "required": True},
    {"checkId": "C2", "description": "second check", "required": True},
    {"checkId": "C3", "description": "third check", "required": True},
]


def _base_campaign() -> dict[str, Any]:
    return {
        "schema": CAMPAIGN_SCHEMA,
        "campaignId": "control-fixture",
        "opening": {
            "campaignId": "control-fixture",
            "openedAt": "2026-01-01T00:00:00Z",
            "plan": copy.deepcopy(BASE_PLAN),
        },
        "amendments": [],
        "closureHistory": [],
        "closure": _closure(
            [
                ("C1", R_PASS),
                ("C2", R_PASS),
                ("C3", R_PASS),
            ],
            claims_success=True,
        ),
        "abandonment": None,
    }


def _outcome(check_id: str, result: str) -> dict[str, Any]:
    if result in (R_PASS, R_FAIL):
        return {
            "checkId": check_id,
            "result": result,
            "evidence": f"control-only:evidence/{check_id}",
            "reason": "",
        }
    return {
        "checkId": check_id,
        "result": result,
        "evidence": "",
        "reason": f"control-only:{result.lower()} reason",
    }


def _closure(
    rows: Sequence[tuple[str, str]], claims_success: bool
) -> dict[str, Any]:
    outcomes = [_outcome(check_id, result) for check_id, result in rows]
    tally = {result: 0 for result in RESULTS}
    for _, result in rows:
        tally[result] += 1
    return {
        "at": "2026-01-02T00:00:00Z",
        "outcomes": outcomes,
        "summary": {
            "text": "control-only summary",
            "claimsSuccess": claims_success,
            "counts": {
                "pass": tally[R_PASS],
                "fail": tally[R_FAIL],
                "skip": tally[R_SKIP],
                "notRun": tally[R_NOT_RUN],
                "planned": len(rows),
                "accounted": len(rows),
            },
        },
    }


def _amendment(**overrides: Any) -> dict[str, Any]:
    amendment = {
        "at": "2026-01-01T12:00:00Z",
        "reason": "control-only amendment",
        "adds": [],
        "removes": [],
        "supersedes": [],
        "by": "control-only:author",
    }
    amendment.update(overrides)
    return amendment


def _observe(fn: Callable[[], Any]) -> str | None:
    try:
        fn()
    except Refusal as refusal:
        return refusal.code
    return None


def build_controls() -> dict[str, Any]:
    """One in-memory control per refusal code, plus two positive controls.

    Each control is `control-only`: it mutates a synthetic campaign in memory.
    It proves the refusal fires; it says nothing about the tree.
    """
    controls: list[dict[str, Any]] = []

    def add(
        name: str,
        code: str | None,
        fixture: str,
        fn: Callable[[], Any],
        kind: str = "refusal",
    ) -> None:
        observed = _observe(fn)
        controls.append(
            {
                "name": name,
                "code": code,
                "observed": observed,
                "established": observed == code,
                "controlOnly": True,
                "kind": kind,
                "fixture": fixture,
            }
        )

    def campaign_without_opening() -> None:
        fixture = _base_campaign()
        del fixture["opening"]
        validate(fixture)

    def campaign_with_two_openings() -> None:
        fixture = _base_campaign()
        fixture["opening"] = [fixture["opening"], copy.deepcopy(fixture["opening"])]
        validate(fixture)

    def campaign_without_terminator() -> None:
        fixture = _base_campaign()
        fixture["closure"] = None
        validate(fixture, require_terminator=True)

    def campaign_claims_a_closure_without_one() -> None:
        fixture = _base_campaign()
        fixture["closure"] = None
        fixture["state"] = S_CLOSED_CLEAN
        validate(fixture)

    def campaign_with_two_terminators() -> None:
        fixture = _base_campaign()
        fixture["closure"] = [fixture["closure"], copy.deepcopy(fixture["closure"])]
        validate(fixture)

    def campaign_with_retroactive_amendment() -> None:
        fixture = _base_campaign()
        fixture["amendments"] = [_amendment(supersedes=["C1"])]
        validate(fixture)

    def campaign_with_unbound_amendment() -> None:
        fixture = _base_campaign()
        fixture["amendments"] = [_amendment()]
        validate(fixture)

    def closure_omits_a_check() -> None:
        fixture = _base_campaign()
        fixture["closure"] = _closure(
            [("C1", R_PASS), ("C2", R_PASS)], claims_success=False
        )
        fixture["closure"]["summary"]["counts"]["planned"] = 3
        validate(fixture)

    def success_over_a_failure() -> None:
        fixture = _base_campaign()
        fixture["closure"] = _closure(
            [("C1", R_PASS), ("C2", R_FAIL), ("C3", R_PASS)], claims_success=True
        )
        validate(fixture)

    def success_over_a_skip() -> None:
        fixture = _base_campaign()
        fixture["closure"] = _closure(
            [("C1", R_PASS), ("C2", R_SKIP), ("C3", R_PASS)], claims_success=True
        )
        validate(fixture)

    def success_over_a_not_run() -> None:
        fixture = _base_campaign()
        fixture["closure"] = _closure(
            [("C1", R_PASS), ("C2", R_NOT_RUN), ("C3", R_PASS)],
            claims_success=True,
        )
        validate(fixture)

    def outcome_for_an_unplanned_check() -> None:
        fixture = _base_campaign()
        fixture["closure"] = _closure(
            [("C1", R_PASS), ("C2", R_PASS), ("C3", R_PASS), ("C9", R_PASS)],
            claims_success=True,
        )
        validate(fixture)

    def duplicate_outcome() -> None:
        fixture = _base_campaign()
        fixture["closure"] = _closure(
            [("C1", R_PASS), ("C1", R_PASS), ("C2", R_PASS), ("C3", R_PASS)],
            claims_success=True,
        )
        validate(fixture)

    def silent_abandonment() -> None:
        fixture = _base_campaign()
        fixture["closure"] = None
        fixture["abandonment"] = {
            "at": "2026-01-02T00:00:00Z",
            "reason": "control-only abandonment",
            "notDone": [
                {"checkId": "C1", "why": "control-only: not done"},
                {"checkId": "C2", "why": "control-only: not done"},
            ],
        }
        validate(fixture)

    def terminator_before_opening() -> None:
        fixture = _base_campaign()
        fixture["closure"]["at"] = "2025-12-31T00:00:00Z"
        validate(fixture)

    def amendment_after_terminator() -> None:
        fixture = _base_campaign()
        fixture["amendments"] = [
            _amendment(at="2026-01-03T00:00:00Z", supersedes=["C1"])
        ]
        validate(fixture)

    def counts_disagree() -> None:
        fixture = _base_campaign()
        fixture["closure"]["summary"]["counts"]["pass"] = 2
        validate(fixture)

    def campaign_plan_narrowed() -> dict[str, Any]:
        fixture = _base_campaign()
        fixture["opening"]["plan"] = copy.deepcopy(BASE_PLAN[:2])
        fixture["closure"] = _closure(
            [("C1", R_PASS), ("C2", R_PASS)], claims_success=True
        )
        return reconcile(fixture, copy.deepcopy(BASE_PLAN))

    def malformed_campaign() -> None:
        fixture = _base_campaign()
        del fixture["campaignId"]
        validate(fixture)

    def malformed_result() -> None:
        fixture = _base_campaign()
        fixture["closure"]["outcomes"][0]["result"] = "PARTIAL"
        validate(fixture)

    add(
        "no-opening",
        R_NO_OPENING,
        "a campaign whose opening record is absent",
        campaign_without_opening,
    )
    add(
        "double-opening",
        R_DOUBLE_OPENING,
        "two opening records, so the plan can be chosen after execution",
        campaign_with_two_openings,
    )
    add(
        "no-terminator",
        R_NO_TERMINATOR,
        "neither a closure nor an abandonment, where the caller asked for a finished record",
        campaign_without_terminator,
    )
    add(
        "claimed-closed-without-terminator",
        R_NO_TERMINATOR,
        "a record whose state says CLOSED_CLEAN but which carries no closure",
        campaign_claims_a_closure_without_one,
    )
    add(
        "double-terminator",
        R_DOUBLE_TERMINATOR,
        "two closure records, so either can be cited later",
        campaign_with_two_terminators,
    )
    add(
        "retroactive-amendment",
        R_RETROACTIVE_AMENDMENT,
        "an amendment supersedes a check whose outcome the closure already records",
        campaign_with_retroactive_amendment,
    )
    add(
        "unbound-amendment",
        R_UNBOUND_AMENDMENT,
        "an amendment that adds, removes and supersedes nothing",
        campaign_with_unbound_amendment,
    )
    add(
        "omitted-check",
        R_OMITTED_CHECK,
        "a closure that leaves required check C3 absent",
        closure_omits_a_check,
    )
    add(
        "failure-omitted",
        R_FAILURE_OMITTED,
        "a closure records C2 FAIL while its summary claims success",
        success_over_a_failure,
    )
    add(
        "skip-as-pass",
        R_SKIP_AS_PASS,
        "a closure records C2 SKIP while its summary claims success",
        success_over_a_skip,
    )
    add(
        "not-run-as-pass",
        R_NOT_RUN_AS_PASS,
        "a closure records C2 NOT_RUN while its summary claims success",
        success_over_a_not_run,
    )
    add(
        "unplanned-outcome",
        R_UNPLANNED_OUTCOME,
        "an outcome for C9, which the plan never contained",
        outcome_for_an_unplanned_check,
    )
    add(
        "duplicate-outcome",
        R_DUPLICATE_OUTCOME,
        "two outcomes for C1",
        duplicate_outcome,
    )
    add(
        "abandonment-silent",
        R_ABANDONMENT_SILENT,
        "an abandonment whose notDone omits required check C3",
        silent_abandonment,
    )
    add(
        "order-terminator",
        R_ORDER,
        "a closure dated before its opening",
        terminator_before_opening,
    )
    add(
        "amendment-after-terminator",
        R_ORDER,
        "an amendment dated after the closure",
        amendment_after_terminator,
    )
    add(
        "count-mismatch",
        R_COUNT_MISMATCH,
        "a summary that counts two PASS when the outcomes contain three",
        counts_disagree,
    )
    add(
        "plan-narrowed",
        R_PLAN_NARROWED,
        "a campaign plan C1/C2 reconciled against an independent plan C1/C2/C3",
        campaign_plan_narrowed,
    )
    add(
        "manifest-invalid",
        R_MANIFEST_INVALID,
        "a campaign with no campaignId",
        malformed_campaign,
    )
    add(
        "unknown-result",
        R_MANIFEST_INVALID,
        "an outcome result that is not PASS/FAIL/SKIP/NOT_RUN",
        malformed_result,
    )

    # Positive controls: the record is valid, and the state says what it is.
    def positive_closed_with_failures() -> None:
        fixture = _base_campaign()
        fixture["closure"] = _closure(
            [("C1", R_PASS), ("C2", R_FAIL), ("C3", R_PASS)], claims_success=False
        )
        report = validate(fixture)
        if report["state"] != S_CLOSED_WITH_FAILURES:
            raise AssertionError(report["state"])

    def positive_clean() -> None:
        report = validate(_base_campaign())
        if report["state"] != S_CLOSED_CLEAN:
            raise AssertionError(report["state"])

    add(
        "positive-closed-with-failures",
        None,
        "a closure that records C2 FAIL and claims no success",
        positive_closed_with_failures,
        kind="positive",
    )
    add(
        "positive-closed-clean",
        None,
        "three PASS outcomes and a success summary",
        positive_clean,
        kind="positive",
    )

    covered = {control["code"] for control in controls if control["code"]}
    return {
        "schema": CONTROLS_SCHEMA,
        "model": MODEL_ID,
        "tool": TOOL_PATH,
        "controls": controls,
        "codes": list(REFUSAL_CODES),
        "coversEveryCode": covered == set(REFUSAL_CODES),
        "positiveControls": [
            control["name"] for control in controls if control["kind"] == "positive"
        ],
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _read_json(path: Path | str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"code={AC_USAGE}", file=sys.stdout)
        print(f"ac: cannot read {path}: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE) from exc
    except json.JSONDecodeError as exc:
        print(f"code={AC_USAGE}", file=sys.stdout)
        print(f"ac: {path} is not JSON: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE) from exc


def _write_json(path: Path | str, document: Any) -> None:
    path = Path(path)
    payload = (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_bytes(payload)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _plan_from(path: Path | str) -> list[dict[str, Any]]:
    document = _read_json(path)
    if isinstance(document, dict):
        for key in ("plan", "checks"):
            if isinstance(document.get(key), list):
                document = document[key]
                break
    return _normalise_plan(document)


def _command_open(args: argparse.Namespace) -> int:
    plan = _plan_from(args.plan)
    campaign = {
        "schema": CAMPAIGN_SCHEMA,
        "campaignId": args.id,
        "label": args.label,
        "opening": {
            "campaignId": args.id,
            "openedAt": args.at,
            "plan": plan,
        },
        "amendments": [],
        "closureHistory": [],
        "closure": None,
        "abandonment": None,
    }
    report = validate(campaign)
    _write_json(args.out, campaign)
    print(f"code={report['code']} campaign={args.id} state={report['state']} planned={report['planned']}")
    return EXIT_OK


def _load_campaign(path: Path | str) -> dict[str, Any]:
    campaign = _read_json(path)
    return _as_document(campaign, "campaign")


def _command_amend(args: argparse.Namespace) -> int:
    campaign = _load_campaign(args.campaign)
    amendment = _read_json(args.amendment)
    campaign.setdefault("amendments", []).append(amendment)
    report = validate(campaign)
    _write_json(args.campaign, campaign)
    print(
        f"code={report['code']} campaign={report['campaignId']} state={report['state']} "
        f"amendments={report['amendments']}"
    )
    return EXIT_OK


def _command_close(args: argparse.Namespace) -> int:
    campaign = _load_campaign(args.campaign)
    if campaign.get("abandonment") is not None:
        _fail(R_DOUBLE_TERMINATOR, "the campaign already has an abandonment")
    campaign["closure"] = _read_json(args.closure)
    report = validate(campaign)
    _write_json(args.campaign, campaign)
    print(
        f"code={report['code']} campaign={report['campaignId']} state={report['state']} "
        f"pass={report['outcomes']['pass']} fail={report['outcomes']['fail']} "
        f"skip={report['outcomes']['skip']} notRun={report['outcomes']['notRun']}"
    )
    return EXIT_OK


def _command_abandon(args: argparse.Namespace) -> int:
    campaign = _load_campaign(args.campaign)
    if campaign.get("closure") is not None:
        _fail(R_DOUBLE_TERMINATOR, "the campaign already has a closure")
    campaign["abandonment"] = _read_json(args.abandonment)
    report = validate(campaign)
    _write_json(args.campaign, campaign)
    print(
        f"code={report['code']} campaign={report['campaignId']} state={report['state']} "
        f"notDone={report['notDone']}"
    )
    return EXIT_OK


def _command_reconcile(args: argparse.Namespace) -> int:
    if args.live and args.as_of:
        print(f"code={AC_USAGE}", file=sys.stdout)
        print(
            "ac: --live and --as-of are different views; choose one",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if not args.live and not args.as_of:
        print(f"code={AC_USAGE}", file=sys.stdout)
        print(
            "ac: reconcile requires --as-of COMMIT (a frozen record) or "
            "--live (the working tree); a live view is never written as a record",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if args.live and args.out:
        print(f"code={AC_USAGE}", file=sys.stdout)
        print(
            "ac: --live writes nothing; --out is only for a frozen view",
            file=sys.stderr,
        )
        return EXIT_USAGE
    campaign = _load_campaign(args.campaign)
    independent = _read_json(args.plan)
    if args.live:
        report = reconcile(campaign, independent, root=args.root)
        print(
            f"code={AC_OK} campaign={report['campaignId']} state=LIVE "
            f"campaignState={report['campaignState']} view=working-tree "
            f"narrowed={str(report['narrowed']).lower()} "
            f"produced={len(report['produced'])} missing={len(report['missing'])} "
            f"omitted={len(report['omitted'])}"
        )
    else:
        try:
            as_of = resolve_commit(args.as_of, REPO_ROOT)
            tree = commit_paths(as_of, REPO_ROOT)
        except ValueError as exc:
            print(f"code={AC_USAGE}", file=sys.stdout)
            print(f"ac: {exc}", file=sys.stderr)
            return EXIT_USAGE
        report = reconcile(
            campaign, independent, root=args.root, as_of=as_of, tree=tree
        )
        if args.out:
            _write_json(args.out, report)
        print(
            f"code={AC_OK} campaign={report['campaignId']} "
            f"state={report['campaignState']} view=frozen "
            f"asOf={report['asOfCommit']} "
            f"narrowed={str(report['narrowed']).lower()} "
            f"produced={len(report['produced'])} missing={len(report['missing'])} "
            f"omitted={len(report['omitted'])}"
        )
    if report["missing"]:
        print("missing=" + ",".join(report["missing"]))
    if report["notPassed"]:
        print("notPassed=" + ",".join(report["notPassed"]))
    return EXIT_OK


def _command_status(args: argparse.Namespace) -> int:
    if args.campaign:
        documents = [_load_campaign(args.campaign)]
    else:
        document = _read_json(args.campaigns)
        if isinstance(document, dict) and isinstance(document.get("campaigns"), list):
            documents = document["campaigns"]
        elif isinstance(document, list):
            documents = document
        else:
            print(f"code={AC_USAGE}", file=sys.stdout)
            print("ac: campaigns file has no campaign list", file=sys.stderr)
            return EXIT_USAGE
    worst = EXIT_OK
    for document in documents:
        report = evaluate(document)
        line = (
            f"campaign={report.get('campaignId')} state={report['state']} "
            f"code={report['code']}"
        )
        for field in ("planned", "required", "amendments", "accounted"):
            if field in report:
                line += f" {field}={report[field]}"
        if "outcomes" in report:
            outcomes = report["outcomes"]
            line += (
                f" pass={outcomes['pass']} fail={outcomes['fail']} "
                f"skip={outcomes['skip']} notRun={outcomes['notRun']}"
            )
        if report["state"] == S_INVALID:
            line += f" detail={report.get('detail', '')}"
            worst = EXIT_REFUSED
        print(line)
    return worst


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - argparse path
        self.print_usage(sys.stderr)
        print(f"code={AC_USAGE}", file=sys.stdout)
        print(f"ac: {message}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _Parser(description="opening, amendment, closure and abandonment records")
    subparsers = parser.add_subparsers(dest="command", required=True)

    open_parser = subparsers.add_parser("open")
    open_parser.add_argument("--out", required=True)
    open_parser.add_argument("--id", required=True)
    open_parser.add_argument("--at", required=True)
    open_parser.add_argument("--plan", required=True)
    open_parser.add_argument("--label", default="")
    open_parser.set_defaults(func=_command_open)

    amend_parser = subparsers.add_parser("amend")
    amend_parser.add_argument("--campaign", required=True)
    amend_parser.add_argument("--amendment", required=True)
    amend_parser.set_defaults(func=_command_amend)

    close_parser = subparsers.add_parser("close")
    close_parser.add_argument("--campaign", required=True)
    close_parser.add_argument("--closure", required=True)
    close_parser.set_defaults(func=_command_close)

    abandon_parser = subparsers.add_parser("abandon")
    abandon_parser.add_argument("--campaign", required=True)
    abandon_parser.add_argument("--abandonment", required=True)
    abandon_parser.set_defaults(func=_command_abandon)

    reconcile_parser = subparsers.add_parser("reconcile")
    reconcile_parser.add_argument("--campaign", required=True)
    reconcile_parser.add_argument("--plan", required=True)
    reconcile_parser.add_argument("--root", default=str(REPO_ROOT))
    reconcile_parser.add_argument("--as-of", default=None)
    reconcile_parser.add_argument("--live", action="store_true")
    reconcile_parser.add_argument("--out", default=None)
    reconcile_parser.set_defaults(func=_command_reconcile)

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--campaign", default=None)
    status_parser.add_argument(
        "--campaigns", default=str(REPO_ROOT / "evidence/b3/CAMPAIGNS.json")
    )
    status_parser.set_defaults(func=_command_status)

    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return args.func(args)
    except Refusal as refusal:
        print(f"code={refusal.code}", file=sys.stdout)
        print(f"ac: {refusal.detail}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
