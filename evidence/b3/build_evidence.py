#!/usr/bin/env python3
"""evidence/b3/build_evidence.py -- the deterministic B3 producer.

It builds the three records from records that already exist, never from the
clock and never from a result this producer invents:

  * ``CAMPAIGNS.json`` -- two real campaigns:
      1. the **programme campaign**: the queue in ``docs/ETP-TODO.md`` at the
         A17 forward freeze's candidate (``731b066e2``), amended by each later
         commit that changed a queue row, with **no terminator** -- so it is
         ``OPEN`` and is not presented as closed;
      2. A22's **eight experiments**, planned as eight checks, closed with
         8 ``PASS`` / 0 ``FAIL`` from the record re-measured at ``e4029e0d5``.
         The earlier closure (6 qualified / 1 defect / 1 partial) is preserved
         as a recorded closure history and in each outcome's history; it is not
         erased.
  * ``RECONCILIATION.json`` -- each campaign against its independent plan: the
    programme campaign against ``evidence/a17/FREEZE-forward.json`` and A22
    against the eight experiment ids in ``evidence/a22/EXPERIMENTS.json``.  The
    produced/missing sets are resolved from the tree of a **declared commit**
    (``asOfCommit``), never from the working tree, so a later item that adds a
    member does not move the record.  The declared commit defaults to the one
    already recorded and is changed only with ``--as-of <commit>``.  A live
    view is a separate command (``campaign.py reconcile --live``) and is never
    written as a record.  The record is still not a closure of the A17 freeze;
    the freeze stays ``OPEN``.
  * ``CONTROLS.json`` -- one ``control-only`` fixture per refusal code, built by
    ``campaign.build_controls()``.

Nothing reads the wall clock.  The base commit, the opening instants and the
closure instants are literals taken from the records named beside them, so two
runs are byte-identical.

Usage:
    python3 evidence/b3/build_evidence.py [--out DIR] [--as-of COMMIT] [--check]

``--check`` recomputes the records in memory and compares them with the
committed bytes instead of writing.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics/tools"
DEFAULT_OUT = REPO_ROOT / "evidence/b3"
sys.path.insert(0, str(TOOLS))

import campaign as ac  # noqa: E402

#: The source candidate at which this record was produced.  A later evidence
#: commit does not move it: the record is *about* this base.
BASE_COMMIT = "1155843e6"
BASE_COMMIT_LONG = "1155843e6fca64704183f6b7d71b2df5b60652ff"

#: The A17 forward freeze was recorded at this candidate and time.
PROGRAMME_BASE = "731b066e261ebc64cf8acb909df18d23b9b11883"
PROGRAMME_OPENED_AT = "2026-11-24T00:20:00Z"  # FREEZE-forward.json#/frozenAt

#: A22's item base, and the two commits its record names.
A22_BASE = "6e64e644ced49bf5d969e0eb56ab51f8f4f2c4fc"
A22_OPENED_AT = "2026-11-24T09:47:33-05:00"  # commit 6e64e644c
A22_FIRST_RECORD = "d3050312fd10e5b45053c6c3d8e9f501a3c6356b"
A22_FIRST_RECORD_AT = "2026-11-24T10:23:59-05:00"  # commit d3050312f
A22_RERECORD = "7c2b5f25fe55e6302b942ed124f4fbec5aff8888"
A22_RERECORD_AT = "2026-11-24T11:20:19-05:00"  # commit 7c2b5f25f
A22_MEASURED_AT = "e4029e0d5"  # RESULTS.json#/baseCommit (the repair commit)

A22_VERDICT_RESULT = {
    "QUALIFIED": ac.R_PASS,
    "DEFECT": ac.R_FAIL,
    "PARTIAL": ac.R_SKIP,
    "NOT_RUN": ac.R_NOT_RUN,
}

#: A queue id is a short section prefix and a number (``T1``, ``A17``, ``B3``).
#: This rejects table headers (``item``, ``id``) without naming them.
QUEUE_ID = re.compile(r"^[A-Z]{1,4}[0-9]+[a-z]?$")


def serialise(document: object) -> bytes:
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


def git(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", str(REPO_ROOT), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(f"code=AC_USAGE\ngit {' '.join(arguments)} failed: {completed.stderr}")
    return completed.stdout


def git_show(ref: str, path: str) -> str:
    return git("show", f"{ref}:{path}")


def commit_time(ref: str) -> str:
    return git("show", "-s", "--format=%cI", ref).strip()


def commit_author(ref: str) -> tuple[str, str]:
    raw = git("show", "-s", "--format=%an|%ae", ref).strip()
    name, _, email = raw.partition("|")
    return name, email


def sha256_text(text: str) -> str:
    return ac.sha256_bytes(text.encode("utf-8"))


# --------------------------------------------------------------------------
# The queue at the recorded base
# --------------------------------------------------------------------------


def todo_rows(text: str) -> list[dict[str, str]]:
    """Parse the queue table rows, in file order.  The first cell is the id."""
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line.startswith("| "):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        check_id = cells[0]
        if not QUEUE_ID.fullmatch(check_id):
            continue
        rows.append(
            {
                "checkId": check_id,
                "description": cells[1],
                "status": cells[2] if len(cells) > 2 else "",
            }
        )
    return rows


def programme_plan() -> list[dict[str, object]]:
    rows = todo_rows(git_show(PROGRAMME_BASE, "docs/ETP-TODO.md"))
    return [
        {
            "checkId": row["checkId"],
            "description": row["description"],
            "required": True,
        }
        for row in rows
    ]


def programme_amendments() -> list[dict[str, object]]:
    """Every commit after the base that changed a queue row, in commit order."""
    commits = git(
        "rev-list", "--reverse", f"{PROGRAMME_BASE}..{BASE_COMMIT}", "--", "docs/ETP-TODO.md"
    ).split()
    amendments: list[dict[str, object]] = []
    for commit in commits:
        parent = git("rev-parse", f"{commit}^").strip()
        before = {
            row["checkId"]: row
            for row in todo_rows(git_show(parent, "docs/ETP-TODO.md"))
        }
        after = {
            row["checkId"]: row
            for row in todo_rows(git_show(commit, "docs/ETP-TODO.md"))
        }
        adds = sorted(set(after) - set(before))
        removes = sorted(set(before) - set(after))
        supersedes = sorted(
            check_id
            for check_id in set(before) & set(after)
            if before[check_id]["description"] != after[check_id]["description"]
            or before[check_id]["status"] != after[check_id]["status"]
        )
        if not adds and not removes and not supersedes:
            continue
        name, email = commit_author(commit)
        subject = git("show", "-s", "--format=%s", commit).strip()
        amendments.append(
            {
                "at": commit_time(commit),
                "reason": f"{subject} [commit {commit[:9]}]",
                "adds": adds,
                "removes": removes,
                "supersedes": supersedes,
                "by": f"{name} <{email}>",
            }
        )
    return amendments


def programme_campaign() -> dict[str, object]:
    plan = programme_plan()
    return {
        "schema": ac.CAMPAIGN_SCHEMA,
        "campaignId": "etp-programme",
        "label": "the ETP programme: the queue at the A17 forward freeze, amended by later queue changes",
        "source": {
            "plan": "docs/ETP-TODO.md",
            "base": PROGRAMME_BASE,
            "openedAtSource": "evidence/a17/FREEZE-forward.json#/frozenAt",
            "reconstructed": False,
        },
        "opening": {
            "campaignId": "etp-programme",
            "openedAt": PROGRAMME_OPENED_AT,
            "plan": plan,
        },
        "amendments": programme_amendments(),
        "closureHistory": [],
        "closure": None,
        "abandonment": None,
        "state": ac.S_OPEN,
        "note": "no terminator exists: the programme is OPEN, not closed. The reconciliation against the A17 forward freeze is a live observation at the recorded base, not a closure of that freeze.",
    }


# --------------------------------------------------------------------------
# A22
# --------------------------------------------------------------------------


def a22_plan() -> list[dict[str, object]]:
    experiments = json.loads(
        (REPO_ROOT / "evidence/a22/EXPERIMENTS.json").read_text(encoding="utf-8")
    )["experiments"]
    return [
        {
            "checkId": experiment["id"],
            "description": experiment["title"],
            "required": True,
        }
        for experiment in experiments
    ]


def a22_results_at(ref: str | None) -> tuple[dict, str]:
    text = (
        (REPO_ROOT / "evidence/a22/RESULTS.json").read_text(encoding="utf-8")
        if ref is None
        else git_show(ref, "evidence/a22/RESULTS.json")
    )
    return json.loads(text), sha256_text(text)


def a22_campaign() -> dict[str, object]:
    plan = a22_plan()
    old, old_digest = a22_results_at(A22_FIRST_RECORD)
    new, new_digest = a22_results_at(None)

    old_outcomes = []
    old_tally = {result: 0 for result in ac.RESULTS}
    for experiment in old["experiments"]:
        result = A22_VERDICT_RESULT[experiment["verdict"]]
        old_tally[result] += 1
        old_outcomes.append(
            {
                "checkId": experiment["id"],
                "result": result,
                "evidence": (
                    f"git:evidence/a22/RESULTS.json@{A22_FIRST_RECORD} "
                    f"(sha256 {old_digest})"
                ),
                "reason": (
                    f"recorded verdict {experiment['verdict']} "
                    f"({experiment.get('refusedWitnesses', 0)}/"
                    f"{experiment.get('rejectedWitnesses', 0)} refused witnesses)"
                ),
            }
        )
    old_summary = (
        f"{old['summary']['qualified']} qualified / {old['summary']['defect']} defect / "
        f"{old['summary']['partial']} partial / {old['summary']['notRun']} not-run; "
        f"allQualified={old['summary']['allQualified']}; "
        f"codes={','.join(old['summary']['codes']) or 'NONE'}"
    )

    history = [
        {
            "at": A22_FIRST_RECORD_AT,
            "record": f"git:evidence/a22/RESULTS.json@{A22_FIRST_RECORD}",
            "outcomes": old_outcomes,
            "summary": {
                "text": old_summary,
                "claimsSuccess": bool(old["summary"]["allQualified"]),
                "counts": {
                    "pass": old_tally[ac.R_PASS],
                    "fail": old_tally[ac.R_FAIL],
                    "skip": old_tally[ac.R_SKIP],
                    "notRun": old_tally[ac.R_NOT_RUN],
                    "planned": len(old_outcomes),
                    "accounted": len(old_outcomes),
                },
            },
        }
    ]

    old_by_id = {outcome["checkId"]: outcome for outcome in old_outcomes}
    outcomes = []
    tally = {result: 0 for result in ac.RESULTS}
    for index, experiment in enumerate(new["experiments"]):
        result = A22_VERDICT_RESULT[experiment["verdict"]]
        tally[result] += 1
        previous = old_by_id[experiment["id"]]
        outcomes.append(
            {
                "checkId": experiment["id"],
                "result": result,
                "evidence": (
                    f"evidence/a22/RESULTS.json#/experiments/{index} "
                    f"(sha256 {new_digest})"
                ),
                "reason": (
                    f"re-measured at {A22_MEASURED_AT} after the repair recorded in "
                    f"evidence/defects/e5-e6/RECEIPT.md; refusals "
                    f"{experiment.get('refusedWitnesses', 0)}/"
                    f"{experiment.get('rejectedWitnesses', 0)}"
                ),
                "history": [
                    {
                        "at": A22_FIRST_RECORD_AT,
                        "result": previous["result"],
                        "evidence": previous["evidence"],
                        "reason": "earlier observation, preserved rather than erased",
                    }
                ],
            }
        )

    closure = {
        "at": A22_RERECORD_AT,
        "record": f"git:evidence/a22/RESULTS.json@{A22_RERECORD}",
        "outcomes": outcomes,
        "summary": {
            "text": (
                f"{tally[ac.R_PASS]} PASS / {tally[ac.R_FAIL]} FAIL / "
                f"{tally[ac.R_SKIP]} SKIP / {tally[ac.R_NOT_RUN]} NOT_RUN after the "
                f"repair at {A22_MEASURED_AT}; the earlier 6/1/1 closure is preserved "
                "in closureHistory and in each outcome's history"
            ),
            "claimsSuccess": True,
            "counts": {
                "pass": tally[ac.R_PASS],
                "fail": tally[ac.R_FAIL],
                "skip": tally[ac.R_SKIP],
                "notRun": tally[ac.R_NOT_RUN],
                "planned": len(outcomes),
                "accounted": len(outcomes),
            },
        },
    }

    return {
        "schema": ac.CAMPAIGN_SCHEMA,
        "campaignId": "a22-adversarial-qualification",
        "label": "A22: eight experiments on the instruments the campaign relies on",
        "source": {
            "plan": "evidence/a22/EXPERIMENTS.json",
            "base": A22_BASE,
            "openedAtSource": "commit 6e64e644c (the item's recorded start base); the plan text is from EXPERIMENTS.json, so this opening is reconstructed, not an authenticated preregistration",
            "reconstructed": True,
        },
        "opening": {
            "campaignId": "a22-adversarial-qualification",
            "openedAt": A22_OPENED_AT,
            "plan": plan,
        },
        "amendments": [],
        "closureHistory": history,
        "closure": closure,
        "abandonment": None,
        "state": ac.S_CLOSED_CLEAN,
        "note": "the plan did not change; the repair changed observations, so the earlier closure is history, not an amendment to the plan. Old and new record digests are in evidence/a22/RECEIPT.md section 11.5.",
    }


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------


def build_campaigns() -> dict[str, object]:
    return {
        "schema": ac.CAMPAIGNS_SCHEMA,
        "model": ac.MODEL_ID,
        "baseCommit": BASE_COMMIT,
        "baseCommitLong": BASE_COMMIT_LONG,
        "tool": ac.tool_identity(),
        "campaigns": [programme_campaign(), a22_campaign()],
    }


def recorded_as_of(out: Path) -> str | None:
    """The declared commit of an existing record, if one is present.

    The old form (``asOf``) is accepted so the first run after the correction
    keeps the commit the record was already about.
    """
    path = out / "RECONCILIATION.json"
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(document, dict):
        for key in ("asOfCommit", "asOf"):
            value = document.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return None


def build_reconciliations(as_of: str, tree: set[str]) -> dict[str, object]:
    freeze = json.loads(
        (REPO_ROOT / "evidence/a17/FREEZE-forward.json").read_text(encoding="utf-8")
    )
    experiments = json.loads(
        (REPO_ROOT / "evidence/a22/EXPERIMENTS.json").read_text(encoding="utf-8")
    )["experiments"]
    independent_a22 = [
        {
            "checkId": experiment["id"],
            "description": experiment["title"],
            "required": True,
        }
        for experiment in experiments
    ]
    return {
        "schema": ac.RECONCILIATION_SCHEMA,
        "model": ac.MODEL_ID,
        "baseCommit": BASE_COMMIT,
        "asOfCommit": as_of,
        "resolvedFrom": "git ls-tree -r --name-only",
        "records": [
            ac.reconcile(programme_campaign(), freeze, as_of=as_of, tree=tree),
            ac.reconcile(a22_campaign(), independent_a22, as_of=as_of, tree=tree),
        ],
        "note": "Each record is frozen at asOfCommit and is not a closure of the A17 forward freeze, which remains OPEN. Later members are not reflected because the record is frozen, not because they are missing. A live view is campaign.py reconcile --live.",
    }


def build(as_of: str, tree: set[str]) -> dict[str, object]:
    campaigns = build_campaigns()
    reconciliations = build_reconciliations(as_of, tree)
    controls = ac.build_controls()

    if not controls["coversEveryCode"]:
        raise ac.Refusal(
            ac.R_OMITTED_CHECK,
            "a refusal code has no control; the refusal table would be decoration",
        )
    broken = [control["name"] for control in controls["controls"] if not control["established"]]
    if broken:
        raise ac.Refusal(ac.R_MANIFEST_INVALID, f"controls did not observe their code: {broken}")

    for reconciliation in reconciliations["records"]:
        if reconciliation["narrowed"] or reconciliation["omitted"]:
            raise ac.Refusal(
                ac.R_PLAN_NARROWED,
                f"{reconciliation['campaignId']} narrows its independent plan",
            )

    # Both real campaigns must validate to the state the record claims.
    for campaign in campaigns["campaigns"]:
        report = ac.validate(campaign)
        if report["state"] != campaign["state"]:
            raise ac.Refusal(
                ac.R_MANIFEST_INVALID,
                f"{campaign['campaignId']} reports {campaign['state']} but validates "
                f"to {report['state']}",
            )

    return {
        "CAMPAIGNS.json": campaigns,
        "RECONCILIATION.json": reconciliations,
        "CONTROLS.json": controls,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="produce the B3 records")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--as-of", default=None)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    out = Path(args.out)
    recorded = recorded_as_of(out)
    as_of_ref = args.as_of or recorded or BASE_COMMIT
    source = "--as-of" if args.as_of else ("record" if recorded else "default")
    try:
        as_of = ac.resolve_commit(as_of_ref, REPO_ROOT)
        tree = ac.commit_paths(as_of, REPO_ROOT)
    except ValueError as exc:
        print(f"code={ac.AC_USAGE}")
        print(f"b3: {exc}", file=sys.stderr)
        return ac.EXIT_USAGE

    records = {
        name: serialise(document)
        for name, document in build(as_of, tree).items()
    }

    if args.check:
        stale = []
        for name, payload in records.items():
            path = out / name
            if not path.is_file() or path.read_bytes() != payload:
                stale.append(name)
        if stale:
            print(f"code={ac.R_MANIFEST_INVALID}")
            print(f"b3: stale record(s): {', '.join(sorted(stale))}")
            return ac.EXIT_REFUSED
        print(f"code={ac.AC_OK} b3: check ok records={len(records)}")
        return ac.EXIT_OK

    out.mkdir(parents=True, exist_ok=True)
    for name, payload in records.items():
        write(out / name, payload)

    campaigns = json.loads(records["CAMPAIGNS.json"])
    controls = json.loads(records["CONTROLS.json"])
    reconciliations = json.loads(records["RECONCILIATION.json"])
    print(
        f"code={ac.AC_OK} b3: base={BASE_COMMIT} "
        f"asOfCommit={as_of} (from {source}) campaigns={len(campaigns['campaigns'])}"
    )
    for campaign in campaigns["campaigns"]:
        report = ac.validate(campaign)
        counts = report.get("outcomes", {})
        print(
            f"b3: campaign={report['campaignId']} state={report['state']} "
            f"planned={report['planned']} amendments={report['amendments']} "
            f"pass={counts.get('pass', 0)} fail={counts.get('fail', 0)} "
            f"skip={counts.get('skip', 0)} notRun={counts.get('notRun', 0)}"
        )
    for reconciliation in reconciliations["records"]:
        print(
            f"b3: reconcile={reconciliation['campaignId']} "
            f"narrowed={str(reconciliation['narrowed']).lower()} "
            f"produced={len(reconciliation['produced'])} "
            f"missing={len(reconciliation['missing'])} "
            f"omitted={len(reconciliation['omitted'])}"
        )
    print(
        f"b3: controls={len(controls['controls'])} "
        f"coversEveryCode={str(controls['coversEveryCode']).lower()}"
    )
    return ac.EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
