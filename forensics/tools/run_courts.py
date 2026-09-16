#!/usr/bin/env python3
"""openssl-rs — run every active stratum's courts, derived from the phase registry.

Why this exists
---------------
The CI venue's job is described as re-running "every court from scratch", and the
workflow used to say which ones by name:

    Phase 2 shell and 11 ABI courts   -> build_phase2.sh
    Phase 3 runtime courts            -> phase3_courts.py
    Phase 4 BIO court                 -> phase4_courts.py

`forensics/tools/phase5_courts.py` existed on disk and was never called. Nine
courts — `RT-BN`, `RT-ASN1`, `RT-ASN1-TEMPLATE`, `RT-ASN1-TIME`, `RT-ASN1-STR`,
`RT-ASN1-PRINT`, `RT-BIO-ASN1`, `RT-ASN1-MIME`, `RT-PEM` — were therefore never
reproduced by CI, and their committed `artifacts/phase5/COURTS.json` was read as
evidence by the regression guard instead. A green authority job said nothing at all
about the stratum that was actually being implemented. See `docs/DECISIONS.md` D94.

The enumeration was the defect, not the omission. A list of runners in the workflow
is a second registry that has to be *remembered*, which is the failure mode D49,
D51 and D92 each recorded in a different guise. This tool derives the list instead:

  * the phases come from `forensics/phase-state.json`, the same derived registry
    `forensics/STATUS.md` is rendered from;
  * each phase's runner is found by convention, so a phase that starts is picked up
    without anyone editing the workflow;
  * a phase that is not `not-started` and has no runner must be **exempted with a
    reason** in `COURTLESS`, so adding a stratum cannot silently add a phase whose
    courts never run;
  * a `phase<N>_courts.py` on disk whose phase is `not-started` is a defect too, and
    is reported rather than ignored.

What it does, per active phase, in numeric order
------------------------------------------------
  1. reads the committed `artifacts/phase<N>/COURTS.json` and holds it aside;
  2. **removes it**, so a file that is present but not reproduced cannot be read as
     evidence by whatever runs next;
  3. runs the phase's runner;
  4. asserts the file exists again, that no court is missing from it, and that every
     court in it passed;
  5. compares it with the copy from step 1 and fails if the committed file's verdicts
     are not the verdicts this run produces, in *either* direction. A committed file
     that claims a pass this run does not reproduce is the trust problem; one that
     claims a failure this run does not reproduce is a record that was not regenerated
     when it should have been. An *increase* in a court's observation count is not a
     failure: recording more observations is what a commit is for, and shrinkage is the
     regression guard's business.

Ordering matters and is why the phases run in numeric order: every runtime court
links against the Phase 2 distribution shell, so the shell must exist before them.
That ordering used to be a property of the workflow's step list; here it is a
property of the loop.

    python3 forensics/tools/run_courts.py                 # every active phase
    python3 forensics/tools/run_courts.py --phase 5       # one of them
    python3 forensics/tools/run_courts.py --list          # what it would run

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
PHASE_STATE = REPO_ROOT / "forensics" / "phase-state.json"

# A stratum with no runtime court of its own, and why. Empty is the goal; every entry
# is a decision that has to be justified rather than an oversight that has to be
# found. Both entries here are the same kind of stratum: they produce *documents*,
# and the evidence for them is the atlas rather than a differential court.
COURTLESS: dict[int, str] = {
    0: "constitution: normative documents, whose evidence is the release-gate mapping in docs/RELEASE_GATES.md",
    1: "archaeology: the atlas, whose evidence is forensics/atlas/ and the symbol-reconciliation residuals it records",
}


# A stratum that is `in-progress` and has no runner *yet*. This is a different condition from
# `COURTLESS`, which is a permanent statement that a stratum's evidence is not a court: a
# stratum lands its ledger in its first subphase and its first probe in its second, and the
# two cannot be one commit without writing the probe before the thing it probes. Phase 6 did
# exactly this -- its modules landed before `RT-PARAM` did, which its own phase-state note
# records.
#
# The exemption is deliberately **conditional and checked in both directions**: it applies
# only while `artifacts/phase<N>/COURTS.json` is absent. The moment a stratum commits a courts
# file it must have a runner, because a committed file that no run reproduces is the trust
# problem this whole tool exists for. And the invariant that a stratum cannot *complete*
# without its courts is not weakened here at all: `phase_state.py` makes an absent courts file
# a blocking reason, so a stratum with no runner cannot reach `complete`.
NO_RUNNER_YET: dict[int, str] = {
    7: (
        "7.0 is the ledger and the stratum's wiring; the first court is `RT-FETCH` and lands "
        "with 7.1, which is where the fetch core it observes is written. Remove this row in "
        "that commit -- the check below fails on a courts file without a runner, so keeping "
        "it past 7.1 is not possible."
    ),
}


def phase_states() -> dict[int, str]:
    """The derived phase registry, as `phase_state.py` writes it."""
    if not PHASE_STATE.is_file():
        raise SystemExit(
            f"run-courts: {PHASE_STATE.relative_to(REPO_ROOT)} is absent, so which "
            "strata are active cannot be derived; run forensics/tools/phase_state.py"
        )
    doc = json.loads(PHASE_STATE.read_text(encoding="utf-8"))
    body = doc.get("body", doc)
    out: dict[int, str] = {}
    for row in body["phases"]:
        out[int(row["phase"])] = str(row["state"])
    if not out:
        raise SystemExit("run-courts: the phase registry lists no phases")
    return out


def runner_for(phase: int) -> tuple[str, list[str]] | None:
    """The command that regenerates a phase's court evidence.

    By convention: the shell builder if the phase has one, because it also produces
    the artefact the later strata's courts link against, and that builder runs the
    phase's own court script itself; otherwise the court script.
    """
    shell = TOOLS / f"build_phase{phase}.sh"
    if shell.is_file():
        return (f"bash {shell.relative_to(REPO_ROOT)}", ["bash", str(shell)])
    script = TOOLS / f"phase{phase}_courts.py"
    if script.is_file():
        return (
            f"python3 {script.relative_to(REPO_ROOT)}",
            [sys.executable, str(script)],
        )
    return None


def courts_path(phase: int) -> Path:
    return REPO_ROOT / "artifacts" / f"phase{phase}" / "COURTS.json"


def load(path: Path) -> dict | None:
    if not path.is_file():
        return None
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("body", doc)


def verdicts(body: dict | None) -> dict[str, str]:
    if not body:
        return {}
    return {str(r["court"]): str(r["verdict"]) for r in body.get("courts", [])}


def observations(body: dict | None) -> dict[str, int]:
    if not body:
        return {}
    return {str(r["court"]): int(r.get("observations", 0))
            for r in body.get("courts", [])}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--phase", type=int, action="append", default=None,
                    help="run only this phase; repeatable")
    ap.add_argument("--list", action="store_true",
                    help="print what would be run and exit")
    args = ap.parse_args(argv)

    states = phase_states()
    active = sorted(p for p, s in states.items() if s != "not-started")
    if args.phase:
        unknown = [p for p in args.phase if p not in states]
        if unknown:
            raise SystemExit(f"run-courts: no such phase: {unknown}")
        active = sorted(args.phase)

    # The registry and the tools have to agree in both directions, and the checks run
    # before anything expensive so a drift is reported rather than paid for.
    problems: list[str] = []
    plan: list[tuple[int, str, list[str]]] = []
    # Reported rather than silently skipped, so a stratum's first subphase says out loud that
    # it has no court rather than reading as a stratum whose courts all passed.
    no_runner_yet: list[str] = []
    for phase in active:
        found = runner_for(phase)
        if found is None:
            if phase in COURTLESS:
                continue
            if phase in NO_RUNNER_YET and not courts_path(phase).exists():
                no_runner_yet.append(f"phase {phase} ({states[phase]}): {NO_RUNNER_YET[phase]}")
                continue
            problems.append(
                f"phase {phase} ({states[phase]}) is not `not-started` and has no "
                f"runner: add forensics/tools/phase{phase}_courts.py, or exempt it in "
                "COURTLESS with the reason it needs none"
            )
            continue
        plan.append((phase, found[0], found[1]))
    for phase, state in sorted(states.items()):
        if state != "not-started" or phase in active:
            continue
        if runner_for(phase) is not None and phase not in COURTLESS:
            problems.append(
                f"phase {phase} is `not-started` but has a runner on disk, so either "
                "the registry is stale or the runner belongs to another stratum"
            )
    if not plan and not problems:
        problems.append("no active phase needs a court runner, which cannot be right")
    if problems:
        print("run-courts: FAIL")
        for p in problems:
            print(f"  {p}")
        return 1

    for line in no_runner_yet:
        print(f"run-courts: no runner yet -- {line}")

    if args.list:
        for phase, command, _argv in plan:
            print(f"phase {phase:>2} ({states[phase]}): {command}")
        return 0

    failures: list[str] = []
    for phase, command, cmd_argv in plan:
        path = courts_path(phase)
        committed = load(path)
        print(f"=== phase {phase} ({states[phase]}): {command}")

        # Step 2: the committed file must not be readable as evidence while the
        # authority-derived one is being produced. This is the whole point: a file
        # that is present but not reproduced used to survive a green job.
        if path.exists():
            path.unlink()

        res = subprocess.run(cmd_argv, cwd=REPO_ROOT)
        if res.returncode != 0:
            failures.append(f"phase {phase}: `{command}` exited {res.returncode}")
            continue

        fresh = load(path)
        if fresh is None:
            failures.append(
                f"phase {phase}: `{command}` did not write "
                f"{path.relative_to(REPO_ROOT)}, so the removal above would have left "
                "the stratum with no court evidence at all"
            )
            continue
        if not fresh.get("all_pass"):
            failed = [c for c, v in verdicts(fresh).items() if v != "pass"]
            failures.append(
                f"phase {phase}: `{command}` reports all_pass false; failing courts: "
                + ", ".join(sorted(failed) or ["<none named>"])
            )
        if committed is None:
            print(f"    no committed evidence to compare against; this run is the first")
            continue

        was, now = verdicts(committed), verdicts(fresh)
        if was != now:
            lost = sorted(c for c in was if c not in now)
            gained = sorted(c for c in now if c not in was)
            changed = sorted(
                f"{c}: {was[c]} -> {now[c]}" for c in was if c in now and was[c] != now[c]
            )
            failures.append(
                f"phase {phase}: the committed evidence is not what this run "
                f"reproduces\n      courts the committed file has and this run does "
                f"not: {lost or '<none>'}\n      courts only this run has: "
                f"{gained or '<none>'}\n      verdicts that moved: {changed or '<none>'}\n"
                "      A verdict that moved in *either* direction is a failure: this "
                "run is the authority-derived one, so the committed file has to be "
                "the file this run writes. Regenerate and commit it."
            )
        # An observation *increase* is reported and allowed: recording more is what a
        # commit is for. A decrease is the regression guard's business, which compares
        # against the pre-push baseline rather than against the committed file.
        was_n, now_n = observations(committed), observations(fresh)
        grew = [f"{c}: {was_n[c]} -> {now_n[c]}"
                for c in sorted(was_n) if now_n.get(c, 0) > was_n[c]]
        if grew:
            print("    more observations than the committed evidence: "
                  + ", ".join(grew))
        print(f"    all_pass, {len(now)} court(s), committed evidence reproduced")

    if failures:
        print("run-courts: FAIL")
        for f in failures:
            print(f"  {f}")
        return 1

    print()
    print(f"run-courts: ok: {len(plan)} phase(s) re-derived from the authority")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
