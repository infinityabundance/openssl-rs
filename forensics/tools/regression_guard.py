#!/usr/bin/env python3
"""openssl-rs — the regression guard: a new commit may not undo earlier work.

Why this exists
---------------
The project's claims are cumulative. Phase 3 proved a differential runtime; Phase 4
proves part of BIO; later strata will prove much more. None of that survives if a
later commit quietly drops an implemented symbol, reopens an obligation, weakens a
probe, or lets a passing court start failing. Those are exactly the regressions
that are invisible in a green "build + tests" check, because a *removed* behaviour
has no failing test.

So the guard compares the current derived evidence against a **committed baseline**
and fails on any movement in the wrong direction. It reads only committed,
content-addressed artefacts, so it runs without the authority:

  * `forensics/atlas/implemented-surface.json`   symbols the crate defines
  * `forensics/phase3-obligations.json`          Phase 3 hand-offs
  * `forensics/phase4-obligations.json`          Phase 4 hand-offs and open work
  * `artifacts/phase{2,3,4}/COURTS.json`         per-court verdicts and observations
  * `forensics/phase-state.json`                 derived phase states

What counts as a regression
---------------------------
| signal | direction | why |
|---|---|---|
| implemented symbols per library | non-decreasing | dropping one is a lost implementation |
| open obligations per ledger | non-increasing | a newly unbuilt symbol is lost ground |
| court verdict | pass must stay pass | a passing court is the strongest claim held |
| observations per court | non-decreasing | a weakened probe is a silent loss of coverage |
| phase state | non-decreasing | `complete` may not become `in-progress` |

A *deferred* count is recorded but not directional: a symbol may legitimately move
from `open` to `deferred` when the stratum that owns its dependency is identified.
The guard prints that movement so it is visible rather than silent.

`--update` rewrites the baseline. That is a deliberate, reviewable act: the diff of
`forensics/regression-baseline.json` is the reviewable statement "the project's
evidence moved, and here is where".

Outputs
-------
  forensics/regression-baseline.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, rel  # noqa: E402

BASELINE = REPO_ROOT / "forensics" / "regression-baseline.json"

# Derived evidence, in the order the report presents it. Every path is committed,
# so the guard needs neither a compiler nor the authority.
IMPLEMENTED_SURFACE = "forensics/atlas/implemented-surface.json"
PHASE_STATE = "forensics/phase-state.json"
OBLIGATION_LEDGERS = {
    "phase3": "forensics/phase3-obligations.json",
    "phase4": "forensics/phase4-obligations.json",
}
COURT_RESULTS = {
    "phase2": "artifacts/phase2/COURTS.json",
    "phase3": "artifacts/phase3/COURTS.json",
    "phase4": "artifacts/phase4/COURTS.json",
}

# The phase states, ordered. A move to a lower rank is a regression.
STATE_RANK = {"not-started": 0, "in-progress": 1, "complete": 2}


def read_json(relpath: str) -> dict | None:
    p = REPO_ROOT / relpath
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def observe() -> dict:
    """The current evidence, reduced to the numbers the guard compares."""
    obs: dict = {"implemented": {}, "open_obligations": {}, "deferred": {},
                 "courts": {}, "phases": {}}

    surface = read_json(IMPLEMENTED_SURFACE)
    if surface:
        for lib, v in surface["body"]["libraries"].items():
            obs["implemented"][lib] = v["implemented"]

    for name, path in OBLIGATION_LEDGERS.items():
        doc = read_json(path)
        if not doc:
            continue
        counts = doc["body"]["counts"]
        # Phase 3 spells it `deferred`; Phase 4 splits hand-offs from open work.
        obs["open_obligations"][name] = counts.get("open_in_this_stratum", 0)
        obs["deferred"][name] = counts.get("deferred", counts.get(
            "deferred_to_later_phase", 0))

    for name, path in COURT_RESULTS.items():
        doc = read_json(path)
        if not doc:
            continue
        for c in doc["body"]["courts"]:
            obs["courts"][c["court"]] = {
                "verdict": c["verdict"],
                "observations": c.get("authority_observations", 0),
            }

    state = read_json(PHASE_STATE)
    if state:
        for row in state["body"]["phases"]:
            obs["phases"][str(row["phase"])] = row["state"]

    return obs


def compare(baseline: dict, current: dict) -> tuple[list[str], list[str]]:
    """Return (regressions, movements). Movements are informational."""
    regressions: list[str] = []
    movements: list[str] = []

    for lib, was in baseline.get("implemented", {}).items():
        now = current["implemented"].get(lib)
        if now is None:
            regressions.append(
                f"implemented[{lib}]: baseline {was}, now absent from the "
                f"implemented-surface manifest")
        elif now < was:
            regressions.append(f"implemented[{lib}]: {was} -> {now} (lost {was - now})")
        elif now > was:
            movements.append(f"implemented[{lib}]: {was} -> {now} (+{now - was})")

    for name, was in baseline.get("open_obligations", {}).items():
        now = current["open_obligations"].get(name, 0)
        if now > was:
            regressions.append(
                f"{name} open obligations: {was} -> {now} (+{now - was})")

    for name, was in baseline.get("deferred", {}).items():
        now = current["deferred"].get(name, 0)
        if now != was:
            movements.append(f"{name} deferred: {was} -> {now}")

    for court, base in baseline.get("courts", {}).items():
        now = current["courts"].get(court)
        if now is None:
            if base["verdict"] == "pass":
                regressions.append(f"court {court}: was pass, now absent")
            continue
        if base["verdict"] == "pass" and now["verdict"] != "pass":
            regressions.append(
                f"court {court}: was pass, now {now['verdict']}")
        if now["observations"] < base["observations"]:
            regressions.append(
                f"court {court}: observations {base['observations']} -> "
                f"{now['observations']} (weakened probe)")
        elif now["observations"] > base["observations"]:
            movements.append(
                f"court {court}: observations {base['observations']} -> "
                f"{now['observations']} (+{now['observations'] - base['observations']})")

    for phase, was in baseline.get("phases", {}).items():
        now = current["phases"].get(phase)
        if now is None:
            regressions.append(f"phase {phase}: was {was}, now absent")
        elif STATE_RANK.get(now, -1) < STATE_RANK.get(was, -1):
            regressions.append(f"phase {phase}: {was} -> {now}")

    return regressions, movements


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--update", action="store_true",
                    help="rewrite the baseline from the current evidence")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    current = observe()

    if args.update:
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
        print(f"[regression-guard] baseline written -> {rel(BASELINE)}")
        for lib, n in sorted(current["implemented"].items()):
            print(f"  implemented[{lib}] = {n}")
        for name, n in sorted(current["open_obligations"].items()):
            print(f"  open[{name}] = {n}")
        for court, rec in sorted(current["courts"].items()):
            print(f"  court {court} = {rec['verdict']} ({rec['observations']} obs)")
        return 0

    baseline = read_json(str(BASELINE.relative_to(REPO_ROOT)))
    if not baseline:
        raise SystemExit(
            f"[regression-guard] {rel(BASELINE)} is missing; create it with "
            f"`--update` and review the diff")

    regressions, movements = compare(baseline, current)

    if not args.quiet:
        for m in movements:
            print(f"  movement: {m}")

    if regressions:
        print(f"[regression-guard] FAIL: {len(regressions)} regression(s)")
        for r in regressions:
            print(f"  REGRESSION: {r}")
        return 1

    total_obs = sum(c["observations"] for c in current["courts"].values())
    print(f"[regression-guard] ok: no regression "
          f"({len(current['courts'])} court(s), {total_obs} observations)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
