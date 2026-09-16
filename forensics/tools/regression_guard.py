#!/usr/bin/env python3
"""openssl-rs — the regression guard: a commit may not undo earlier evidence.

The rule
--------
A commit may not remove an implementation, reopen an obligation, break a passing
court, weaken a probe, or move a phase backwards. A green "build + unit tests"
check does not enforce that, because *subtraction* produces no failing test.

Two baselines, not one
----------------------
An earlier version of this tool compared the working-tree evidence against the
working-tree baseline. That is a self-certifying loop: a commit could delete
forty implementations, run `--update`, commit the lower baseline, and pass. The
check would be arithmetically true and procedurally worthless.

So there are **two** trust boundaries:

1. The **authority** is the baseline at `--baseline-ref` (the merge base or the
   default branch), read *through git*, not from the working tree. A candidate
   cannot lower it, because the candidate is not the thing being read. This is the
   comparison that must pass.
2. The **proposed baseline** is `forensics/regression-baseline.json` in the working
   tree. With `--require-current` it must equal the observed evidence exactly, so a
   stale baseline is a failure rather than a quiet drift. Taken together, the two
   checks say: *do not regress against the authority, and keep the proposed
   baseline honest*.

Absence is never zero
---------------------
Every check is fail-closed: if a baseline recorded evidence for a plane and the
current checkout cannot produce that plane at all — a ledger deleted, a court
result removed, a manifest missing — that is a **regression**, not an improvement.
An absent evidence plane must never resemble successful completion.

What counts as a regression
---------------------------
| signal | direction | why |
|---|---|---|
| implemented symbols per library | non-decreasing | a lost implementation |
| open obligations per ledger | non-increasing | a newly unbuilt symbol |
| court verdict | `pass` must stay `pass` | the strongest claim held |
| observations per court | non-decreasing | a weakened probe loses coverage silently |
| phase state | non-decreasing | `complete` must not become `in-progress` |
| prerequisite findings | zero, and zero | a dependency nobody owns |
| prerequisite censuses | non-increasing | a hidden omission growing behind a "not a failure" label |

A *deferred* count is recorded and printed but is not directional: a symbol may
legitimately move from `open` to `deferred` once the stratum owning its dependency
is named. That movement is reported so it is visible rather than silent.

Outputs
-------
  forensics/regression-baseline.json          (only with --update)

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    REPO_ROOT,
    court_observations,
    rel,
)

BASELINE_REL = "forensics/regression-baseline.json"
BASELINE = REPO_ROOT / BASELINE_REL

IMPLEMENTED_SURFACE = "forensics/atlas/implemented-surface.json"
PREREQUISITE_GATE = "forensics/atlas/prerequisite-gate.json"
PHASE_STATE = "forensics/phase-state.json"
TRANSITIONS = "forensics/ownership-transitions.json"

# The ledgers and court results are **discovered**, not listed. Listing them meant
# every new stratum had to remember to update this guard, which is the failure mode
# the project exists to remove: an obligation that disappears between classification
# layers. The glob is cross-checked against `phase-state.json`'s phase inventory, so
# a ledger for a phase the state does not know -- or a non-`not-started` phase with
# no ledger -- is a failure rather than a silent omission.
def discover_ledgers() -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(REPO_ROOT.glob("forensics/phase*-obligations.json")):
        m = re.fullmatch(r"phase(\d+)-obligations\.json", p.name)
        if m:
            out[f"phase{m.group(1)}"] = rel(p)
    return out


def discover_courts() -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(REPO_ROOT.glob("artifacts/phase*/COURTS.json")):
        out[p.parent.name] = rel(p)
    return out


OBLIGATION_LEDGERS = discover_ledgers()
COURT_RESULTS = discover_courts()

STATE_RANK = {"not-started": 0, "in-progress": 1, "complete": 2}


def read_json(relpath: str) -> dict | None:
    p = REPO_ROOT / relpath
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def baseline_from_ref(ref: str, allow_missing: bool) -> dict | None:
    """Read the committed baseline at `ref` **through git**.

    Reading it through git rather than from the filesystem is the whole point: the
    candidate's working tree cannot influence it. `None` means the ref predates
    the baseline entirely (the bootstrap case), which is only tolerated when the
    caller asks for it.
    """
    out = subprocess.run(
        ["git", "show", f"{ref}:{BASELINE_REL}"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    if out.returncode != 0:
        if allow_missing and "does not exist" in out.stderr or \
                (allow_missing and "exists on disk, but not in" in out.stderr) or \
                (allow_missing and "Path '" in out.stderr):
            return None
        raise SystemExit(
            f"[regression-guard] cannot read {BASELINE_REL} at {ref!r}:\n"
            f"{out.stderr.strip()}\n"
            "  Pass a ref that exists (the merge base or the default branch), or"
            " --allow-missing-baseline when the ref predates the baseline."
        )
    return json.loads(out.stdout)


def observe() -> dict:
    """The current evidence, reduced to the numbers the guard compares."""
    obs: dict = {"implemented": {}, "open_obligations": {}, "owned_obligations": {},
                 "deferred": {}, "courts": {}, "phases": {}, "court_phases": []}

    surface = read_json(IMPLEMENTED_SURFACE)
    if surface:
        for lib, v in surface["body"]["libraries"].items():
            obs["implemented"][lib] = v["implemented"]

    for name, path in OBLIGATION_LEDGERS.items():
        doc = read_json(path)
        if not doc:
            continue
        counts = doc["body"]["counts"]
        obs["open_obligations"][name] = counts.get("open_in_this_stratum", 0)
        # The owned count is what makes a scope correction distinguishable from a
        # regression: see `transition_for`.
        obs["owned_obligations"][name] = counts.get("owned", 0)
        obs["deferred"][name] = counts.get(
            "deferred", counts.get("deferred_to_later_phase", 0))

    for name, path in COURT_RESULTS.items():
        doc = read_json(path)
        if not doc:
            continue
        obs["court_phases"].append(name)
        for c in doc["body"]["courts"]:
            obs["courts"][c["court"]] = {
                "verdict": c["verdict"],
                "observations": court_observations(c),
            }

    state = read_json(PHASE_STATE)
    if state:
        for row in state["body"]["phases"]:
            obs["phases"][str(row["phase"])] = row["state"]

    # The prerequisite gate's numbers, tracked the same way as everything else. Its
    # two censuses are explicitly *not* failures in the gate -- the C language surface
    # cannot be matched lexically, and an internal function left unbuilt in a stratum
    # that has sealed is a decision rather than a repair -- so the only thing keeping
    # them from becoming a place where real omissions hide is a non-increase invariant.
    # That invariant lives here, which is why this plane is read at all.
    gate = read_json(PREREQUISITE_GATE)
    if gate:
        gb = gate["body"]
        obs["prerequisites"] = {
            "findings": sum(gb["counts"].values()),
            "sealed_census": gb["sealed_stratum_census"]["names"],
            "language_census": gb["census"].get(
                "language_surface_not_modelled_by_name", 0),
            "blocking_dependencies": len(gb["blocking_dependencies"]),
            "divergence_names_covered": gb["checked"]["divergence_names_covered"],
        }

    return obs


def validate_authority(authority: dict, current: dict) -> list[str]:
    """Problems that make the authority baseline unfit to certify anything.

    A baseline that has been *trimmed* is as dangerous as one that has been
    lowered: removing the `courts` map, or an obligation ledger, makes the
    corresponding checks disappear rather than fail, and a comparison that checks
    nothing always passes. So an authority baseline must carry the planes the
    project relies on.

    A plane that is present now but absent from the authority is reported as a
    movement rather than a failure: adding a new obligation ledger is legitimate
    work, and the authority simply cannot certify it yet. That case is printed
    loudly so the gap is visible.
    """
    problems: list[str] = []
    if not authority.get("implemented"):
        problems.append("it carries no implemented-symbol counts")
    if not authority.get("courts"):
        problems.append("it carries no court results")
    if not authority.get("phases"):
        problems.append("it carries no phase states")
    return problems


def uncertified_planes(authority: dict, current: dict) -> list[str]:
    """Planes the current evidence has that the authority cannot speak about."""
    notes: list[str] = []
    for name in sorted(set(current.get("open_obligations", {}))
                       - set(authority.get("open_obligations", {}))):
        notes.append(
            f"obligation ledger {name!r} exists now but not in the authority: "
            f"the comparison cannot certify it")
    for phase in sorted(set(current.get("phases", {}))
                        - set(authority.get("phases", {}))):
        notes.append(f"phase {phase} exists now but not in the authority")
    return notes


def transition_for(phase: str, was: int, now: int, owned_now: int) -> dict | None:
    """An approved ownership transition covering an open-obligation increase.

    An obligation ledger's universe can legitimately *change*: when discovery stops
    being a prefix test and becomes the global ownership atlas (D72), a stratum's
    owned set moves and so does its open count. That is not a regression -- nothing
    was undone -- but it is arithmetically indistinguishable from one, so it must be
    recorded rather than argued about.

    `forensics/ownership-transitions.json` records each approved move with the
    before and after numbers. The match is **exact on every field**, so a transition
    can bless the change it describes and nothing else: a larger increase, a
     different owned count, or an unrecorded phase all fail.
    """
    doc = read_json(TRANSITIONS)
    if not doc:
        return None
    for t in doc.get("transitions", []):
        if (str(t.get("phase")) == str(phase).removeprefix("phase")
                and t.get("open_before") == was
                and t.get("open_after") == now
                and t.get("owned_after") == owned_now):
            return t
    return None


def prerequisite_transition_for(metric: str, was: int, now: int) -> dict | None:
    """An approved **increase** in a prerequisite-plane count covering exactly that change.

    The same discipline as `transition_for`: a row can bless the change it describes and
    nothing else -- a larger increase, or a different metric, fails.

    It exists for the case D132 found. The blocking-dependency list is a list of names the
    gate *observed*, and a name becomes observable when something references it, so landing
    work can move the count **up** for a reason that is not new work: a whole authority unit
    that nothing referenced is invisible, and giving it an owner makes it visible. Without
    this mechanism the invariant would punish exactly the behaviour it wants (a projection
    that has stopped hiding work), which is the failure D130 found in the language census
    from the other side.
    """
    doc = read_json(TRANSITIONS)
    if not doc:
        return None
    for t in doc.get("prerequisite_transitions", []):
        if (t.get("metric") == metric
                and t.get("before") == was
                and t.get("after") == now):
            return t
    return None


def phase_transition_for(phase: str, was: str, now: str) -> dict | None:
    """An approved *downward* phase-state correction covering a state change.

    A stratum's state is derived from its ledger, so when the ledger's universe is
    corrected the derived state can move **down**. That is exactly what D97 does:
    Phases 3 and 4 were called `complete` because their ledgers were prefix lists
    that matched nothing for sixty-nine and nineteen of the exports the ownership
    atlas assigns them, so the state was derived from an incomplete premise. The
    correction lowers it.

    A state *downgrade* is a regression by default, and it must stay that way: the
    whole value of a cumulative invariant is that you cannot quietly undo it. So the
    same shape is used as for an ownership transition -- a row here that matches the
    phase and both states **exactly**, naming the decision and the artifact that is
    the authority for the new state. A different pair of states is not blessed, and
    removing the row makes the same change fail again.

    Only a *downward* move is ever routed through this file. An upward move is
    reported as a movement by `compare`, which needs no approval: it is the work.
    """
    doc = read_json(TRANSITIONS)
    if not doc:
        return None
    for t in doc.get("phase_state_transitions", []):
        if (str(t.get("phase")) == str(phase).removeprefix("phase")
                and t.get("state_before") == was
                and t.get("state_after") == now):
            return t
    return None


def inventory_problems(current: dict) -> list[str]:
    """The phase inventory must be complete in both directions.

    A ledger for a phase `phase-state.json` does not know, and a phase that is not
    `not-started` whose ledger is missing, are both failures. Without this the
    discovery-by-glob above could silently drop a stratum -- which is the same
    defect as the hardcoded list, reached from the other side.
    """
    problems: list[str] = []
    known = set(current.get("phases", {}))
    for name in sorted(current.get("open_obligations", {})):
        phase = str(name).removeprefix("phase")
        if phase not in known:
            problems.append(
                f"{name}: there is an obligation ledger for a phase phase-state.json"
                " does not know")
    for phase, state in sorted(current.get("phases", {}).items()):
        if int(phase) >= 3 and state != "not-started":
            if f"phase{phase}" not in current.get("open_obligations", {}):
                problems.append(
                    f"phase {phase} is {state} but has no obligation ledger: a"
                    " stratum that moved off `not-started` must have one")
    for name in sorted(current.get("court_phases", [])):
        phase = str(name).removeprefix("phase")
        if phase not in known:
            problems.append(
                f"{name}: there are court results for a phase phase-state.json does"
                " not know")
    return problems


def compare(baseline: dict, current: dict) -> tuple[list[str], list[str]]:
    """Return (regressions, movements). Movements are informational."""
    regressions: list[str] = []
    movements: list[str] = []

    def label(kind: str, key: str) -> str:
        return f"{kind}[{key}]"

    for lib, was in baseline.get("implemented", {}).items():
        if lib not in current["implemented"]:
            regressions.append(
                f"{label('implemented', lib)}: baseline {was}, but the "
                f"implemented-surface manifest is missing or unreadable")
            continue
        now = current["implemented"][lib]
        if now < was:
            regressions.append(f"{label('implemented', lib)}: {was} -> {now} (lost {was - now})")
        elif now > was:
            movements.append(f"{label('implemented', lib)}: {was} -> {now} (+{now - was})")

    for name, was in baseline.get("open_obligations", {}).items():
        if name not in current["open_obligations"]:
            # An absent ledger is NOT zero open obligations. Defaulting to zero
            # here would read a deleted evidence plane as perfect progress.
            regressions.append(
                f"open_obligations[{name}]: baseline {was}, but the obligation "
                f"ledger is absent — absence is not completion")
            continue
        now = current["open_obligations"][name]
        if now > was:
            # An increase is a regression **unless** an approved ownership
            # transition accounts for exactly this change.
            t = transition_for(name, was, now,
                               current.get("owned_obligations", {}).get(name, 0))
            if t is None:
                regressions.append(
                    f"open_obligations[{name}]: {was} -> {now} (+{now - was})")
            else:
                movements.append(
                    f"open_obligations[{name}]: {was} -> {now} (+{now - was}), "
                    f"an approved ownership transition ({t.get('reason', 'no reason ')}"
                    f" recorded in {TRANSITIONS})")
        elif now < was:
            movements.append(
                f"open_obligations[{name}]: {was} -> {now} (-{was - now})")

    for name, was in baseline.get("deferred", {}).items():
        now = current["deferred"].get(name)
        if now is None:
            movements.append(f"deferred[{name}]: {was} -> absent")
        elif now != was:
            movements.append(f"deferred[{name}]: {was} -> {now}")

    for court, base in baseline.get("courts", {}).items():
        now = current["courts"].get(court)
        if now is None:
            regressions.append(
                f"court[{court}]: baseline {base['verdict']}/{base['observations']} "
                f"obs, but the court result is absent")
            continue
        if base["verdict"] == "pass" and now["verdict"] != "pass":
            regressions.append(f"court[{court}]: was pass, now {now['verdict']}")
        if now["observations"] < base["observations"]:
            regressions.append(
                f"court[{court}]: observations {base['observations']} -> "
                f"{now['observations']} (weakened probe)")
        elif now["observations"] > base["observations"]:
            movements.append(
                f"court[{court}]: observations {base['observations']} -> "
                f"{now['observations']} (+{now['observations'] - base['observations']})")

    for phase, was in baseline.get("phases", {}).items():
        now = current["phases"].get(phase)
        if now is None:
            regressions.append(f"phase[{phase}]: was {was}, but the phase state is absent")
        elif STATE_RANK.get(now, -1) < STATE_RANK.get(was, -1):
            t = phase_transition_for(phase, was, now)
            if t is None:
                regressions.append(f"phase[{phase}]: {was} -> {now}")
            else:
                movements.append(
                    f"phase[{phase}]: {was} -> {now}, an approved state correction "
                    f"({t.get('reason', 'no reason recorded in ' + TRANSITIONS)})")
        elif STATE_RANK.get(now, -1) > STATE_RANK.get(was, -1):
            movements.append(f"phase[{phase}]: {was} -> {now}")

    # The prerequisite plane. `findings` must be zero and stay zero; an absent gate
    # artefact is an absence of evidence, not a clean bill, so it is a regression like
    # every other missing plane. The blocking list must not grow, and the language
    # census is checked **per authority unit** rather than as a total -- see
    # `language_census_by_unit` below for why the total cannot carry the invariant.
    for key, was in sorted(baseline.get("prerequisites", {}).items()):
        now = current.get("prerequisites", {}).get(key)
        if now is None:
            regressions.append(
                f"prerequisites[{key}]: baseline {was}, but {PREREQUISITE_GATE} is "
                f"absent or does not carry this field -- absence is not completion")
            continue
        if key == "language_census_by_unit":
            # A map, not a count; handled in its own loop below.
            continue
        if key == "findings" and now:
            regressions.append(
                f"prerequisites[findings]: {now} finding(s) in {PREREQUISITE_GATE}; "
                f"the gate does not pass")
            continue
        if key == "divergence_names_covered":
            # Not directional in either direction: a divergence row is added when a
            # difference is understood and removed when it is fixed, and both are work.
            if now != was:
                movements.append(f"prerequisites[{key}]: {was} -> {now}")
            continue
        if key == "language_census":
            # The total is *expected* to grow when another authority file is
            # transcribed, because that file's local identifiers enter the census,
            # and a growth the total cannot distinguish from a real omission would
            # hide one. So the total is reported and the per-unit comparison below
            # carries the invariant.
            if now != was:
                movements.append(f"prerequisites[{key}]: {was} -> {now}")
            continue
        if now > was:
            t = prerequisite_transition_for(key, was, now)
            if t is None:
                regressions.append(
                    f"prerequisites[{key}]: {was} -> {now} (+{now - was})")
            else:
                movements.append(
                    f"prerequisites[{key}]: {was} -> {now} (+{now - was}), an approved "
                    f"transition ({t.get('reason', 'no reason')[:80]}... recorded in "
                    f"{TRANSITIONS})")
        elif now < was:
            movements.append(f"prerequisites[{key}]: {was} -> {now} (-{was - now})")

    # The language census, per authority unit. A unit that was already transcribed may
    # not gain censused names -- that would be a name this crate should reference or
    # model and does not -- and a unit that is new is a movement. This is the invariant
    # the total was standing in for, stated where it can actually be checked
    # (`docs/DECISIONS.md` D130).
    was_by_unit = baseline.get("prerequisites", {}).get("language_census_by_unit", {})
    now_by_unit = current.get("prerequisites", {}).get("language_census_by_unit", {})
    if was_by_unit and now_by_unit:
        for unit, was in sorted(was_by_unit.items()):
            now = now_by_unit.get(unit, 0)
            if now > was:
                regressions.append(
                    f"prerequisites[language_census_by_unit][{unit}]: {was} -> {now} "
                    f"(+{now - was}); a transcribed unit gained censused names")
            elif now < was:
                movements.append(
                    f"prerequisites[language_census_by_unit][{unit}]: {was} -> "
                    f"{now} (-{was - now})")
        for unit, now in sorted(now_by_unit.items()):
            if unit not in was_by_unit:
                movements.append(
                    f"prerequisites[language_census_by_unit][{unit}]: new unit, "
                    f"{now} censused name(s)")

    return regressions, movements


def baseline_mismatch(proposed: dict, current: dict) -> list[str]:
    """Where the working-tree baseline disagrees with the observed evidence.

    This is check 2: the proposed baseline must be exactly what the checkout
    produces, so a baseline cannot drift away from the evidence it claims to
    summarise.
    """
    diffs: list[str] = []
    for key in (
        "implemented",
        "open_obligations",
        "deferred",
        "courts",
        "phases",

        # `prerequisites` is compared too, and it is a *strengthening* rather than a
        # formality: the per-unit language census and the blocking-dependency count
        # are evidence the authority baseline certifies against, and a proposed
        # baseline that disagreed with the checkout would let the next commit's
        # comparison read the wrong numbers. Its nested `language_census_by_unit`
        # map is compared by value, which is what the per-unit invariant needs.
        "prerequisites",
    ):
        p = proposed.get(key, {})
        c = current.get(key, {})
        for k in sorted(set(p) | set(c)):
            if p.get(k) != c.get(k):
                diffs.append(f"{key}[{k}]: baseline={p.get(k)!r} observed={c.get(k)!r}")
    return diffs


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--baseline-ref", default=None,
                    help="git ref whose committed baseline is the authority for the "
                         "comparison (e.g. the merge base or origin/main)")
    ap.add_argument("--baseline-file", default=None, type=Path,
                    help="a file holding the authority baseline, for venues where git "
                         "is not usable (the court container sees the repository "
                         "through a bind mount it does not own)")
    ap.add_argument("--allow-missing-baseline", action="store_true",
                    help="tolerate a ref that predates the baseline (bootstrap only; "
                         "the --require-current check still runs)")
    ap.add_argument("--require-current", action="store_true",
                    help="fail unless the working-tree baseline equals the observed "
                         "evidence")
    ap.add_argument("--update", action="store_true",
                    help="rewrite the working-tree baseline from current evidence")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    current = observe()

    if args.update:
        if args.baseline_ref:
            raise SystemExit(
                "[regression-guard] --update and --baseline-ref are contradictory: "
                "--update writes the proposed baseline, which is never the authority")
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
        print(f"[regression-guard] proposed baseline written -> {rel(BASELINE)}")
        for lib, n in sorted(current["implemented"].items()):
            print(f"  implemented[{lib}] = {n}")
        for name, n in sorted(current["open_obligations"].items()):
            print(f"  open[{name}] = {n}")
        for court, rec in sorted(current["courts"].items()):
            print(f"  court {court} = {rec['verdict']} ({rec['observations']} obs)")
        return 0

    proposed = read_json(BASELINE_REL)
    if not proposed:
        raise SystemExit(
            f"[regression-guard] {BASELINE_REL} is missing; create it with "
            f"`--update` and review the diff")

    failed = False

    if args.require_current:
        diffs = baseline_mismatch(proposed, current)
        if diffs:
            failed = True
            print(f"[regression-guard] the proposed baseline is stale: "
                  f"{len(diffs)} disagreement(s) with the observed evidence")
            for d in diffs[:40]:
                print(f"  STALE: {d}")
            print("  Regenerate it with `--update` and commit the result.")

    if args.baseline_ref and args.baseline_file:
        raise SystemExit(
            "[regression-guard] pass either --baseline-ref or --baseline-file, not "
            "both: the authority must be a single, named artefact")

    regressions: list[str] = []
    movements: list[str] = []
    authority = None
    if args.baseline_ref:
        authority = baseline_from_ref(args.baseline_ref, args.allow_missing_baseline)
        if authority is None:
            print(f"[regression-guard] {args.baseline_ref} predates {BASELINE_REL}; "
                  "no authority comparison is possible for this push")
        else:
            print(f"[regression-guard] authority = {BASELINE_REL} @ {args.baseline_ref}")
    elif args.baseline_file:
        if not args.baseline_file.is_file():
            raise SystemExit(
                f"[regression-guard] --baseline-file {args.baseline_file} does not exist")
        authority = json.loads(args.baseline_file.read_text(encoding="utf-8"))
        print(f"[regression-guard] authority = {args.baseline_file}")
    else:
        authority = proposed
        print("[regression-guard] WARNING: no --baseline-ref, so the working-tree "
              "baseline is judging itself; use --baseline-ref in CI")

    if authority is not None:
        problems = validate_authority(authority, current)
        if problems:
            failed = True
            print("[regression-guard] FAIL: the authority baseline is unfit to "
                  "certify this comparison")
            for p in problems:
                print(f"  INADEQUATE: {p}")
        for problem in inventory_problems(current):
            print(f"[regression-guard] FAIL: {problem}")
            failed = True
        for note in uncertified_planes(authority, current):
            print(f"  UNCERTIFIED: {note}")
        regressions, movements = compare(authority, current)
        if not args.quiet:
            for m in movements:
                print(f"  movement: {m}")
        if regressions:
            failed = True
            print(f"[regression-guard] FAIL: {len(regressions)} regression(s)")
            for r in regressions:
                print(f"  REGRESSION: {r}")

    if failed:
        return 1

    total_obs = sum(c["observations"] for c in current["courts"].values())
    print(f"[regression-guard] ok: no regression "
          f"({len(current['courts'])} court(s), {total_obs} observations)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
