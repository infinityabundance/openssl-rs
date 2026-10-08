#!/usr/bin/env python3
"""openssl-rs — Phase-24.17 the biggest-mover remediation: the before/after record of the repairs.

Why this exists
---------------
24.16 (`forensics/tools/downstream_blockers.py`) partitioned the 1,000 counted families by their
deepest blocker and ranked the classes by mover potential, but it repaired nothing: its recipe queue
is a labelled **heuristic**, not a measurement of buildability. 24.17 acts on the largest movers —
it fixes the recipe-backed blockers it can fix inside the fixed venue, adds the missing runtime
fixtures, and admits a bounded, deterministic batch of recipe-less families whose pinned release
tarball ships a build entry point the venue can execute — and this tool is the **record** of that
work: for every blocker class 24.16 named it reads the 24.16 figures (`before`, preserved
immutably), re-derives the re-measured figures (`after`) from the committed planes, computes the
`movement`, and names the exact recipe/flag/fixture each `action` applied.

The admission criterion is empirical, not a claim
-------------------------------------------------
A recipe is admissible when its pinned release tarball ships a build entry point the venue can
execute (a generated `configure`, or a plain `Makefile`) and needs no tool the venue lacks. This
tool records the batch that was **actually built** (and the candidate families that were probed and
rejected, with the reason the venue could not build them), so the criterion is a measurement rather
than a heuristic. The admission batch is bounded and deterministic, not an attempt at all 988.

What is measured, and what is not
---------------------------------
`before` is the 24.16 blocker partition, read once and then preserved immutably in this artefact (the
same discipline 24.11 applies to the holdout `first_run`): it is a measurement of the pre-remediation
planes, which the re-measurement supersedes, so a re-run carries it forward rather than re-deriving
it from planes that no longer exist. `after` is re-derived from the committed planes on every run.
Nothing here is typed: every count is read from a committed partition or a committed atlas, and the
`movement` is a subtraction of two measured figures. A passing record is an **instrument**: it says
what was repaired and what the planes then measured, not that the population now passes.

It executes nothing: it reads committed Phase-24 planes and this artefact's own recorded `before`,
and writes one derived record, so it is declared `metadata_only` in
`forensics/downstream/container.json` and `evidence_determinism.py` regenerates it host-side.

Outputs
-------
  forensics/downstream/blocker-remediation.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    write_json,
)

# The Docker-only execution guard. Called first in `main`; this tool executes nothing, but it is a
# Phase-24 entry point and a host invocation is refused.
import phase24_guard  # noqa: E402

# The 24.16 analysis and its inputs: the partition is re-derived through the same code path 24.16
# produced it with, so the two can never drift.
import downstream_blockers as blockers  # noqa: E402

# The 24.6 build/link atlas: its recipe catalogue names the admitted recipes this record attributes
# the admission batch to, and its rows carry each newly-admitted family's measured build/link level.
import downstream_build_link as bl  # noqa: E402

from downstream_schemas import BLOCKER_CLASSES  # noqa: E402

OUT = REPO_ROOT / "forensics" / "downstream" / "blocker-remediation.json"
# The preserved pre-remediation baseline: the 24.16 blocker partition, captured once (before the
# planes are re-measured) and committed, so the record's `before` is a measured input rather than a
# figure the record carries against planes that no longer exist.
BASELINE = REPO_ROOT / "forensics" / "downstream" / "blocker-remediation-baseline.json"
GENERATOR = "forensics/tools/downstream_remediation.py"

SHARED_BLOCKERS = blockers.OUT
BUILD_LINK_ATLAS = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"
RUNTIME_ATLAS = REPO_ROOT / "forensics" / "downstream" / "runtime-functional-atlas.json"
P1000_RUN = REPO_ROOT / "forensics" / "downstream" / "p1000-run.json"

# The 24.16 admitted recipe families (the eleven 24.3 census recipes plus the Phase-17 nginx slice).
# Families in the present catalogue that are absent here are the 24.17 admission batch.
BASELINE_RECIPE_FAMILIES: frozenset[str] = frozenset({
    "libssh", "curl", "haproxy", "monit", "openssh", "pure-ftpd", "redis",
    "kmod", "lighttpd", "openvpn", "isync", "nginx",
})

# 24.17's own batch, so the record's `new_recipes` are the families 24.17 admitted and not a later
# subphase's (24.18's campaign adds its own; scoping keeps 24.17's admission-batch consistency check
# honest without rewriting its historical probe).
BATCH_24_17: frozenset[str] = bl.ADMISSION_BATCH_24_17

# The remediation actions, keyed by id. `blocker_class` is the 24.16 class the action targets;
# `families` are the counted families it names; `fix_kind` is the mechanism; `still_blocked` marks an
# action where the venue cannot host the fix (and `missing_tool` names what is absent); `change` is
# the exact recipe/flag/fixture the action applied. Every field is a claim the record re-checks
# against the measured planes: a still-blocked action must show no movement, a resolving action must.
ACTIONS: tuple[dict, ...] = (
    {
        "action_id": "recipe-fix:kmod",
        "blocker_class": "recipe-build-dependency-missing",
        "families": ["kmod"], "fix_kind": "recipe-configure-flag", "still_blocked": False,
        "change": ("kmod 33: add `--disable-manpages` to the recipe configure, so the absent scdoc "
                   "man-page builder no longer stops configure"),
        "evidence": "forensics/tools/downstream_build_link.py:_RECIPE_OVERRIDES",
    },
    {
        "action_id": "recipe-fix:openvpn",
        "blocker_class": "recipe-build-dependency-missing",
        "families": ["openvpn"], "fix_kind": "recipe-repin", "still_blocked": False,
        "change": ("openvpn: pin the 2.5 line (2.5.10) and configure "
                   "`--with-crypto-library=openssl --disable-lzo --disable-lz4 "
                   "--disable-plugin-auth-pam`, because 2.6.12 requires libnl-genl-3.0 (DCO) and then "
                   "libcap-ng on Linux, neither admitted here"),
        "evidence": "forensics/tools/downstream_build_link.py:_RECIPE_OVERRIDES",
    },
    {
        "action_id": "recipe-fix:isync",
        "blocker_class": "no-fixture",
        "families": ["isync"], "fix_kind": "recipe-link-flag", "still_blocked": False,
        "change": ("isync: add `-Wl,-rpath-link,{prefix}/lib` to the link environment so libssl's "
                   "transitive libcrypto dependency resolves against the authority prefix"),
        "evidence": "forensics/tools/downstream_build_link.py:_RECIPE_OVERRIDES + _measure_subject",
    },
    {
        "action_id": "still-blocked:libssh",
        "blocker_class": "recipe-build-system-unsupported",
        "families": ["libssh"], "fix_kind": "recipe-build-system", "still_blocked": True,
        "missing_tool": "cmake",
        "change": ("libssh 0.10.6 ships only CMakeLists.txt; the venue admits no cmake, so the "
                   "recipe cannot be repaired here and is recorded still-blocked rather than faked"),
        "evidence": "tarball inspection: libssh-0.10.6.tar.xz root has CMakeLists.txt and no configure",
    },
    {
        "action_id": "still-blocked:lighttpd",
        "blocker_class": "recipe-build-system-unsupported",
        "families": ["lighttpd"], "fix_kind": "recipe-build-system", "still_blocked": True,
        "missing_tool": "autoconf/automake (or cmake/meson)",
        "change": ("lighttpd 1.4.76 ships no generated ./configure (configure.ac, CMakeLists.txt, "
                   "meson.build and SConstruct only); the venue admits no autotools, cmake or meson, "
                   "so the recipe cannot be repaired here and is recorded still-blocked"),
        "evidence": "tarball inspection: lighttpd-1.4.76.tar.gz root has configure.ac, no configure",
    },
    {
        "action_id": "fixture:pure-ftpd",
        "blocker_class": "no-fixture",
        "families": ["pure-ftpd"], "fix_kind": "fixture-addition", "still_blocked": False,
        "change": ("pure-ftpd: add a deterministic local authenticated FTPS workload -- a system "
                   "account the venue creates in its disposable container, driven over explicit TLS "
                   "by the authority's own `openssl s_client -starttls ftp` (USER/PASS/PWD) on "
                   "loopback"),
        "evidence": "forensics/tools/downstream_runtime.py:_wl_pureftpd",
    },
    {
        "action_id": "fixture:isync",
        "blocker_class": "no-fixture",
        "families": ["isync"], "fix_kind": "fixture-addition", "still_blocked": False,
        "change": ("isync: add a deterministic local IMAP4rev1-over-TLS peer (served by the courtroom "
                   "over the authority-generated certificate on loopback) that the subject mbsync "
                   "syncs a message from into a Maildir"),
        "evidence": "forensics/tools/downstream_runtime.py:_wl_isync + _imaps_server",
    },
    {
        "action_id": "admission-batch:24.17",
        "blocker_class": "no-admitted-recipe",
        "families": [], "fix_kind": "recipe-admission", "still_blocked": False,
        "change": ("admit a bounded, deterministic batch of recipe-less counted families whose pinned "
                   "release tarball ships a build entry point the venue can execute and needs no "
                   "missing tool (see `new_recipes`)"),
        "evidence": "forensics/tools/downstream_build_link.py:_EXTRA_SPECS",
    },
)

# The candidates probed for the admission batch and the venue's observed verdict. `admitted` marks
# the ones whose recipe was authored; the others record exactly why the venue could not build them,
# so the admission criterion is a measurement rather than a heuristic.
ADMISSION_PROBE: tuple[dict, ...] = (
    {"family": "socat", "admitted": True, "stage": "linked"},
    {"family": "ldns", "admitted": True, "stage": "linked"},
    {"family": "stunnel", "admitted": True, "stage": "linked"},
    {"family": "links", "admitted": True, "stage": "linked"},
    {"family": "libevent", "admitted": True, "stage": "linked"},
    {"family": "dovecot", "admitted": True, "stage": "linked"},
    {"family": "cyrus-sasl", "admitted": True, "stage": "linked"},
    {"family": "fossil", "admitted": True, "stage": "linked"},
    {"family": "mutt", "admitted": False, "stage": "configure",
     "detail": "no curses/ncurses library in the venue"},
    {"family": "nmap", "admitted": False, "stage": "make",
     "detail": "needs aclocal/automake for its bundled pcre"},
    {"family": "openldap", "admitted": False, "stage": "make",
     "detail": "needs groff's soelim to build manpages (no --disable-manpages option)"},
    {"family": "net-snmp", "admitted": False, "stage": "configure",
     "detail": "could not find the subject OpenSSL from --with-openssl"},
    {"family": "w3m", "admitted": False, "stage": "configure", "detail": "needs libgc (gc.h)"},
    {"family": "mini-httpd", "admitted": False, "stage": "make", "detail": "source does not compile"},
    {"family": "vsftpd", "admitted": False, "stage": "link",
     "detail": "its Makefile does not link the subject OpenSSL"},
    {"family": "libesmtp", "admitted": False, "stage": "fetch", "detail": "release archive URL"},
    {"family": "sofia-sip", "admitted": False, "stage": "fetch", "detail": "release archive URL"},
    {"family": "sslscan", "admitted": False, "stage": "fetch", "detail": "release archive URL"},
    {"family": "ike-scan", "admitted": False, "stage": "fetch",
     "detail": "no generated configure in the release archive"},
    {"family": "proxytunnel", "admitted": False, "stage": "fetch", "detail": "release archive URL"},
    {"family": "bruteforce-salted-openssl", "admitted": False, "stage": "fetch",
     "detail": "release archive URL"},
    {"family": "librelp", "admitted": False, "stage": "fetch", "detail": "release archive URL"},
)

NON_CLAIMS: list[str] = [
    "a bounded, deterministic admission batch is not an attempt at all 988 recipe-less families: it "
    "is the subset this subphase built and measured, and it makes no claim about the rest",
    "a build/link is not a functional proof: a newly-admitted family that reached L4-linked has "
    "compiled and linked, not behaved, and one with no admitted local workload is `no-fixture`",
    "a still-blocked class is a measurement of the fixed venue, not of the project: libssh needs "
    "cmake and lighttpd needs autotools/cmake/meson, none of which this venue admits",
    "the before figures are a preserved measurement of the pre-remediation planes, recorded once and "
    "carried forward like 24.11's holdout first_run, not re-derived from planes that no longer exist",
    "a deterministic local fixture is one exercise of the program's OpenSSL path on loopback, not a "
    "statement that every consumer works or that the library is safe",
]


def _load_json(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("body", doc)


def _class_counts(partition: dict) -> dict:
    counts = {c: 0 for c in BLOCKER_CLASSES}
    for cls in partition.values():
        counts[cls] = counts.get(cls, 0) + 1
    return counts


def _summarise(analysis: dict) -> dict:
    """The comparable figures of one blocker analysis: the partition, its counts and the funnel."""
    partition = analysis.get("partition") or {}
    counts = analysis.get("counts") or {}
    return {
        "partition": partition,
        "partition_hash": analysis.get("partition_hash"),
        "class_counts": _class_counts(partition),
        "resolved_families": counts.get("resolved_families"),
        "recipe_backed_families": counts.get("recipe_backed_families"),
        "recipe_less_families": counts.get("recipe_less_families"),
        "measurable_families": counts.get("measurable_families"),
        "funnel": analysis.get("funnel"),
    }


def _missing_inputs() -> list[str]:
    required = [SHARED_BLOCKERS, BUILD_LINK_ATLAS, RUNTIME_ATLAS, P1000_RUN, BASELINE,
                blockers.FAMILY_FREEZE, blockers.FAMILIES]
    return [rel(p) for p in required if not p.is_file()]


def _baseline() -> dict | None:
    """The preserved pre-remediation baseline body, or `None` when it is absent."""
    if not BASELINE.is_file():
        return None
    try:
        return _load_json(BASELINE)
    except (json.JSONDecodeError, OSError):
        return None


def _new_recipes(build_link_body: dict) -> list[dict]:
    """The recipes 24.17 admitted (its own batch), with their measured level."""
    rows = {(str(r.get("canonical_name")), str(r.get("subject"))): r
            for r in build_link_body.get("runs") or []}
    out: list[dict] = []
    for r in bl.RECIPES:
        fam = r["family"]
        if fam in BASELINE_RECIPE_FAMILIES:
            continue
        if fam not in BATCH_24_17:
            # a later subphase's admission (24.18's campaign): not this record's `new_recipes`
            continue
        out.append({
            "family": fam,
            "recipe_id": r["recipe_id"],
            "version": r["version"],
            "url": r["url"],
            "sha256": r.get("sha256"),
            "build_system": r["build_system"],
            "artifact": r["artifact"],
            "authority_level": (rows.get((fam, "authority")) or {}).get("level"),
            "candidate_level": (rows.get((fam, "candidate")) or {}).get("level"),
            "candidate_linkage_proven": (rows.get((fam, "candidate")) or {}).get("linkage_proven"),
            "candidate_reason": (rows.get((fam, "candidate")) or {}).get("reason"),
        })
    out.sort(key=lambda d: str(d["family"]))
    return out


def _verdict_by_family(p1000_body: dict) -> dict:
    return {str(v.get("family_id")): v for v in p1000_body.get("verdicts") or []}


def derive_remediation(inputs: dict) -> dict:
    """The whole record: before, after, movement, actions, the batch and the new recipes."""
    analysis = blockers.derive_blockers(inputs)
    after = _summarise(analysis)
    before = inputs.get("baseline_body")
    if not before:
        before = dict(_summarise(inputs["shared_blockers_body"]),
                      source="24.16 shared-blockers.json (pre-remediation)")
    else:
        before = dict(before)
        before.setdefault("source", "24.16 shared-blockers.json (pre-remediation)")

    movement: dict[str, dict] = {}
    for cls in BLOCKER_CLASSES:
        b = int((before.get("class_counts") or {}).get(cls) or 0)
        a = int((after.get("class_counts") or {}).get(cls) or 0)
        movement[cls] = {"before": b, "after": a, "delta": a - b}

    before_partition = before.get("partition") or {}
    after_partition = after.get("partition") or {}
    family_movement = []
    for fid in sorted(set(before_partition) | set(after_partition)):
        b = before_partition.get(fid)
        a = after_partition.get(fid)
        if b != a:
            family_movement.append({"family_id": fid, "before": b, "after": a})

    new_recipes = _new_recipes(inputs["build_link_body"])
    verdicts = _verdict_by_family(inputs["p1000_body"])
    for rec in new_recipes:
        fam_id = inputs["family_id_by_name"].get(rec["family"])
        v = verdicts.get(str(fam_id)) or {}
        rec["verdict"] = v.get("verdict")
        rec["residual_class"] = None

    actions: list[dict] = []
    for a in ACTIONS:
        action = copy.deepcopy(a)
        fams = list(action.get("families") or [])
        if action["action_id"] == "admission-batch:24.17":
            fams = [r["family"] for r in new_recipes]
            action["families"] = fams
        observed = []
        moved = 0
        for name in fams:
            fid = inputs["family_id_by_name"].get(name)
            b = before_partition.get(str(fid)) if fid is not None else None
            af = after_partition.get(str(fid)) if fid is not None else None
            changed = b != af
            moved += 1 if changed else 0
            observed.append({"family": name, "before": b, "after": af, "moved": changed})
        action["observed"] = observed
        action["families_moved"] = moved
        actions.append(action)

    counts = {
        "actions": len(actions),
        "fix_actions": sum(1 for a in actions if not a.get("still_blocked")
                           and a["action_id"] != "admission-batch:24.17"),
        "still_blocked_actions": sum(1 for a in actions if a.get("still_blocked")),
        "families_moved": len(family_movement),
        "new_recipes": len(new_recipes),
        "new_recipes_linked": sum(1 for r in new_recipes
                                  if bl.RANK.get(str(r.get("candidate_level")), -1)
                                  >= bl.RANK["L4-linked"]),
        "probe_admitted": sum(1 for p in ADMISSION_PROBE if p.get("admitted")),
        "probe_rejected": sum(1 for p in ADMISSION_PROBE if not p.get("admitted")),
    }

    rule = {
        "id": "downstream-blocker-remediation/1",
        "name": "the biggest-mover remediation record",
        "before": (
            "the 24.16 blocker partition of the pre-remediation planes, captured once (before the "
            "re-measurement) and committed as `forensics/downstream/blocker-remediation-baseline.json`; "
            "the planes it measured are superseded by the re-measurement, so it is a preserved "
            "measured input rather than a re-derivation from planes that no longer exist"
        ),
        "after": (
            "the blocker partition re-derived from the committed (re-measured) Phase-24 planes "
            "through 24.16's own code path, so the record cannot drift from the analysis"
        ),
        "movement": (
            "the per-class difference between `after` and `before`, computed as a subtraction of two "
            "measured class counts, plus the per-family class transitions"
        ),
        "actions": (
            "the exact recipe/flag/fixture each repair applied, with the family it targets and the "
            "class it names; a resolving action must show the family moved, and a still-blocked "
            "action must show it did not"
        ),
        "admission_criterion": (
            "a recipe is admissible when its pinned release tarball ships a build entry point the "
            "venue can execute (a generated `configure`, or a plain `Makefile`) and needs no tool the "
            "venue lacks; the batch is bounded and deterministic, and the candidates the venue could "
            "not build are recorded with the reason"
        ),
        "honesty_labels": [
            "a bounded admission batch is not an attempt at all 988 recipe-less families",
            "a build/link is not a functional proof",
            "a still-blocked class is a measurement of the fixed venue, not of the project",
        ],
    }

    return {
        "rule": rule,
        "before": before,
        "after": after,
        "movement": movement,
        "family_movement": family_movement,
        "actions": actions,
        "admission_batch": [dict(p) for p in ADMISSION_PROBE],
        "new_recipes": new_recipes,
        "counts": counts,
        "non_claims": NON_CLAIMS,
    }


# ---------------------------------------------------------------------------------------------------
# findings and the sensitivity control (the court's own checks over the committed record)
# ---------------------------------------------------------------------------------------------------

def remediation_findings(inputs: dict, body: dict) -> list[str]:
    """Every way the recorded remediation fails its own derivation.

    The conditions: the analysis reproduces; the movement is the subtraction of the recorded before
    and the derived after; every action's observed families match the recorded partitions; a
    still-blocked action shows no movement and names its missing tool; a resolving action shows its
    families moved; the new recipes are exactly the catalogue families outside the baseline; and the
    counts are derived rather than typed.
    """
    out: list[str] = []
    derived = derive_remediation(inputs)
    # `derive_remediation` reads the preserved baseline for `before` and re-derives `after` from the
    # committed planes, so a faithful record reproduces every measured field.

    if body.get("after") != derived["after"]:
        out.append("the recorded `after` does not reproduce from the committed planes")
    if body.get("movement") != derived["movement"]:
        out.append("the recorded `movement` does not reproduce from before/after")
    if body.get("family_movement") != derived["family_movement"]:
        out.append("the recorded `family_movement` does not reproduce from the partitions")
    if body.get("new_recipes") != derived["new_recipes"]:
        out.append("the recorded `new_recipes` do not reproduce from the recipe catalogue")
    if body.get("counts") != derived["counts"]:
        out.append("the recorded `counts` do not reproduce from the record")
    if body.get("rule") != derived["rule"]:
        out.append("the recorded rule is not the frozen rule")
    if body.get("non_claims") != NON_CLAIMS:
        out.append("the recorded non_claims are not the remediation non-claims")

    before = body.get("before") or {}
    if not before.get("partition"):
        out.append("the record carries no preserved `before` partition")
    if content_hash({k: (before.get("partition") or {})[k]
                     for k in sorted(before.get("partition") or {})}) != before.get("partition_hash"):
        out.append("the recorded `before` partition_hash does not match its partition")

    # Every action is re-checked against the measured partitions.
    for a in body.get("actions") or []:
        aid = a.get("action_id")
        obs = a.get("observed") or []
        moved = sum(1 for o in obs if o.get("moved"))
        if int(a.get("families_moved") or 0) != moved:
            out.append(f"action {aid}: families_moved {a.get('families_moved')!r} disagrees with its "
                       f"observed transitions ({moved})")
        if a.get("still_blocked"):
            if moved:
                out.append(f"action {aid}: records still-blocked but {moved} of its families moved "
                           f"in the re-measured planes")
            if not a.get("missing_tool"):
                out.append(f"action {aid}: records still-blocked but names no missing tool")
        elif a.get("action_id") != "admission-batch:24.17" and not moved:
            out.append(f"action {aid}: claims a fix but none of its families moved in the "
                       f"re-measured planes (a claimed fix with no measured movement)")

    # The admission batch: every admitted probe family must be a new recipe, and a rejected one must
    # not be.
    new_fams = {r["family"] for r in body.get("new_recipes") or []}
    for p in body.get("admission_batch") or []:
        fam = p.get("family")
        if p.get("admitted") and fam not in new_fams:
            out.append(f"admission batch claims {fam!r} admitted but it is not in the recipe "
                       f"catalogue")
        if not p.get("admitted") and fam in new_fams:
            out.append(f"admission batch marks {fam!r} rejected but it is an admitted recipe")

    # Movement is the arithmetic of the two measured partitions, never typed.
    before_counts = before.get("class_counts") or {}
    after_counts = (body.get("after") or {}).get("class_counts") or {}
    for cls, m in (body.get("movement") or {}).items():
        if m.get("before") != int(before_counts.get(cls) or 0):
            out.append(f"movement[{cls}].before {m.get('before')!r} disagrees with the preserved "
                       f"before count {before_counts.get(cls)!r}")
        if m.get("after") != int(after_counts.get(cls) or 0):
            out.append(f"movement[{cls}].after {m.get('after')!r} disagrees with the measured after "
                       f"count {after_counts.get(cls)!r}")
        if m.get("delta") != int(m.get("after") or 0) - int(m.get("before") or 0):
            out.append(f"movement[{cls}].delta {m.get('delta')!r} is not after - before")
    return out


def remediation_sensitivity_control(inputs: dict, body: dict) -> dict:
    """Prove the record can fail: seed five mutations and require each caught."""
    base = remediation_findings(inputs, body)
    specificity = not base

    def caught(mutated: dict) -> int:
        return len(remediation_findings(inputs, mutated))

    # 1. A claimed fix with no re-measured movement: mark a resolving action's families moved.
    m1 = copy.deepcopy(body)
    for a in m1.get("actions") or []:
        if a.get("action_id") == "admission-batch:24.17":
            a["families_moved"] = 999

    # 2. A still-blocked class marked resolved: clear a still-blocked flag.
    m2 = copy.deepcopy(body)
    for a in m2.get("actions") or []:
        if a.get("still_blocked"):
            a["still_blocked"] = False
            a["missing_tool"] = None

    # 3. A movement figure that disagrees with the planes.
    m3 = copy.deepcopy(body)
    if m3.get("movement"):
        first = sorted(m3["movement"])[0]
        m3["movement"][first]["after"] = int(m3["movement"][first]["after"]) + 7

    # 4. A fabricated new recipe not in the catalogue.
    m4 = copy.deepcopy(body)
    m4.setdefault("new_recipes", []).append({"family": "not-a-real-family", "recipe_id": "x"})

    # 5. A mutated before partition count.
    m5 = copy.deepcopy(body)
    if m5.get("movement"):
        first = sorted(m5["movement"])[0]
        m5["movement"][first]["before"] = int(m5["movement"][first]["before"]) + 5

    return {
        "baseline_findings": len(base),
        "specificity_holds": specificity,
        "caught_claimed_fix_no_movement": caught(m1),
        "caught_still_blocked_marked_resolved": caught(m2),
        "caught_movement_disagrees": caught(m3),
        "caught_fabricated_new_recipe": caught(m4),
        "caught_before_count_mutated": caught(m5),
        "honest": bool(specificity and all(caught(m) for m in (m1, m2, m3, m4, m5))),
    }


# ---------------------------------------------------------------------------------------------------
# the artefact
# ---------------------------------------------------------------------------------------------------

def load_inputs() -> dict:
    """Every committed plane this record reads."""
    bi = blockers.load_inputs()
    build_link_body = _load_json(BUILD_LINK_ATLAS)
    runtime_body = _load_json(RUNTIME_ATLAS)
    p1000_body = _load_json(P1000_RUN)
    names = [str(e.get("canonical_name")) for e in bi["family_freeze"].get("p1000") or []]
    ids = [str(e.get("family_id")) for e in bi["family_freeze"].get("p1000") or []]
    return {
        **bi,
        "shared_blockers_body": _load_json(SHARED_BLOCKERS),
        "baseline_body": _baseline(),
        "build_link_body": build_link_body,
        "runtime_body": runtime_body,
        "p1000_body": p1000_body,
        "family_id_by_name": dict(zip(names, ids)),
    }


def _inputs_list() -> list[InputRef]:
    return [
        InputRef(name="shared-blockers", path=SHARED_BLOCKERS),
        InputRef(name="blocker-remediation-baseline", path=BASELINE),
        InputRef(name="build-link-atlas", path=BUILD_LINK_ATLAS),
        InputRef(name="runtime-functional-atlas", path=RUNTIME_ATLAS),
        InputRef(name="p1000-run", path=P1000_RUN),
        InputRef(name="family-freeze", path=blockers.FAMILY_FREEZE),
        InputRef(name="families", path=blockers.FAMILIES),
        InputRef(name="downstream-remediation",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_remediation.py"),
        InputRef(name="downstream-blockers",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_blockers.py"),
        InputRef(name="downstream-build-link",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_build_link.py"),
        InputRef(name="phase24-guard", path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]


def write_outputs(body: dict) -> None:
    doc = envelope(kind="downstream-blocker-remediation", authority=PRODUCTION_AUTHORITY,
                   inputs=_inputs_list(), body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)


def _baseline_doc(analysis: dict) -> dict:
    """The committed baseline document: the pre-remediation summary with its provenance."""
    body = dict(_summarise(analysis),
                source="24.16 shared-blockers.json (pre-remediation)",
                captured_by="forensics/tools/downstream_remediation.py --capture-baseline",
                captured_note=("the pre-remediation 24.16 blocker partition, captured once before the "
                               "planes were re-measured and committed as the record's `before`"))
    doc = envelope(kind="downstream-blocker-remediation-baseline", authority=PRODUCTION_AUTHORITY,
                   inputs=[InputRef(name="shared-blockers", path=SHARED_BLOCKERS)], body=body,
                   generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    return doc


def cmd_capture_baseline() -> int:
    """Capture the pre-remediation 24.16 partition as the committed `before` input.

    Run once, before the planes are re-measured. It reads the committed 24.16 analysis through 24.16's
    own derivation and freezes the summary; the record then reads it rather than a plane that no
    longer exists.
    """
    missing = [rel(p) for p in (SHARED_BLOCKERS, BUILD_LINK_ATLAS, RUNTIME_ATLAS, P1000_RUN,
                                blockers.FAMILY_FREEZE, blockers.FAMILIES) if not p.is_file()]
    if missing:
        print(f"[downstream-remediation] {', '.join(missing)} is absent; cannot capture a baseline")
        return 1
    inputs = load_inputs()
    analysis = blockers.derive_blockers(inputs)
    if not analysis.get("partition"):
        print("[downstream-remediation] the derived 24.16 partition is empty; cannot capture a "
              "baseline")
        return 1
    write_json(BASELINE, _baseline_doc(analysis))
    print(f"[downstream-remediation] captured the pre-remediation baseline "
          f"({len(analysis['partition'])} families) -> {rel(BASELINE)}")
    return 0


def cmd_measure() -> int:
    missing = _missing_inputs()
    if missing:
        print(f"[downstream-remediation] {', '.join(missing)} is absent; run the earlier "
              f"subphase(s) first")
        return 1
    inputs = load_inputs()
    body = derive_remediation(inputs)
    findings = remediation_findings(inputs, body)
    control = remediation_sensitivity_control(inputs, body)
    if findings or not control["honest"]:
        print("[downstream-remediation] the derived record fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    write_outputs(body)
    c = body["counts"]
    print(f"[downstream-remediation] actions={c['actions']} still_blocked={c['still_blocked_actions']} "
          f"families_moved={c['families_moved']} new_recipes={c['new_recipes']} "
          f"new_recipes_linked={c['new_recipes_linked']}")
    for cls in sorted(body["movement"]):
        m = body["movement"][cls]
        if m["before"] or m["after"]:
            print(f"  {cls:<34} before={m['before']:<5} after={m['after']:<5} delta={m['delta']}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check() -> int:
    if not OUT.is_file():
        print(f"[downstream-remediation] {rel(OUT)} is absent")
        return 1
    missing = _missing_inputs()
    if missing:
        print(f"[downstream-remediation] {', '.join(missing)} is absent")
        return 1
    inputs = load_inputs()
    body = _load_json(OUT)
    findings = remediation_findings(inputs, body)
    control = remediation_sensitivity_control(inputs, body)
    if findings:
        print(f"[downstream-remediation] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    print(f"[downstream-remediation] findings={len(findings)} control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard admits this metadata-only generator and the pure functions behave."""
    failures: list[str] = []

    admission = phase24_guard.evaluate(env={}, dockerenv=False,
                                       manifest=phase24_guard.load_manifest(),
                                       entry_point="downstream_remediation.py")
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("the guard did not admit downstream_remediation.py as metadata-only on a host")

    if set(BLOCKER_CLASSES) != set(blockers.CLASS_RULE):
        failures.append("the blocker vocabulary this record partitions against is not the schema's")

    missing = _missing_inputs()
    if missing:
        failures.append(f"{', '.join(missing)} is absent")
    elif not OUT.is_file():
        failures.append(f"{rel(OUT)} is absent; run --measure")
    else:
        inputs = load_inputs()
        body = _load_json(OUT)
        findings = remediation_findings(inputs, body)
        if findings:
            failures.append(f"the committed record has findings: {findings[:3]}")
        control = remediation_sensitivity_control(inputs, body)
        if not control["honest"]:
            failures.append(f"the sensitivity control is not honest: {control}")
        # The preserved before must be the 24.16 partition (1,000 families), not a re-derivation.
        before = body.get("before") or {}
        if len(before.get("partition") or {}) != 1000:
            failures.append(f"the preserved `before` partition does not cover 1,000 families: "
                            f"{len(before.get('partition') or {})}")

    if failures:
        print("[downstream-remediation] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-remediation] self-test ok: the guard admits this metadata-only generator on a "
          "host, the vocabulary matches the schema, the committed record reproduces with zero "
          "findings, the preserved before partition covers 1,000 families, and every seeded mutation "
          "(a claimed fix with no movement, a still-blocked class marked resolved, a movement figure "
          "disagreeing with the planes, a fabricated new recipe and a mutated before count) is "
          "caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive the record from the committed planes and write it")
    ap.add_argument("--capture-baseline", action="store_true",
                    help="capture the pre-remediation 24.16 partition as the committed before input")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed record without regenerating")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool reads committed evidence and writes one
    # record, so it executes nothing itself, but it is a Phase-24 entry point and a host invocation is
    # refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check()
    if args.capture_baseline:
        return cmd_capture_baseline()
    return cmd_measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
