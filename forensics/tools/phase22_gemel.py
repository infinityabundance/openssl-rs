#!/usr/bin/env python3
"""openssl-rs -- Phase 22.16 the Gemel checkpoint, and the question of regenerating the ledgers.

`docs/PHASE-22-SUBPHASES.md` section 5 gives this subphase its artefact
(`forensics/atlas/phase22/gemel-checkpoint.json`) and its two obligations: section 6 says
22.16 "must regenerate symbol ownership, phase ledgers and parity obligations from the
stronger atlas, and preserve the Phase-11 continuation state", and `docs/RELEASE_GATES.md`
section 2 item 10 requires a Gemel checkpoint to exist and be legible (`docs/DECISIONS.md`
D17: the `.gemel` store is not Git-tracked, so the checkpoint is a projection that travels,
not the store).

What a checkpoint is for
------------------------
A checkpoint is not a seal (22.17 writes that) and it is not a summary. It is the **durable
knowledge state** a later session resumes from: *what was known, from which evidence, and
what was still open*. Two readers matter. A human reader decides whether Phase 22 closed
enough to unblock Phase 11; a machine reader (the next session) needs the content hashes of
the evidence so it can tell whether the state is still the one the checkpoint named.

So the checkpoint binds five things, and every count in it is derived from the artefact it
names rather than typed:

  * **atlas identity** -- the sha256 of every Phase-22 plane artefact, read from disk, plus
    the authority id and the hash of the plan itself. This says *what was known and from
    which evidence*.
  * **the plane ledger state** -- which compatibility planes are implemented and which are
    open (`forensics/phase22-obligations.json`, whose unit is a plane).
  * **the residual census by class** -- 22.12's cross-plane reconciliation, with the
    `UNKNOWN` disposition's sets *named*, not merely counted: they are the open questions.
  * **the Phase-11 continuation state** -- Phase 11's implemented/open counts, 22.14's
    `x509_slice` verdict and the state of `phase22_x509_gate.py`, so Phase 11.2 resumes
    exactly.
  * **what Phase 22 found that the export ledgers cannot carry** -- a *proposal*, because
    the ledgers count exports and Phase 22 found surfaces an export ledger has no unit for
    (POD-only names, the CLI surface, the configuration/environment surface, the installed
    distribution, the dispatch/callback slots that have no source-level caller).

Regeneration is measured, not asserted
--------------------------------------
The plan's section 6 asks 22.16 to regenerate the export ledgers from the stronger atlas.
The honest question is whether that regeneration is a *no-op*: the export universe Phase 22
reads is the one Phase 1 already had, so the ledgers should not move. This tool does not
assert that -- it **runs** the generators (`symbol_ownership.py`, `implemented_surface.py`,
the `phase*_obligations.py` set and `atlas_parity.py`), records the before/after content
hashes and the scalar deltas, and **restores the files**, so the measurement leaves the tree
exactly as it found it. The checkpoint then states plainly whether regenerating would move
counts, and if it would, by how much. A checkpoint that changed obligation counts without
recording the delta would be the worst outcome here.

Determinism
-----------
The checkpoint carries no wall-clock time, PID, hostname or scratch path. The one subtlety
is that `forensics/phase22-obligations.json` names this very checkpoint as its 22.16 plane,
so a naive regeneration measurement would depend on whether the checkpoint already exists.
The measurement therefore hides `gemel-checkpoint.json` while it runs, which makes it a pure
function of the pre-checkpoint tree both on the first run and on any later one.

Output
------
    forensics/atlas/phase22/gemel-checkpoint.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
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
    sha256_bytes,
    sha256_file,
    write_json,
)

GENERATOR = "forensics/tools/phase22_gemel.py"
ARTEFACT_REL = "forensics/atlas/phase22/gemel-checkpoint.json"
OUT = REPO_ROOT / ARTEFACT_REL
COURT = "RT-PHASE22-GEMEL"

PLAN_REL = "docs/PHASE-22-SUBPHASES.md"
P22 = REPO_ROOT / "forensics" / "atlas" / "phase22"
LEDGER_REL = "forensics/phase22-obligations.json"
PHASE11_LEDGER_REL = "forensics/phase11-obligations.json"
UNITS_REL = "forensics/atlas/export-defining-units.json"
X509_BASELINE_REL = "forensics/phase22/x509-closure-slice-baseline.json"
CLI_CAPTURE_REL = "forensics/atlas/openssl-3.6.4-production/cli-commands.json"
PARITY_DIR = "forensics/atlas/openssl-3.6.4-production"

# Phase 11.2's three units, from `docs/PHASE-11-SUBPHASES.md` section 2's row (the gate's
# own constant, repeated here so the checkpoint does not import the gate to name its units).
UNITS_11_2 = (
    "crypto/x509/x509_vfy.c",
    "crypto/x509/x509_vpm.c",
    "crypto/x509/pcy_tree.c",
)

# The keys of the checkpoint's *source* context. `build_checkpoint` copies exactly these
# into the body, derives the rest, and the court feeds them back through `_inputs` to prove
# the committed body is the assembler's own output rather than a stale copy of it.
SOURCE_FIELDS = (
    "plan",
    "authority",
    "planes",
    "plane_ledger",
    "residual_census",
    "phase11_continuation",
    "x509_slice",
    "x509_gate",
    "non_export_obligations",
    "regeneration",
)

WHAT_THIS_IS = (
    "Phase 22.16's durable knowledge state: the content hashes of every Phase-22 plane "
    "artefact and of the plan, the plane ledger, 22.12's residual census with its UNKNOWN "
    "sets named, the Phase-11 continuation state (ledger counts, 22.14's x509_slice verdict "
    "and the x509 gate), a proposal for the non-export surfaces the export ledgers cannot "
    "carry, and the measured result of regenerating the export ledgers. It is a projection "
    "for a later session to resume from, not a seal (22.17 writes that) and not a parity "
    "claim."
)


# ---------------------------------------------------------------------------
# pure assembly -- the checkpoint is a function of its context
# ---------------------------------------------------------------------------

def _count_obligations(obligations: list) -> int:
    return len(obligations)


def _sum_obligation_units(obligations: list) -> int:
    return sum(int(o["count"]) for o in obligations)


def _derive_counts(ctx: dict) -> dict:
    """Every derived count. Pure: a function of the context alone."""
    census = ctx["residual_census"]
    ledger = ctx["plane_ledger"]
    p11 = ctx["phase11_continuation"]
    gate = ctx["x509_gate"]
    reg = ctx["regeneration"]
    unknown_by_class = {k: len(v) for k, v in sorted(census["unknown_sets"].items())}
    outputs = [o for g in reg["generators"] for o in g["outputs"]]
    return {
        "planes_bound": len(ctx["planes"]),
        "plane_ledger_implemented": len(ledger["implemented"]),
        "plane_ledger_open": len(ledger["open"]),
        "census_entities": census["entities"],
        "census_residuals": census["residuals"],
        "census_residual_classes": len(census["by_class"]),
        "unknown_total": sum(unknown_by_class.values()),
        "unknown_by_class": unknown_by_class,
        "unknown_intersecting_roots": len(census["intersecting_root_keys"]),
        "phase11_implemented": p11["counts"]["implemented"],
        "phase11_open": p11["counts"]["open_in_this_stratum"],
        "x509_satisfied": bool(ctx["x509_slice"]["satisfied"]),
        "x509_gate_baseline": len(gate["baseline"]),
        "x509_gate_current": len(gate["current"]),
        "x509_gate_grown": len(sorted(set(gate["current"]) - set(gate["baseline"]))),
        "obligations": _count_obligations(ctx["non_export_obligations"]),
        "obligation_units": _sum_obligation_units(ctx["non_export_obligations"]),
        "regenerated_generators": len(reg["generators"]),
        "regenerated_outputs": len(outputs),
        "regenerated_changed_outputs": sum(1 for o in outputs if o["changed"]),
        "regenerated_count_deltas": sum(len(o["body_scalar_deltas"]) for o in outputs),
    }


def build_checkpoint(ctx: dict) -> dict:
    """Assemble the whole checkpoint body from its context. Pure, no I/O.

    The body carries the context verbatim (that is the evidence) plus the derived `counts`
    and `identity`. The committed artefact is this function's output, so `RT-PHASE22-GEMEL`
    re-derives it from the body's own context and requires equality.
    """
    body = {k: copy.deepcopy(ctx[k]) for k in SOURCE_FIELDS}
    body["counts"] = _derive_counts(ctx)
    body["identity"] = {
        "authority": ctx["authority"],
        "plan": {
            "path": ctx["plan"]["path"],
            "sha256": ctx["plan"]["sha256"],
        },
        "atlas": {p["name"]: p["sha256"] for p in ctx["planes"]},
        "checkpoint_state_hash": content_hash({k: ctx[k] for k in SOURCE_FIELDS}),
    }
    body["what_this_is"] = WHAT_THIS_IS
    body["sort_key"] = (
        "planes by name; plane_ledger lists sorted; residual_census.by_class and "
        "unknown_sets by key; unknown_sets lists sorted; non_export_obligations by surface; "
        "regeneration.generators by script; every list sorted"
    )
    return body


def _inputs(body: dict) -> dict:
    """The source context recovered from a committed body, for the court."""
    return {k: copy.deepcopy(body[k]) for k in SOURCE_FIELDS}


# ---------------------------------------------------------------------------
# collection (I/O)
# ---------------------------------------------------------------------------

def _collect_planes() -> list[dict]:
    """The sha256 of every Phase-22 plane artefact, read from disk (never typed)."""
    planes: list[dict] = []
    for path in sorted(P22.glob("*.json")):
        if path.name == Path(ARTEFACT_REL).name:
            continue  # a checkpoint does not hash itself
        planes.append({"name": path.stem, "path": rel(path), "sha256": sha256_file(path)})
    raw = P22 / "raw" / "compile-commands.jsonl"
    if raw.is_file():
        planes.append({"name": "compile-commands-raw", "path": rel(raw),
                       "sha256": sha256_file(raw)})
    planes.sort(key=lambda p: p["name"])
    return planes


def _collect_plane_ledger() -> dict:
    body = json.loads((REPO_ROOT / LEDGER_REL).read_text(encoding="utf-8"))["body"]
    return {
        "unit": body["unit"],
        "counts": body["counts"],
        "implemented": sorted(body["implemented"]),
        "open": sorted(r["subphase"] for r in body["open"]),
    }


def _collect_census(closure: dict) -> dict:
    body = json.loads((P22 / "reconciliation.json").read_text(encoding="utf-8"))["body"]
    field_map = body["field_map"]
    inv = {short: long for long, short in field_map.items()}
    sets: dict[str, set[str]] = {}
    for row in body["entities"]:
        ent = {inv.get(k, k): v for k, v in row.items()}
        if ent.get("disposition") != "UNKNOWN":
            continue
        cls = ent.get("residual") or "UNKNOWN_UNCLASSIFIED"
        sets.setdefault(cls, set()).add(ent["key"])
    named = {k: sorted(v) for k, v in sets.items()}
    counts = body["counts"]
    return {
        "entities": counts["entities"],
        "residuals": counts["residuals"],
        "by_class": counts["residuals_by_class"],
        "by_disposition": counts["by_disposition"],
        "unknown_sets": dict(sorted(named.items())),
        "intersecting_root_keys": sorted(closure["unknown_intersecting_root_keys"]),
        "root_reachable": counts["root_reachable"],
        "root_families_unpopulated": list(body["root_families_unpopulated"]),
        "unjoined": list(body["unjoined"]),
        "joins": counts["joins"],
    }


def _collect_phase11() -> tuple[dict, list[str]]:
    body = json.loads((REPO_ROOT / PHASE11_LEDGER_REL).read_text(encoding="utf-8"))["body"]
    return (
        {
            "counts": body["counts"],
            "implemented_total": len(body["implemented"]),
            "open_total": len(body["open"]),
        },
        sorted(body["implemented"]),
    )


def _unit_exports() -> list[str]:
    body = json.loads((REPO_ROOT / UNITS_REL).read_text(encoding="utf-8"))["body"]
    out: set[str] = set()
    for unit in UNITS_11_2:
        out.update(body["by_translation_unit"].get(unit, []))
    return sorted(out)


def _collect_x509_gate(implemented_now: list[str]) -> dict:
    baseline = sorted(json.loads(
        (REPO_ROOT / X509_BASELINE_REL).read_text(encoding="utf-8"))["implemented"])
    implemented = set(implemented_now)
    current = sorted(s for s in _unit_exports() if s in implemented)
    return {
        "units": list(UNITS_11_2),
        "baseline": baseline,
        "current": current,
        "grown": sorted(set(current) - set(baseline)),
    }


def _collect_obligations(census: dict) -> list[dict]:
    cli = json.loads((P22 / "cli-surface.json").read_text(encoding="utf-8"))["body"]["counts"]
    cfg = json.loads((P22 / "config-surface.json").read_text(encoding="utf-8"))["body"]["counts"]
    inst = json.loads(
        (P22 / "install-manifest.json").read_text(encoding="utf-8"))["body"]["counts"]
    disp = json.loads((P22 / "dispatch-graph.json").read_text(encoding="utf-8"))["body"]
    pod = json.loads((P22 / "pod-contract.json").read_text(encoding="utf-8"))["body"]
    cap = json.loads(
        (REPO_ROOT / CLI_CAPTURE_REL).read_text(encoding="utf-8"))["body"]

    cap_commands = len(cap["commands"])
    cap_options = sum(int(c.get("option_count", 0)) for c in cap["commands"])

    slot_edges = [e for e in disp["edges"]
                  if e["kind"] in ("DISPATCH_SLOT", "CALLBACK_SLOT")]
    no_caller = [e for e in slot_edges if not e.get("ast_witness")]
    slot_targets = sorted({e["target"] for e in slot_edges})
    no_caller_targets = sorted({e["target"] for e in no_caller})

    pod_names = census["unknown_sets"].get("POD_NAME_NOT_IN_ATLAS", [])
    pod_classes = pod["reconciliation"]["counts_by_class"]
    pod_own = pod_classes.get("POD_NAME_NOT_IN_ATLAS", 0)
    atlas_not_in_pod = pod_classes.get("ATLAS_PUBLIC_NAME_NOT_IN_POD", 0)

    proposals = [
        {
            "surface": "cli-surface",
            "count": int(cli["commands"]),
            "proposed_owner": "16",
            "evidence": ["forensics/atlas/phase22/cli-surface.json", CLI_CAPTURE_REL],
            "reason": (
                "22.9 enumerates the CLI from the authority's own built binary: the digest and "
                "cipher pseudo-commands are part of the surface, so the Phase-1 capture's "
                "standard-command count is not the CLI. The whole namespace needs an owner, and "
                "CLI is a Phase-16 surface."
            ),
            "detail": {
                "commands": int(cli["commands"]),
                "standard": int(cli["standard"]),
                "deprecated": int(cli["deprecated"]),
                "digest_aliases": int(cli["digest_aliases"]),
                "cipher_aliases": int(cli["cipher_aliases"]),
                "structured_options": int(cli["options_structured"]),
                "phase1_capture_commands": cap_commands,
                "phase1_capture_structured_options": cap_options,
            },
        },
        {
            "surface": "configuration-environment-filesystem",
            "count": int(cfg["directives"]) + int(cfg["env_vars"]) + int(cfg["default_paths"]),
            "proposed_owner": "16",
            "evidence": ["forensics/atlas/phase22/config-surface.json"],
            "reason": (
                "22.10 treats an environment variable and a configuration directive as contract "
                "items with a name, a default, a scope and an effect, and a default path as a "
                "filesystem contract. None is an export; all are Phase-16 (config/filesystem) "
                "surfaces."
            ),
            "detail": {
                "directives": int(cfg["directives"]),
                "environment_variables": int(cfg["env_vars"]),
                "default_paths": int(cfg["default_paths"]),
                "config_entry_points": int(cfg["config_entry_points"]),
                "env_named_sites": int(cfg["env_named_sites"]),
            },
        },
        {
            "surface": "pod-documented-unimplemented-api",
            "count": len(pod_names),
            "proposed_owner": "the phase owning each name's declaring header",
            "evidence": ["forensics/atlas/phase22/pod-contract.json",
                         "forensics/atlas/phase22/reconciliation.json"],
            "reason": (
                "The canonical 3.6.4 POD manual documents names the header/API atlas and the "
                "`.num` inventory do not publish. Undocumented is not nonexistent and "
                "documented-but-unimplemented is an obligation an export ledger has no unit for; "
                "each name's owner is the phase whose header would declare it, which is the "
                "ownership rule `forensics/atlas/symbol-ownership.json` applies to exports. "
                "The reconciled census names "
                f"{len(pod_names)} such names; 22.11's own pod-contract reconciliation records "
                f"{pod_own} (its narrower join against the Phase-1 atlas)."
            ),
            "detail": {
                "reconciled_pod_name_not_in_atlas": len(pod_names),
                "pod_contract_own_class_count": int(pod_own),
                "pod_only_residuals": int(census["by_class"].get("POD_ONLY", 0)),
                "atlas_public_name_not_in_pod": int(atlas_not_in_pod),
            },
        },
        {
            "surface": "installed-distribution-required-compatibility",
            "count": int(inst["by_disposition"].get("REQUIRED_COMPATIBILITY", 0)),
            "proposed_owner": "16 or 20 (distribution/packaging)",
            "evidence": ["forensics/atlas/phase22/install-manifest.json"],
            "reason": (
                "22.8 lets the authority's own install define the distribution surface: the "
                "installed cmake config files, pkg-config files, headers, manpages and modules "
                "the constitution had not modelled. A distribution entry is not an export, so "
                "only the packaging phase (16) or the distribution phase (20) can own it."
            ),
            "detail": {
                "required_compatibility": int(
                    inst["by_disposition"].get("REQUIRED_COMPATIBILITY", 0)),
                "entries": int(inst["entries"]),
                "files": int(inst["files"]),
                "symlinks": int(inst["symlinks"]),
                "directories": int(inst["directories"]),
                "by_category": inst["by_category"],
            },
        },
        {
            "surface": "dispatch-callback-slots-without-source-caller",
            "count": len(no_caller),
            "proposed_owner": "the phase owning each slot's containing unit",
            "evidence": ["forensics/atlas/phase22/dispatch-graph.json",
                         "forensics/atlas/phase22/reconciliation.json"],
            "reason": (
                "The architecture of this library is function-pointer tables, so a dispatch or "
                "callback slot has no `caller -> target` edge anywhere in the source; 22.7 "
                "recovers the slot edges themselves, which no export ledger records. Each "
                "slot's owner is the phase owning the unit the table lives in."
            ),
            "detail": {
                "slot_edges": len(slot_edges),
                "slot_targets": len(slot_targets),
                "without_ast_caller_edges": len(no_caller),
                "without_ast_caller_targets": len(no_caller_targets),
                "tables": int(disp["counts"]["tables"]),
                "slots_without_target": int(disp["counts"]["slots_without_target"]),
                "reconciliation_dispatch_unwitnessed_in_binary": int(
                    census["by_class"].get("DISPATCH_UNWITNESSED_IN_BINARY", 0)),
            },
        },
    ]
    proposals.sort(key=lambda o: o["surface"])
    return proposals


# ---------------------------------------------------------------------------
# regeneration measurement -- run the generators, record the delta, restore the tree
# ---------------------------------------------------------------------------

# The generators and the artefacts they own. `atlas_parity.py` is included because the
# constitution's item 9 ("generated parity projection") is one of the artefacts this
# checkpoint must not have moved silently.
REGENERATION_SPECS = (
    {"script": "forensics/tools/symbol_ownership.py", "args": [],
     "outputs": ["forensics/atlas/symbol-ownership.json"]},
    {"script": "forensics/tools/implemented_surface.py", "args": [],
     "outputs": ["forensics/atlas/implemented-surface.json"]},
    {"script": "forensics/tools/phase3_obligations.py", "args": [],
     "outputs": ["forensics/phase3-obligations.json"]},
    {"script": "forensics/tools/phase4_obligations.py", "args": [],
     "outputs": ["forensics/phase4-obligations.json"]},
    {"script": "forensics/tools/phase5_obligations.py", "args": [],
     "outputs": ["forensics/phase5-obligations.json"]},
    {"script": "forensics/tools/phase6_obligations.py", "args": [],
     "outputs": ["forensics/phase6-obligations.json"]},
    {"script": "forensics/tools/phase7_obligations.py", "args": [],
     "outputs": ["forensics/phase7-obligations.json"]},
    {"script": "forensics/tools/phase8_obligations.py", "args": [],
     "outputs": ["forensics/phase8-obligations.json"]},
    {"script": "forensics/tools/phase9_obligations.py", "args": [],
     "outputs": ["forensics/phase9-obligations.json"]},
    {"script": "forensics/tools/phase10_obligations.py", "args": [],
     "outputs": ["forensics/phase10-obligations.json"]},
    {"script": "forensics/tools/phase11_obligations.py", "args": [],
     "outputs": ["forensics/phase11-obligations.json"]},
    {"script": "forensics/tools/phase22_obligations.py", "args": [],
     "outputs": ["forensics/phase22-obligations.json"]},
    {"script": "forensics/tools/atlas_parity.py", "args": ["--authority", PRODUCTION_AUTHORITY],
     "outputs": [f"{PARITY_DIR}/parity-obligations.json",
                 f"{PARITY_DIR}/surface-reconciliation.json",
                 f"{PARITY_DIR}/coverage.json",
                 f"{PARITY_DIR}/PARITY_MATRIX.md"]},
)


def _leaf_deltas(before, after, path: str, out: list[dict]) -> None:
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after)):
            if key not in before:
                out.append({"path": f"{path}.{key}", "before": None, "after": after[key]})
            elif key not in after:
                out.append({"path": f"{path}.{key}", "before": before[key], "after": None})
            else:
                _leaf_deltas(before[key], after[key], f"{path}.{key}", out)
    elif isinstance(before, list) and isinstance(after, list):
        if len(before) != len(after):
            out.append({"path": f"{path}.length", "before": len(before), "after": len(after)})
        for i, (x, y) in enumerate(zip(before, after)):
            _leaf_deltas(x, y, f"{path}[{i}]", out)
    elif before != after:
        out.append({"path": path, "before": before, "after": after})


def _compare_output(relpath: str, before: bytes | None, after: bytes | None) -> dict:
    rec = {
        "path": relpath,
        "sha256_before": sha256_bytes(before) if before is not None else None,
        "sha256_after": sha256_bytes(after) if after is not None else None,
        "changed": before != after,
        "scalar_deltas": [],
        "body_scalar_deltas": [],
    }
    if before == after:
        return rec
    try:
        jb = json.loads(before.decode("utf-8")) if before is not None else None
        ja = json.loads(after.decode("utf-8")) if after is not None else None
    except (ValueError, UnicodeDecodeError) as exc:  # a non-JSON output, compared byte-wise
        rec["scalar_deltas"] = [{"path": "<non-json>", "before": None, "after": str(exc)}]
        return rec
    _leaf_deltas(jb, ja, "", rec["scalar_deltas"])
    if isinstance(jb, dict) and isinstance(ja, dict):
        _leaf_deltas(jb.get("body"), ja.get("body"), "body", rec["body_scalar_deltas"])
    return rec


def _regeneration_conclusion(records: list[dict], summary: dict) -> str:
    """The plain statement the checkpoint owes: no-op, or moved by how much."""
    changed = sorted(o["path"] for r in records for o in r["outputs"] if o["changed"])
    if not changed:
        return (
            f"regeneration is a byte-for-byte no-op across all {summary['outputs']} output(s) "
            f"of {summary['generators']} generator(s): the export universe Phase 22 reads is "
            "the one Phase 1 already had"
        )
    if summary["body_count_deltas"] == 0:
        return (
            f"regeneration moves NO obligation count: {len(changed)} of "
            f"{summary['outputs']} output(s) differ byte-wise, and every difference is a "
            "recorded input hash rather than a body value, so the export universe is "
            "unchanged; the differing files are "
            + ", ".join(changed)
            + ". The deltas are recorded inline in each output's scalar_deltas"
        )
    return (
        f"regeneration WOULD move counts: {summary['body_count_deltas']} body scalar "
        f"delta(s) across {summary['changed_outputs_with_body_delta']} output(s); the deltas "
        "are recorded inline in each output's body_scalar_deltas and must be dispositioned "
        "before the ledger is committed"
    )


def _measure_regeneration() -> dict:
    """Run every generator, record what moved, and restore the tree.

    The checkpoint artefact is hidden while this runs, because
    `forensics/phase22-obligations.json` names it as its 22.16 plane and would otherwise make
    the measurement depend on whether this checkpoint already exists. Hiding it makes the
    measurement a pure function of the pre-checkpoint tree on the first and every later run.
    """
    hidden: Path | None = None
    if OUT.is_file():
        hidden = OUT.with_name(OUT.name + ".measuring")
        OUT.rename(hidden)

    saved: dict[str, tuple[bool, bytes | None]] = {}
    try:
        for spec in REGENERATION_SPECS:
            for relpath in spec["outputs"]:
                p = REPO_ROOT / relpath
                saved[relpath] = (p.is_file(), p.read_bytes() if p.is_file() else None)

        records = []
        for spec in REGENERATION_SPECS:
            proc = subprocess.run(
                [sys.executable, spec["script"], *spec["args"]],
                cwd=str(REPO_ROOT), capture_output=True, text=True, check=False,
            )
            outputs = []
            for relpath in spec["outputs"]:
                _existed, before = saved[relpath]
                p = REPO_ROOT / relpath
                after = p.read_bytes() if p.is_file() else None
                outputs.append(_compare_output(relpath, before, after))
            records.append({
                "generator": spec["script"],
                "args": list(spec["args"]),
                "returncode": proc.returncode,
                "outputs": outputs,
            })

        changed = [o for r in records for o in r["outputs"] if o["changed"]]
        summary = {
            "generators": len(records),
            "generators_failed": sum(1 for r in records if r["returncode"] != 0),
            "outputs": sum(len(r["outputs"]) for r in records),
            "changed_outputs": len(changed),
            "changed_outputs_with_body_delta": sum(
                1 for o in changed if o["body_scalar_deltas"]),
            "body_count_deltas": sum(
                len(o["body_scalar_deltas"]) for r in records for o in r["outputs"]),
            "scalar_deltas": sum(
                len(o["scalar_deltas"]) for r in records for o in r["outputs"]),
        }
        return {
            "method": (
                "each generator is run in the repository, its declared outputs are compared "
                "with the bytes found before the run, and the bytes found before the run are "
                "restored -- so this is a measurement that leaves the tree as it found it"
            ),
            "normalization": (
                f"{Path(ARTEFACT_REL).name} is hidden while the generators run, because "
                f"{LEDGER_REL} names it as its 22.16 plane; with the checkpoint present, that "
                "one plane would move from open to implemented by construction rather than by "
                "any export changing"
            ),
            "generators": records,
            "summary": summary,
            "conclusion": _regeneration_conclusion(records, summary),
            "changed_paths": sorted(o["path"] for o in changed),
        }
    finally:
        for relpath, (existed, data) in saved.items():
            p = REPO_ROOT / relpath
            if existed and data is not None:
                p.write_bytes(data)
            elif not existed and p.exists():
                p.unlink()
        if hidden is not None:
            hidden.rename(OUT)


# ---------------------------------------------------------------------------
# collection entry point
# ---------------------------------------------------------------------------

def collect_context(authority: str) -> dict:
    closure = json.loads(
        (P22 / "compatibility-closure.json").read_text(encoding="utf-8"))["body"]
    census = _collect_census(closure)
    p11, p11_implemented = _collect_phase11()
    return {
        "plan": {"path": PLAN_REL, "sha256": sha256_file(REPO_ROOT / PLAN_REL)},
        "authority": authority,
        "planes": _collect_planes(),
        "plane_ledger": _collect_plane_ledger(),
        "residual_census": census,
        "phase11_continuation": p11,
        "x509_slice": closure["x509_slice"],
        "x509_gate": _collect_x509_gate(p11_implemented),
        "non_export_obligations": _collect_obligations(census),
        "regeneration": _measure_regeneration(),
    }


# ---------------------------------------------------------------------------
# the court
# ---------------------------------------------------------------------------

def court_gemel(body: dict) -> dict:
    """`RT-PHASE22-GEMEL`: an FRF-style sensitivity challenge of the checkpoint assembly.

    Round-trips the committed checkpoint through `build_checkpoint` from its own context,
    then drives the assembler over five controlled in-memory mutations -- change a bound
    artefact hash, add a residual class, add an UNKNOWN to the named set, move a plane
    between open and implemented, and add a proposed obligation -- and fails if any derived
    figure is insensitive to it.
    """
    checks: list[tuple[str, bool]] = []
    src = _inputs(body)
    base = build_checkpoint(src)
    counts = body["counts"]
    ident = body["identity"]

    checks.append(("round-trip: the committed body equals the assembler's output",
                   base == body))
    checks.append(("baseline: the checkpoint binds atlas planes",
                   counts["planes_bound"] > 0))
    checks.append(("baseline: the checkpoint carries residual classes",
                   counts["census_residual_classes"] > 0))
    checks.append(("baseline: the checkpoint names a non-empty UNKNOWN set",
                   counts["unknown_total"] > 0))
    checks.append(("baseline: the checkpoint carries a proposed obligation set",
                   counts["obligations"] > 0))
    checks.append(("baseline: the state hash is a sha256",
                   len(ident["checkpoint_state_hash"]) == 64))

    # 1. change a bound artefact hash: the identity must move, the counts must not.
    if src["planes"]:
        probe = copy.deepcopy(src)
        name = probe["planes"][0]["name"]
        old = probe["planes"][0]["sha256"]
        probe["planes"][0]["sha256"] = ("0" * 64) if old != "0" * 64 else ("1" * 64)
        got = build_checkpoint(probe)
        checks.append(("change-artefact-hash: the atlas hash moves",
                       got["identity"]["atlas"][name] != ident["atlas"][name]))
        checks.append(("change-artefact-hash: the state hash moves",
                       got["identity"]["checkpoint_state_hash"]
                       != ident["checkpoint_state_hash"]))
        checks.append(("change-artefact-hash: the derived counts hold",
                       got["counts"] == counts))
    else:
        checks.append(("change-artefact-hash: a bound plane was found", False))

    # 2. add a residual class.
    probe = copy.deepcopy(src)
    probe["residual_census"]["by_class"]["GEMEL_PROBE_CLASS"] = 1
    got = build_checkpoint(probe)
    checks.append(("add-residual-class: the class count rises by one",
                   got["counts"]["census_residual_classes"]
                   == counts["census_residual_classes"] + 1))
    checks.append(("add-residual-class: the class is present",
                   got["residual_census"]["by_class"].get("GEMEL_PROBE_CLASS") == 1))

    # 3. add an UNKNOWN to the named set.
    cls = min(src["residual_census"]["unknown_sets"])
    probe = copy.deepcopy(src)
    probe["residual_census"]["unknown_sets"][cls] = sorted(
        set(probe["residual_census"]["unknown_sets"][cls]) | {"sym|gemel_probe_unknown"})
    got = build_checkpoint(probe)
    checks.append(("add-unknown: the unknown total rises by one",
                   got["counts"]["unknown_total"] == counts["unknown_total"] + 1))
    checks.append(("add-unknown: the key is named in its class",
                   "sym|gemel_probe_unknown"
                   in got["residual_census"]["unknown_sets"][cls]))
    checks.append(("add-unknown: unknown_by_class tracks the class",
                   got["counts"]["unknown_by_class"][cls]
                   == counts["unknown_by_class"][cls] + 1))

    # 4. move a plane between implemented and open. The direction is chosen from the ledger so the
    #    mutation is always available: once every plane is complete there is no open plane to
    #    close, so an implemented plane is reopened and the derivation must move the other way.
    #    (Depending on an open plane being present made this check silently hostage to a stale
    #    committed checkpoint.)
    if src["plane_ledger"]["open"]:
        moved = sorted(src["plane_ledger"]["open"])[0]
        new_open = [x for x in src["plane_ledger"]["open"] if x != moved]
        new_impl = sorted(set(src["plane_ledger"]["implemented"]) | {moved})
        expect_impl = counts["plane_ledger_implemented"] + 1
        expect_open = counts["plane_ledger_open"] - 1
    else:
        moved = sorted(src["plane_ledger"]["implemented"])[0]
        new_open = sorted(set(src["plane_ledger"]["open"]) | {moved})
        new_impl = [x for x in src["plane_ledger"]["implemented"] if x != moved]
        expect_impl = counts["plane_ledger_implemented"] - 1
        expect_open = counts["plane_ledger_open"] + 1
    probe = copy.deepcopy(src)
    probe["plane_ledger"]["open"] = new_open
    probe["plane_ledger"]["implemented"] = new_impl
    got = build_checkpoint(probe)
    checks.append(("move-ledger-state: implemented moved by one",
                   got["counts"]["plane_ledger_implemented"] == expect_impl))
    checks.append(("move-ledger-state: open moved by one",
                   got["counts"]["plane_ledger_open"] == expect_open))
    checks.append(("move-ledger-state: the plane's list membership followed",
                   (moved in got["plane_ledger"]["implemented"]) == (moved in new_impl)
                   and (moved in got["plane_ledger"]["open"]) == (moved in new_open)))

    # 5. add a proposed obligation.
    probe = copy.deepcopy(src)
    probe["non_export_obligations"] = list(probe["non_export_obligations"]) + [{
        "surface": "gemel-probe",
        "count": 1,
        "proposed_owner": "none",
        "evidence": [],
        "reason": "the court's own probe",
        "detail": {},
    }]
    got = build_checkpoint(probe)
    checks.append(("add-obligation: the obligation count rises by one",
                   got["counts"]["obligations"] == counts["obligations"] + 1))
    checks.append(("add-obligation: the obligation units rise by its count",
                   got["counts"]["obligation_units"] == counts["obligation_units"] + 1))
    checks.append(("add-obligation: the state hash moves",
                   got["identity"]["checkpoint_state_hash"]
                   != ident["checkpoint_state_hash"]))

    # restore: the committed inputs still produce the committed body.
    checks.append(("restore: the committed inputs return the committed body",
                   build_checkpoint(_inputs(body)) == body))

    failures = [desc for desc, ok in checks if not ok]
    reg = body["regeneration"]["summary"]
    return {
        "court": COURT,
        "artefact": ARTEFACT_REL,
        "summary": (
            f"{counts['planes_bound']} plane hashes, {counts['census_entities']} entities, "
            f"{counts['unknown_total']} UNKNOWN named, {counts['obligations']} proposed "
            f"obligations, regeneration changed {reg['changed_outputs']}/"
            f"{reg['outputs']} outputs with {reg['body_count_deltas']} count deltas"),
        "planes_bound": counts["planes_bound"],
        "census_entities": counts["census_entities"],
        "census_residuals": counts["census_residuals"],
        "unknown_total": counts["unknown_total"],
        "unknown_intersecting_roots": counts["unknown_intersecting_roots"],
        "phase11_implemented": counts["phase11_implemented"],
        "phase11_open": counts["phase11_open"],
        "x509_satisfied": counts["x509_satisfied"],
        "obligations": counts["obligations"],
        "regenerated_changed_outputs": reg["changed_outputs"],
        "regenerated_count_deltas": reg["body_count_deltas"],
        "mutations": ["round-trip", "change-artefact-hash", "add-residual-class",
                      "add-unknown", "move-ledger-state", "add-obligation", "restore"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
    }


def courts() -> list[dict]:
    """`RT-PHASE22-GEMEL`, or `[]` while the artefact has not landed."""
    if not OUT.is_file():
        return []
    try:
        body = json.loads(OUT.read_text(encoding="utf-8"))["body"]
    except Exception as exc:  # a court that cannot read its artefact is a failing court
        return [{"court": COURT, "artefact": ARTEFACT_REL, "verdict": "fail",
                 "stage": "artefact-unreadable", "observations": 0, "failures": [str(exc)]}]
    return [court_gemel(body)]


# ---------------------------------------------------------------------------
# the self-test: break the assembler in memory and require the court to fail
# ---------------------------------------------------------------------------

def self_test(body: dict) -> bool:
    """Prove the court is not a rubber stamp by breaking `_count_obligations` in memory.

    Real body -> pass. Broken function (obligation count insensitive to its input) -> the
    round trip and the add-obligation check must fail, so the court must FAIL. Restored ->
    pass. A court that still passed with the broken function would be evidence of nothing.
    """
    real = court_gemel(body)
    if real["verdict"] != "pass":
        print("[phase22-gemel] self-test: FAIL -- the court fails on the committed artefact")
        for f in real["failures"]:
            print(f"  {f}")
        return False

    original = globals()["_count_obligations"]

    def broken(_obligations):  # insensitive to its own input
        return 0

    globals()["_count_obligations"] = broken
    try:
        broken_court = court_gemel(body)
    finally:
        globals()["_count_obligations"] = original

    restored = court_gemel(body)

    failures: list[str] = []
    if broken_court["verdict"] != "fail":
        failures.append("the court PASSED with a broken obligation counter (not sensitive)")
    if restored["verdict"] != "pass":
        failures.append("the court did not return to pass after the function was restored")

    if failures:
        print("[phase22-gemel] self-test: FAIL")
        for f in failures:
            print(f"  {f}")
        return False
    print("[phase22-gemel] self-test: ok (broken assembly -> "
          f"{len(broken_court['failures'])} failing check(s); restored -> pass)")
    return True


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _envelope_inputs(ctx: dict) -> list[InputRef]:
    seen: set[str] = set()
    inputs: list[InputRef] = []

    def add(relpath: str, name: str) -> None:
        path = REPO_ROOT / relpath
        if relpath in seen or not path.is_file():
            return
        seen.add(relpath)
        inputs.append(InputRef(name=name, path=path))

    add(PLAN_REL, "plan")
    add(LEDGER_REL, "phase22-obligations")
    add(PHASE11_LEDGER_REL, "phase11-obligations")
    add(UNITS_REL, "export-defining-units")
    add(X509_BASELINE_REL, "x509-closure-slice-baseline")
    add(CLI_CAPTURE_REL, "phase1-cli-capture")
    for plane in ctx["planes"]:
        add(plane["path"], plane["name"])
    for spec in REGENERATION_SPECS:
        for relpath in spec["outputs"]:
            add(relpath, Path(relpath).stem)
    return inputs


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--self-test", action="store_true",
                    help="break the assembler in memory and require the court to fail")
    ap.add_argument("--court-only", action="store_true",
                    help="run the court over the committed artefact without regenerating")
    args = ap.parse_args(argv)

    if args.court_only:
        if not OUT.is_file():
            print(f"[phase22-gemel] {ARTEFACT_REL} is absent")
            return 1
        body = json.loads(OUT.read_text(encoding="utf-8"))["body"]
        record = court_gemel(body)
        for f in record["failures"]:
            print(f"  FAIL {f}")
        print(f"[phase22-gemel] court {record['verdict']} ({record['observations']} "
              f"observations): {record['summary']}")
        return 0 if record["verdict"] == "pass" else 1

    ctx = collect_context(args.authority)
    body = build_checkpoint(ctx)

    doc = envelope(
        kind="phase22-gemel-checkpoint",
        authority=args.authority,
        inputs=_envelope_inputs(ctx),
        body=body,
        generator=GENERATOR,
    )
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase22-gemel] planes={c['planes_bound']} "
          f"ledger={c['plane_ledger_implemented']}/{c['plane_ledger_implemented'] + c['plane_ledger_open']} "
          f"entities={c['census_entities']} residuals={c['census_residuals']} "
          f"unknown={c['unknown_total']} obligations={c['obligations']} "
          f"-> {rel(OUT)}")
    reg = body["regeneration"]["summary"]
    print(f"[phase22-gemel] regeneration: {reg['changed_outputs']}/{reg['outputs']} outputs "
          f"changed, {reg['body_count_deltas']} body count delta(s); "
          f"phase11 implemented={c['phase11_implemented']} open={c['phase11_open']}; "
          f"x509_satisfied={c['x509_satisfied']}")

    if args.self_test:
        return 0 if self_test(body) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
