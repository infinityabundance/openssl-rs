#!/usr/bin/env python3
"""Load-bearing controls for the repaired carry-forward migration arm (b78c).

Runs the *pre-repair* tool (``git show HEAD:forensics/tools/consumer_closure.py``)
and the repaired worktree tool through the same real ``adjudicate`` /
``migration_witness`` / ``migration_bindings`` code on identical two-commit git
fixtures, so each control is demonstrably discriminating rather than merely
documented.

Controls (expected verdicts):
  base  positive: stale coordinate bound by a committed content proof
  a     same body hash under a *different* qualified context  (O1)
  b     two boundaries with the identical body                (O6)
  c     non-definition ancestor coordinate                     (O5)
  d     recorded ancestor hash != candidate body               (hash gate)
  e     previously RETAINED disposition                        (B67 gate)
  f1    modified receipt with the original pin retained        (O3)
  f2    modified receipt with the pin recomputed from the file (O3)
  g     absolute receipt path                                  (O7)
  o4    no candidate source commit bound                       (O4)

``expected_old``/``expected_new`` are the verdicts the review observed/wants;
the runner reports MISMATCH for any control that does not behave as expected.

Run inside the court:
  OPENSSL_RS_COURT_DATA=6291456 bash docker/openssl-rs-court.sh exec \
      sh -c 'cd /work && python3 court/freeze-b78/controls-migration-b78c.py'
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

WORK = Path("/work") if Path("/work").is_dir() else Path(__file__).resolve().parents[2]
NEW_TOOL = WORK / "forensics/tools/consumer_closure.py"
OLD_REV = "HEAD"
OLD_PATH = "forensics/tools/consumer_closure.py"

ANCESTOR = (
    "mod m1 {\n"
    "    pub unsafe fn copyctx(a: *mut u8) {\n"
    "        core::ptr::read_volatile(a);\n"
    "    }\n"
    "}\n"
    "mod m2 {\n"
    "    pub unsafe fn copyctx(a: *mut u8) {\n"
    "        core::ptr::read_volatile(a);\n"
    "    }\n"
    "}\n")
CANDIDATE = ANCESTOR
DEFAULT_DISPOSITION = "SAFETY_DISCHARGED (scope: src/ssl/mig.rs:1-20)"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def old_tool_path() -> Path:
    out = Path(tempfile.mkdtemp(prefix="old-closure-")) / "consumer_closure_old.py"
    raw = subprocess.check_output(
        ["git", "-C", str(WORK), "show", f"{OLD_REV}:{OLD_PATH}"])
    out.write_bytes(raw)
    return out


def git(d, *args):
    subprocess.run(["git", "-C", str(d), "-c", "user.email=t@t",
                    "-c", "user.name=t", *args], check=True,
                   capture_output=True)


def rev(d, ref="HEAD"):
    return subprocess.check_output(
        ["git", "-C", str(d), "rev-parse", ref], text=True).strip()


def fixture(m, *, boundary_operation="m1::copyctx", census_lines=(5, 10),
            two_boundaries=False, tamper_receipt=False,
            repin_uncommitted=False, absolute_receipt=False,
            disposition=DEFAULT_DISPOSITION, row_line=2, previous_line=2,
            recorded_from_ancestor=False, without_source_commit=False):
    """Two commits (ancestor, candidate+committed receipt) -> adjudicate()."""
    td = tempfile.TemporaryDirectory(prefix="mig-control-")
    d = Path(td.name)
    (d / "src/ssl").mkdir(parents=True)
    (d / "evidence").mkdir()
    git(d, "init", "-q")
    (d / "src/ssl/mig.rs").write_text(ANCESTOR)
    git(d, "add", "-A")
    git(d, "commit", "-qm", "ancestor")
    ancestor_head = rev(d)

    (d / "src/ssl/mig.rs").write_text(
        "//! a module doc line that did not exist at the ancestor head\n"
        "//! second line\n"
        "\n" + CANDIDATE)
    evidence = {
        "source_identity": {"span_source_commit": ancestor_head},
        "obligations": [{
            "id": "V1:src/ssl/mig.rs:2:UNSAFE_FN_DEF",
            "file": "src/ssl/mig.rs", "kind": "UNSAFE_FN_DEF",
            "item": "copyctx", "line": 2,
            "carried_forward_from": None}],
    }
    ev_rel = "evidence/closure-test-anc.json"
    (d / ev_rel).write_text(json.dumps(evidence))
    git(d, "add", "-A")
    git(d, "commit", "-qm", "candidate")
    candidate_head = rev(d)

    digest = hashlib.sha256((d / ev_rel).read_bytes()).hexdigest()
    if tamper_receipt:
        digest = "0" * 64
    receipt_ref = str(d / ev_rel) if absolute_receipt else ev_rel

    m.clear_span_cache()
    if recorded_from_ancestor:
        recorded = m.resolve_operation_at_line(
            d, "src/ssl/mig.rs", "copyctx", 2,
            source_commit=ancestor_head)["sha256"]
    else:
        recorded = m.resolve_operation_span(
            d, "src/ssl/mig.rs", boundary_operation, "copyctx",
            allow_worktree=True)["sha256"]

    bounds = [{
        "id": "D-MIG", "receipt": "sweep-mig", "file": "src/ssl/mig.rs",
        "kind": "UNSAFE_FN_DEF", "operation": boundary_operation,
        "disposition": disposition,
        "disposition_discharges": m.boundary_disposition_is_discharge(
            disposition),
        "superseded_ids": [],
        "span_sha256": recorded, "line": 5, "inventory_line": 2}]
    if two_boundaries:
        bounds.append(dict(bounds[0], id="D-MIG-2"))

    obligation = {
        "file": "src/ssl/mig.rs", "line": row_line,
        "kind": "UNSAFE_FN_DEF", "item": "copyctx",
        "mechanism": "SSL_SESSION", "status": None,
        "discharge_receipt": None, "status_reason": None,
        "carried_forward_from": {
            "receipt": receipt_ref, "receipt_sha256": digest,
            "previous_id": "V1:src/ssl/mig.rs:2:UNSAFE_FN_DEF",
            "previous_line": previous_line},
    }
    if repin_uncommitted:
        tampered = dict(evidence, note="modified after the commit")
        (d / ev_rel).write_text(json.dumps(tampered))
        obligation["carried_forward_from"]["receipt_sha256"] = (
            hashlib.sha256((d / ev_rel).read_bytes()).hexdigest())

    census = {("src/ssl/mig.rs", "UNSAFE_FN_DEF", "copyctx"):
              set(census_lines)}
    plane = {"mechanism_discharges": {},
             "scoped_boundary_discharges": {
                 b["id"]: {"receipt": "sweep-mig"} for b in bounds},
             "err_scope": {}}
    previous = m._EVIDENCE_ENV.get("source_commit")
    m._EVIDENCE_ENV["source_commit"] = (
        None if without_source_commit else candidate_head)
    try:
        return m.adjudicate(
            obligation, {"SSL_SESSION": {"state": None}}, bounds, plane,
            repo=d, allow_worktree_span=True, census_ops=census)
    finally:
        m._EVIDENCE_ENV["source_commit"] = previous
        td.cleanup()


def reason_of(result):
    reasons = [r.get("reason") for r in result.get("migration_refusals") or []]
    if reasons:
        return ",".join(sorted({str(r) for r in reasons}))
    rejection = (result.get("span_discharge_rejections") or [{}])[0].get(
        "classification")
    disposition = (result.get("disposition_discharge_rejections")
                   or [{}])[0].get("classification")
    return rejection or disposition or "-"


CONTROLS = [
    # id, description, kwargs, expected old, expected new
    ("base", "positive: stale coordinate, committed content proof", {},
     "DISCHARGED", "DISCHARGED"),
    ("a", "same body under a different qualified context", {
        "boundary_operation": "m2::copyctx"}, "DISCHARGED", "BLOCKED"),
    ("b", "two boundaries with the identical body",
     {"two_boundaries": True}, "BLOCKED", "BLOCKED"),
    ("c", "ancestor coordinate inside a definition, not its def line",
     {"previous_line": 3, "row_line": 3}, "BLOCKED", "BLOCKED"),
    ("d", "recorded ancestor hash != candidate body", {},
     "BLOCKED", "BLOCKED"),
    ("e", "previously RETAINED disposition", {
        "disposition": "RETAINED (BLOCKED)"}, "BLOCKED", "BLOCKED"),
    ("f1", "modified receipt, original pin retained", {
        "tamper_receipt": True}, "BLOCKED", "BLOCKED"),
    ("f2", "modified receipt, pin recomputed from the file", {
        "repin_uncommitted": True}, "DISCHARGED", "BLOCKED"),
    ("g", "absolute receipt path", {"absolute_receipt": True},
     "DISCHARGED", "BLOCKED"),
    ("o4", "no candidate source commit bound", {
        "without_source_commit": True}, "DISCHARGED", "BLOCKED"),
]


def run(mod, cid, kwargs):
    if cid == "d":
        # control d needs the candidate body edited *after* the ancestor hash is
        # recorded; fixture() with recorded_from_ancestor already records the
        # ancestor hash, and the candidate fixture body is byte-identical, so an
        # explicit edit is applied through a dedicated call.
        return d_control(mod)
    return fixture(mod, **kwargs)


def d_control(mod):
    """Candidate body edited while the boundary records the ancestor hash."""
    td = tempfile.TemporaryDirectory(prefix="mig-control-d-")
    d = Path(td.name)
    (d / "src/ssl").mkdir(parents=True)
    (d / "evidence").mkdir()
    git(d, "init", "-q")
    (d / "src/ssl/mig.rs").write_text(ANCESTOR)
    git(d, "add", "-A")
    git(d, "commit", "-qm", "ancestor")
    ancestor_head = rev(d)
    edited_body = CANDIDATE.replace(
        "core::ptr::read_volatile(a);",
        "core::ptr::read_volatile(a); // edited", 1)
    (d / "src/ssl/mig.rs").write_text(
        "//! a module doc line that did not exist at the ancestor head\n"
        "//! second line\n\n" + edited_body)
    evidence = {"source_identity": {"span_source_commit": ancestor_head},
                "obligations": [{"id": "V1:src/ssl/mig.rs:2:UNSAFE_FN_DEF",
                                 "file": "src/ssl/mig.rs",
                                 "kind": "UNSAFE_FN_DEF",
                                 "item": "copyctx", "line": 2,
                                 "carried_forward_from": None}]}
    ev_rel = "evidence/closure-test-anc.json"
    (d / ev_rel).write_text(json.dumps(evidence))
    git(d, "add", "-A")
    git(d, "commit", "-qm", "candidate")
    candidate_head = rev(d)
    digest = hashlib.sha256((d / ev_rel).read_bytes()).hexdigest()
    mod.clear_span_cache()
    recorded = mod.resolve_operation_at_line(
        d, "src/ssl/mig.rs", "copyctx", 2,
        source_commit=ancestor_head)["sha256"]
    bounds = [{
        "id": "D-MIG", "receipt": "sweep-mig", "file": "src/ssl/mig.rs",
        "kind": "UNSAFE_FN_DEF", "operation": "m1::copyctx",
        "disposition": DEFAULT_DISPOSITION, "disposition_discharges": True,
        "superseded_ids": [], "span_sha256": recorded,
        "line": 5, "inventory_line": 2}]
    obligation = {
        "file": "src/ssl/mig.rs", "line": 2, "kind": "UNSAFE_FN_DEF",
        "item": "copyctx", "mechanism": "SSL_SESSION", "status": None,
        "discharge_receipt": None, "status_reason": None,
        "carried_forward_from": {
            "receipt": ev_rel, "receipt_sha256": digest,
            "previous_id": "V1:src/ssl/mig.rs:2:UNSAFE_FN_DEF",
            "previous_line": 2}}
    census = {("src/ssl/mig.rs", "UNSAFE_FN_DEF", "copyctx"): {5, 10}}
    plane = {"mechanism_discharges": {},
             "scoped_boundary_discharges": {"D-MIG": {"receipt": "sweep-mig"}},
             "err_scope": {}}
    previous = mod._EVIDENCE_ENV.get("source_commit")
    mod._EVIDENCE_ENV["source_commit"] = candidate_head
    try:
        return mod.adjudicate(
            obligation, {"SSL_SESSION": {"state": None}}, bounds, plane,
            repo=d, allow_worktree_span=True, census_ops=census)
    finally:
        mod._EVIDENCE_ENV["source_commit"] = previous
        td.cleanup()


def main() -> int:
    new = load_module(NEW_TOOL, "closure_new")
    old = load_module(old_tool_path(), "closure_old")
    print(f"old tool: git {OLD_REV}:{OLD_PATH}")
    print(f"new tool: {NEW_TOOL}")
    failures = 0
    rows = []
    for cid, description, kwargs, want_old, want_new in CONTROLS:
        try:
            obs_old = run(old, cid, kwargs)["status"]
        except Exception as exc:  # noqa: BLE001
            obs_old = f"ERROR:{type(exc).__name__}"
        try:
            new_result = run(new, cid, kwargs)
            obs_new = new_result["status"]
            why = reason_of(new_result)
        except Exception as exc:  # noqa: BLE001
            obs_new = f"ERROR:{type(exc).__name__}"
            why = "-"
        ok = obs_old == want_old and obs_new == want_new
        failures += 0 if ok else 1
        rows.append({"id": cid, "description": description,
                     "old": obs_old, "new": obs_new,
                     "expected_old": want_old, "expected_new": want_new,
                     "new_reason": why, "pass": ok})
        print(f"  [{cid}] {description}: old={obs_old} new={obs_new} "
              f"(want old={want_old} new={want_new}) "
              f"new_reason={why} {'OK' if ok else 'MISMATCH'}")

    # Real-row positive control: the seven carried-forward copyctx rows, if the
    # b78c closures have been produced.
    real = []
    for family in ("ssh", "sshd"):
        path = WORK / f"evidence/closure-{family}-b78c.json"
        if not path.is_file():
            continue
        doc = json.loads(path.read_text())
        for o in doc.get("obligations") or []:
            if o.get("item") == "copyctx" and o.get("carried_forward_from"):
                real.append({
                    "family": family, "id": o["id"], "status": o.get("status"),
                    "binding": (o.get("span_discharge") or {}).get("binding"),
                    "reason": (o.get("status_reason") or "")[:160]})
    if real:
        print("\nreal seven-row positive control (b78c closures):")
        for row in real:
            print(f"  {row['family']} {row['id']} -> {row['status']} "
                  f"binding={row['binding']}")

    out = WORK / "court/freeze-b78/controls-migration-b78c.json"
    out.write_text(json.dumps({
        "schema": "openssl-rs/campaign/safe-c33/migration-controls/v1",
        "old_tool": f"git {OLD_REV}:{OLD_PATH}",
        "new_tool": str(NEW_TOOL),
        "controls": rows,
        "real_seven_rows": real,
        "failures": failures,
    }, indent=2) + "\n")
    print(f"\ncontrols: {len(rows) - failures}/{len(rows)} behaved as expected; "
          f"report {out}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
