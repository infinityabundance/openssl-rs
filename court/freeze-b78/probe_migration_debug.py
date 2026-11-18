#!/usr/bin/env python3
"""Debug the migration fixture: print each stage's decision."""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

ANC = ("mod m1 {\n"
       "    pub unsafe fn copyctx(a: *mut u8) {\n"
       "        // one\n"
       "        core::ptr::read_volatile(a);\n"
       "    }\n"
       "}\n"
       "mod m2 {\n"
       "    pub unsafe fn copyctx(a: *mut u8) {\n"
       "        // two\n"
       "        core::ptr::read_volatile(a);\n"
       "    }\n"
       "}\n")


def git(d, *a):
    subprocess.run(["git", "-C", str(d), "-c", "user.email=t@t",
                    "-c", "user.name=t"] + list(a), check=True,
                   capture_output=True)


def main():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "src/ssl").mkdir(parents=True)
        (d / "evidence").mkdir()
        git(d, "init", "-q")
        (d / "src/ssl/mig.rs").write_text(ANC)
        git(d, "add", "-A")
        git(d, "commit", "-qm", "ancestor")
        head = subprocess.check_output(
            ["git", "-C", str(d), "rev-parse", "HEAD"], text=True).strip()
        (d / "src/ssl/mig.rs").write_text(
            "//! doc\n//! doc2\n\n" + ANC)
        ev = {"source_identity": {"span_source_commit": head},
              "obligations": [{"id": "V1:src/ssl/mig.rs:2:UNSAFE_FN_DEF",
                               "file": "src/ssl/mig.rs",
                               "kind": "UNSAFE_FN_DEF", "item": "copyctx",
                               "line": 2, "carried_forward_from": None}]}
        ev_rel = "evidence/anc.json"
        (d / ev_rel).write_text(json.dumps(ev))
        digest = hashlib.sha256((d / ev_rel).read_bytes()).hexdigest()
        cc.clear_span_cache()
        try:
            sp = cc.resolve_operation_span(d, "src/ssl/mig.rs", "m1::copyctx",
                                           "copyctx", allow_worktree=True)
            print("cand span", sp["start_line"], sp["end_line"],
                  sp["def_line"], sp["qualified_identity"], sp["sha256"][:16])
        except cc.SpanResolutionError as e:
            print("cand span FAILED", e.classification, e.detail)
            return
        try:
            at = cc.resolve_operation_at_line(d, "src/ssl/mig.rs", "copyctx", 2,
                                              source_commit=head)
            print("anc  span", at["start_line"], at["end_line"], at["def_line"],
                  at["resolution"], at["sha256"][:16], "same",
                  at["sha256"] == sp["sha256"])
        except cc.SpanResolutionError as e:
            print("anc  span FAILED", e.classification, e.detail)
        ob = {"file": "src/ssl/mig.rs", "line": 2, "kind": "UNSAFE_FN_DEF",
              "item": "copyctx", "mechanism": "SSL_SESSION", "status": None,
              "discharge_receipt": None, "status_reason": None,
              "carried_forward_from": {"receipt": ev_rel,
                                       "receipt_sha256": digest,
                                       "previous_id":
                                           "V1:src/ssl/mig.rs:2:UNSAFE_FN_DEF",
                                       "previous_line": 2}}
        print("chain", cc._carried_forward_coordinates(d, ob))
        b = {"id": "D-MIG", "receipt": "sweep-mig", "file": "src/ssl/mig.rs",
             "kind": "UNSAFE_FN_DEF", "operation": "m1::copyctx",
             "disposition": "SAFETY_DISCHARGED (scope: src/ssl/mig.rs:1-20)",
             "disposition_discharges": True, "superseded_ids": [],
             "span_sha256": sp["sha256"], "line": 5, "inventory_line": 2}
        census = {("src/ssl/mig.rs", "UNSAFE_FN_DEF", "copyctx"): {5, 10}}
        w = cc.migration_witness(d, ob, b, None, allow_worktree=True,
                                 census_ops=census)
        print("witness", "None" if w is None else "ok")
        print("bindings", sorted(cc.migration_bindings(
            d, ob, [b], None, allow_worktree=True, census_ops=census)))


if __name__ == "__main__":
    main()
