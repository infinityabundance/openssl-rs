#!/usr/bin/env python3
"""Controls for the extension-slot callback enumeration gate.

Runs C1-C5 and writes a machine-readable result set plus a short Markdown
report.  C1 edits the real source tree temporarily and restores it with
``git checkout``; the harness refuses to run if the tree is dirty, and verifies
that the restored files are byte-identical to HEAD.

Control inventories (the full post-enrolment inventory, and that inventory with
one callback removed) are *test-only* inputs.  They exist to exercise the
gate's pass/fail logic and are never used for the authoritative run.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
GATE = os.path.join(ROOT, "forensics", "tools", "callback_enumeration_gate.py")
CLOSURE = os.path.join(ROOT, "evidence", "closure-ssh-b52-applied.json")
REFRESH = os.path.join(
    ROOT, "forensics", "memory-safety", "campaign", "safe-c33", "atlas-refresh")
CTRL = os.path.join(REFRESH, "callback-gate-controls")

ENROLMENT = os.path.join(REFRESH, "callback-enrolment-blockers.json")
AUTH_REPORT = os.path.join(REFRESH, "callback-gate-report.json")
AUTH_MANIFEST = os.path.join(REFRESH, "callback-registration-manifest.json")
SKID = "src/x509/v3_skid.rs"
VLIB = "src/x509/v3_lib.rs"


def run(cmd: list[str], cwd: str = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def gate(out_dir: str, inventory: str | None = None,
         overrides: str | None = None, allow_drift: bool = True,
         tag: str = "run", default_names: bool = False) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    cmd = [sys.executable, GATE, "--root", ROOT, "--closure", CLOSURE,
           "--out-dir", out_dir]
    if default_names:
        report_name = "callback-gate-report.json"
    else:
        report_name = f"report-{tag}.json"
        cmd += ["--manifest-name", f"manifest-{tag}.json",
                "--report-name", report_name,
                "--enrolment-name", f"enrolment-{tag}.json"]
    if inventory:
        cmd += ["--inventory", inventory]
    if overrides:
        cmd += ["--overrides", overrides]
    if allow_drift:
        cmd += ["--allow-source-drift"]
    proc = run(cmd)
    report_path = os.path.join(out_dir, report_name)
    report = {}
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
    return {
        "cmd": " ".join(cmd),
        "exit_code": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
        "report": report,
    }


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_control_inventory(path: str, drop: tuple[str, str] | None = None) -> dict:
    with open(CLOSURE, "r", encoding="utf-8") as f:
        closure = json.load(f)
    with open(ENROLMENT, "r", encoding="utf-8") as f:
        enrolment = json.load(f)
    keep = ("file", "line", "kind", "item", "partition", "status")
    obligations = [{k: o.get(k) for k in keep}
                   for o in closure["obligations"]]
    seen = {(o.get("file"), o.get("item"), o.get("kind"))
            for o in obligations}
    for b in enrolment["blockers"]:
        key = (b["file"], b["item"], b["kind"])
        if key in seen:
            continue
        seen.add(key)
        obligations.append({
            "id": b["id"],
            "stable_id": b["stable_id"],
            "file": b["file"],
            "line": b["line"],
            "kind": b["kind"],
            "item": b["item"],
            "partition": b["partition"],
            "contract": "contracted",
            "contract_basis": "control inventory: post-enrolment state",
            "status": "BLOCKED",
            "status_reason": "control-only enrolment; not an applied ledger row",
            "mechanism": b.get("mechanism"),
        })
    if drop:
        obligations = [o for o in obligations
                       if (o.get("file"), o.get("item")) != drop]
    doc = {
        "schema": closure.get("schema"),
        "family": closure.get("family"),
        "source_identity": closure.get("source_identity"),
        "control_only": True,
        "note": ("Synthetic post-enrolment inventory used only by the gate "
                 "controls; it is not an applied census and must not be used "
                 "for a graduation claim."),
        "obligations": obligations,
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    return doc


def write_overrides(path: str, key: str, classification: str,
                    assumption: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({key: {"classification": classification,
                         "assumption": assumption}}, f, indent=1, sort_keys=True)
        f.write("\n")


def missing_names(report: dict) -> list[str]:
    return [f'{c["file"]}::{c["callback"]}' for c in report.get("missing", [])]


def main() -> int:
    # Refuse to edit a dirty tree.
    st = run(["git", "status", "--porcelain", "--", SKID, VLIB])
    if st.stdout.strip():
        print("refusing to run: source files to be edited are dirty", file=sys.stderr)
        print(st.stdout, file=sys.stderr)
        return 2
    os.makedirs(CTRL, exist_ok=True)

    # Authoritative run to the deliverable paths, twice for determinism.
    auth1 = gate(REFRESH, allow_drift=False, default_names=True)
    auth_report_hash_1 = sha256(AUTH_REPORT)
    auth_manifest_hash_1 = sha256(AUTH_MANIFEST)
    shutil.copy2(AUTH_REPORT, os.path.join(CTRL, "first-authoritative-report.json"))
    auth2 = gate(REFRESH, allow_drift=False, default_names=True)
    auth_report_hash_2 = sha256(AUTH_REPORT)
    auth_manifest_hash_2 = sha256(AUTH_MANIFEST)
    det_ok = (auth_report_hash_1 == auth_report_hash_2
              and auth_manifest_hash_1 == auth_manifest_hash_2)

    # Control inventories.
    build_control_inventory(os.path.join(CTRL, "inventory-post-enrolment.json"))
    drop_key = ("src/x509/v3_skid.rs", "s2i_skey_id")
    build_control_inventory(
        os.path.join(CTRL, "inventory-minus-s2i_skey_id.json"), drop=drop_key)

    # C1: omission control on the real source tree.
    c1_baseline = gate(os.path.join(CTRL, "out-c1"), inventory=os.path.join(
        CTRL, "inventory-post-enrolment.json"), tag="c1-baseline")
    backup = {}
    for path in (SKID, VLIB):
        backup[path] = run(["git", "show", f"HEAD:{path}"]).stdout
    probe = '''
// CONTROL C1: a reachable slot callback deliberately omitted from the inventory.
unsafe extern "C" fn i2s_fixture_probe(
    _meth: *const X509V3ExtMethod,
    _value: *mut c_void,
) -> *mut c_char {
    ptr::null_mut()
}

pub static ossl_v3_fixture_probe: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: 0,
    ext_flags: 0,
    it: None,
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: Some(i2s_fixture_probe),
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: None,
    r2i: None,
    usr_data: ptr::null_mut(),
};
'''
    with open(os.path.join(ROOT, SKID), "a", encoding="utf-8") as f:
        f.write(probe)
    vlib_text = open(os.path.join(ROOT, VLIB), "r", encoding="utf-8").read()
    anchor = "static STANDARD_EXTS: StandardExts = StandardExts([\n"
    assert anchor in vlib_text
    vlib_text = vlib_text.replace(
        anchor,
        anchor + "    &crate::x509::v3_skid::ossl_v3_fixture_probe,\n", 1)
    with open(os.path.join(ROOT, VLIB), "w", encoding="utf-8") as f:
        f.write(vlib_text)
    c1_added = gate(os.path.join(CTRL, "out-c1"), inventory=os.path.join(
        CTRL, "inventory-post-enrolment.json"), tag="c1-added")
    named = "src/x509/v3_skid.rs::i2s_fixture_probe"
    c1_named = named in missing_names(c1_added["report"])
    for path, text in backup.items():
        with open(os.path.join(ROOT, path), "w", encoding="utf-8") as f:
            f.write(text)
    restored = run(["git", "diff", "--quiet", "--", SKID, VLIB]).returncode == 0
    c1_restored = gate(os.path.join(CTRL, "out-c1"), inventory=os.path.join(
        CTRL, "inventory-post-enrolment.json"), tag="c1-restored")

    # C2: PROVEN_EXCLUDED is only accepted with a written assumption.
    inv_minus = os.path.join(CTRL, "inventory-minus-s2i_skey_id.json")
    ov_empty = os.path.join(CTRL, "overrides-excluded-empty.json")
    ov_ok = os.path.join(CTRL, "overrides-excluded-assumption.json")
    write_overrides(ov_empty, "src/x509/v3_skid.rs::s2i_skey_id",
                    "PROVEN_EXCLUDED", "")
    write_overrides(ov_ok, "src/x509/v3_skid.rs::s2i_skey_id",
                    "PROVEN_EXCLUDED",
                    "C2 control assumption: s2i_skey_id is treated as "
                    "unreachable for this control only; the assumption is "
                    "load-bearing and the gate must reject its absence.")
    c2_empty = gate(os.path.join(CTRL, "out-c2"), inventory=inv_minus,
                    overrides=ov_empty, tag="c2-empty")
    c2_ok = gate(os.path.join(CTRL, "out-c2"), inventory=inv_minus,
                 overrides=ov_ok, tag="c2-assumption")
    c2_empty_flagged = any(
        c["callback"] == "s2i_skey_id"
        for c in c2_empty["report"].get("excluded_without_assumption", []))

    # C3: UNRESOLVED always fails.
    ov_unres = os.path.join(CTRL, "overrides-unresolved.json")
    write_overrides(ov_unres, "src/x509/v3_skid.rs::s2i_skey_id",
                    "UNRESOLVED", "")
    c3 = gate(os.path.join(CTRL, "out-c3"), inventory=inv_minus,
              overrides=ov_unres, tag="c3-unresolved")
    c3_flagged = any(c["callback"] == "s2i_skey_id"
                     for c in c3["report"].get("unresolved", []))

    # C5: no false positives.
    auth_report = auth2["report"]
    fp = auth_report.get("false_positive_check", {})
    inv_matched = auth_report.get("inventory_matched_callbacks", 0)
    recon = auth_report.get("reconciliation", {})

    results = {
        "schema": "openssl-rs/campaign/safe-c33/callback-gate-controls/v1",
        "commands": {
            "C1_baseline": c1_baseline["cmd"],
            "C1_added": c1_added["cmd"],
            "C1_restored": c1_restored["cmd"],
            "C2_empty_assumption": c2_empty["cmd"],
            "C2_with_assumption": c2_ok["cmd"],
            "C3_unresolved": c3["cmd"],
            "C4_authoritative": auth2["cmd"],
        },
        "authoritative": {
            "pass": auth_report.get("pass"),
            "exit_code": auth_report.get("exit_code"),
            "missing_count": auth_report.get("missing_count"),
            "unresolved_count": auth_report.get("unresolved_count"),
            "enrolment_count": auth_report.get("enrolment", {}).get("count"),
            "inventory_matched_callbacks": inv_matched,
            "reconciliation": recon,
            "report_sha256": auth_report_hash_2,
            "manifest_sha256": auth_manifest_hash_2,
        },
        "determinism": {
            "report_sha256_run1": auth_report_hash_1,
            "report_sha256_run2": auth_report_hash_2,
            "manifest_sha256_run1": auth_manifest_hash_1,
            "manifest_sha256_run2": auth_manifest_hash_2,
            "identical": det_ok,
            "pass": det_ok,
        },
        "controls": {
            "C1": {
                "baseline_pass": c1_baseline["report"].get("pass"),
                "added_exit_code": c1_added["exit_code"],
                "added_named": c1_named,
                "restored_byte_identical": restored,
                "restored_pass": c1_restored["report"].get("pass"),
                "pass": (c1_baseline["report"].get("pass") is True
                         and c1_added["exit_code"] != 0 and c1_named
                         and restored and c1_restored["report"].get("pass") is True),
            },
            "C2": {
                "empty_assumption_exit_code": c2_empty["exit_code"],
                "empty_assumption_flagged": c2_empty_flagged,
                "with_assumption_exit_code": c2_ok["exit_code"],
                "with_assumption_pass": c2_ok["report"].get("pass"),
                "pass": (c2_empty["exit_code"] != 0 and c2_empty_flagged
                         and c2_ok["report"].get("pass") is True),
            },
            "C3": {
                "exit_code": c3["exit_code"],
                "flagged": c3_flagged,
                "pass": c3["exit_code"] != 0 and c3_flagged,
            },
            "C4": {"identical": det_ok, "pass": det_ok},
            "C5": {
                "inventory_matched_callbacks": inv_matched,
                "reported_missing": fp.get(
                    "inventory_matched_reported_missing"),
                "prefix_definitions_in_queue_inventory": recon.get(
                    "prefix_definitions_in_queue_inventory"),
                "pass": (fp.get("inventory_matched_reported_missing") == 0
                         and inv_matched >= 51),
            },
        },
    }
    with open(os.path.join(CTRL, "control-results.json"), "w",
              encoding="utf-8") as f:
        json.dump(results, f, indent=1, sort_keys=True)
        f.write("\n")
    print(json.dumps(results, indent=1, sort_keys=True))
    all_pass = all(v["pass"] for v in results["controls"].values())
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
