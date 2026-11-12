#!/usr/bin/env python3
"""Write atlas-refresh/b61-candidate-freeze.json: the tool-only re-freeze.

The b61 batch changed exactly one build-relevant input,
``forensics/tools/consumer_closure.py`` (the ``declared_spans`` mechanism).  No
Rust source, no census and no artefact changed, so the source candidate S is
still ``b6f38f134`` while the *evidence identity* moves -- the instrument sha is
part of the identity (AGENTS.md section 22).

Everything below is measured from this working tree, never copied from the b58
freeze blindly: every artefact digest is recomputed and compared with the b58
record, the source-tree digests are recomputed, and the two closures are the
files this batch actually produced.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path("/work")
CAMPAIGN = REPO / "forensics/memory-safety/campaign/safe-c33"
OUT = CAMPAIGN / "atlas-refresh/b61-candidate-freeze.json"
B58_FREEZE = CAMPAIGN / "atlas-refresh/b58-candidate-freeze.json"
B60_RECEIPT = CAMPAIGN / "atlas-refresh/b60-free-lock-operations.json"
B60_SITES = CAMPAIGN / "atlas-refresh/b60-free-lock-operations-sites.json"
B60_GENERATOR = CAMPAIGN / "atlas-refresh/b60_generate.py"
CENSUS = REPO / "court/freeze-b58/census-b58.json"
S = "b6f38f13456b79ecd94b1088c835c3da92bc942a"

sys.path.insert(0, str(REPO / "forensics/tools"))
import phase7_courts  # noqa: E402


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def art(rel: str) -> dict:
    p = REPO / rel
    return {"path": rel, "sha256": sha256_file(p), "size": p.stat().st_size}


def git(*a: str) -> str:
    return subprocess.check_output(["git", *a], text=True, cwd=str(REPO)).strip()


def movement(before: dict, after: dict) -> dict:
    A = {o["id"]: o for o in before["obligations"]}
    B = {o["id"]: o for o in after["obligations"]}
    lost = sorted(i for i in A if A[i]["status"] == "DISCHARGED"
                  and B.get(i, {}).get("status") != "DISCHARGED")
    changed = sorted(i for i in A if i in B
                     and A[i]["status"] == "DISCHARGED"
                     and B[i]["status"] == "DISCHARGED"
                     and A[i].get("discharge_boundary_id")
                     != B[i].get("discharge_boundary_id"))
    gained = sorted(i for i in A if A[i]["status"] != "DISCHARGED"
                    and B.get(i, {}).get("status") == "DISCHARGED")
    return {
        "identities_before": len(A),
        "identities_after": len(B),
        "identity_sets_equal": set(A) == set(B),
        "stable_identity_sets_equal": ({o["stable_id"] for o in before["obligations"]}
                                       == {o["stable_id"]
                                           for o in after["obligations"]}),
        "discharged_to_blocked": lost,
        "discharged_boundary_changed": changed,
        "blocked_to_discharged": gained,
        "rows": [{"id": i, "stable_id": A[i]["stable_id"],
                  "file": A[i]["file"], "item": A[i]["item"],
                  "previous_status": A[i]["status"], "status": B[i]["status"],
                  "discharge_receipt": B[i].get("discharge_receipt"),
                  "discharge_boundary_id": B[i].get("discharge_boundary_id"),
                  "binding": (B[i].get("span_discharge") or {}).get("binding"),
                  "definitions": (B[i].get("span_discharge") or {}).get(
                      "definition_count")}
                 for i in gained],
    }


def main() -> int:
    census = json.loads(CENSUS.read_text())
    old = json.loads(B58_FREEZE.read_text())
    receipt = json.loads(B60_RECEIPT.read_text())
    ssh = json.loads((REPO / "evidence/closure-ssh-b61.json").read_text())
    sshd = json.loads((REPO / "evidence/closure-sshd-b61.json").read_text())
    prev = {f: json.loads((REPO / f"evidence/closure-{f}-b59.json").read_text())
            for f in ("ssh", "sshd")}
    sha = sha256_file(REPO / "forensics/tools/consumer_closure.py")

    digest = phase7_courts._source_tree_digest()
    src_vs_s = git("diff", "--stat", S, "--", "src", "Cargo.toml", "Cargo.lock",
                   "build.rs").strip()

    artefact_paths = {
        "libcrypto.so.3": "court/freeze-b58/install/lib/libcrypto.so.3",
        "libssl.so.3": "court/freeze-b58/install/lib/libssl.so.3",
        "libcrypto.a": "court/freeze-b58/install/lib/libcrypto.a",
        "libssl.a": "court/freeze-b58/install/lib/libssl.a",
        "legacy.so": "court/freeze-b58/install/lib/ossl-modules/legacy.so",
        "openssl": "court/freeze-b58/install/bin/openssl",
        "ssh": "court/tmp/openssh-closure/client-b58/openssh-9.9p1/ssh",
        "sshd": "court/tmp/openssh-closure/server-b58/openssh-9.9p1/sshd",
        "sshd_session": "court/tmp/openssh-closure/server-b58/openssh-9.9p1/sshd-session",
    }
    artefacts, artefact_checks = {}, {}
    for name, rel in artefact_paths.items():
        now = art(rel)
        was = (old.get("artefacts") or {}).get(name)
        same = bool(was) and was.get("sha256") == now["sha256"]
        artefact_checks[name] = {
            "sha256": now["sha256"],
            "matches_b58_freeze": same,
            "b58_recorded_sha256": (was or {}).get("sha256"),
        }
        artefacts[name] = now

    controls = subprocess.run(
        [sys.executable, str(B60_GENERATOR), "--controls"],
        cwd=str(REPO), text=True, capture_output=True)
    self_test = subprocess.run(
        [sys.executable, str(REPO / "forensics/tools/consumer_closure.py"),
         "--self-test"], cwd=str(REPO), text=True, capture_output=True)

    def e7(doc: dict) -> dict:
        return doc["precision"]["predicate_element_7"]

    def closure(name: str, doc: dict) -> dict:
        return {
            "receipt": f"evidence/closure-{name}-b61.json",
            "sha256": sha256_file(REPO / f"evidence/closure-{name}-b61.json"),
            "bytes": (REPO / f"evidence/closure-{name}-b61.json").stat().st_size,
            "artifact": doc["artifact_identity"]["path"],
            "artifact_sha256": doc["artifact_identity"]["sha256"],
            "tool_sha256": doc["tool"]["sha256"],
            "counts": {k: v for k, v in doc["counts"].items()
                       if not isinstance(v, (dict, list))},
            "by_mechanism": doc["counts"]["by_mechanism"],
            "verdict": doc["verdict"],
            "refusals": doc["refusals"],
            "element_7": e7(doc),
            "movement_vs_b59": movement(prev[name], doc),
        }

    def run_log(fam: str) -> dict:
        """The `run_closure_b61.sh` output for this family, if it was retained.

        The closure receipts carry no wall-clock or return-code field, so those
        figures are only derivable from the captured run log.  When the log is
        absent the value is reported as unknown, never inferred.
        """
        log = REPO / f"court/freeze-b61/b61-{fam}.log"
        info = {"path": str(log.relative_to(REPO)), "present": log.is_file(),
                "wall_seconds": None, "rc": None}
        if not info["present"]:
            info["note"] = ("run log absent: wall seconds and return code are "
                            "not derivable from the closure receipt")
            return info
        for line in log.read_text(errors="replace").splitlines():
            key, _, value = line.partition("=")
            if key == "WALL_SECONDS" and value.strip().isdigit():
                info["wall_seconds"] = int(value.strip())
            elif key == "RC" and value.strip().lstrip("-").isdigit():
                info["rc"] = int(value.strip())
        if info["wall_seconds"] is None:
            info["note"] = "log present but carries no WALL_SECONDS= line"
        return info

    logs = {fam: run_log(fam) for fam in ("ssh", "sshd")}

    cgroup = Path("/sys/fs/cgroup")

    def cg(name: str) -> str | None:
        p = cgroup / name
        return p.read_text().strip() if p.is_file() else None

    oom_events = {
        parts[0]: int(parts[1])
        for parts in (line.split() for line in (cg("memory.events") or "").splitlines())
        if len(parts) == 2 and parts[1].isdigit()}
    generator_run = {
        "cap_env": {k: os.environ.get(k) for k in (
            "OPENSSL_RS_COURT_MEM", "OPENSSL_RS_COURT_MEMSWAP",
            "OPENSSL_RS_COURT_DATA")},
        "cgroup_memory_max": cg("memory.max"),
        "cgroup_memory_events": oom_events,
        "note": ("the cap this generator actually ran under; the closure runs "
                 "themselves were executed earlier and their cap was not "
                 "captured"),
    }

    self_test_output = (self_test.stderr or "") + (self_test.stdout or "")
    self_test_failure = (
        next((line for line in reversed(self_test_output.splitlines())
              if line.strip()), None))
    if self_test.returncode == 0:
        self_test_note = "the instrument's own --self-test exited 0"
    elif "5267120" in self_test_output:
        self_test_note = (
            "the instrument's own --self-test fails with the pre-existing "
            "fixture/pin mismatch b59 reported (KeyError 5267120 in "
            "_pbe_outparam_self_test -> _insns_copy); the declared-span "
            "self-test cases execute before the failing call and raise "
            "nothing, but their pass/fail list is never printed because the "
            "process aborts later. The observable control is the --controls "
            "run above. Not fixed by this batch.")
    else:
        self_test_note = (
            "the instrument's own --self-test exited non-zero; its last "
            "output line is recorded in `failure`. The observable control is "
            "the --controls run above.")
    py_compile = subprocess.run(
        [sys.executable, "-m", "py_compile",
         "forensics/tools/consumer_closure.py"],
        cwd=str(REPO), text=True, capture_output=True)
    controls_gate = ("b60-C1..C5 via the real adjudicate() path: "
                     + ("PASS" if controls.returncode == 0
                        else f"FAILED (rc={controls.returncode})"))
    element_7 = {fam: e7(d) for fam, d in (("ssh", ssh), ("sshd", sshd))}
    safe_compatible_reason = (
        "consumer_closure.py never promotes: verdict.safe_compatible is a "
        "hard-coded False. Measured at this candidate: "
        + "; ".join(
            f"{fam} {d['counts']['DISCHARGED']}/"
            f"{d['counts']['reachable_production_obligations']} DISCHARGED, "
            f"{d['counts']['BLOCKED']} BLOCKED, "
            f"{d['counts']['UNKNOWN']} UNKNOWN, element 7 "
            f"{element_7[fam]['status']} "
            f"({element_7[fam]['target_bounded_unresolved_sites']} "
            f"target-bounded, {element_7[fam]['contract_bounded_sites']} "
            "contract-bounded)"
            for fam, d in (("ssh", ssh), ("sshd", sshd)))
        + ". AGENTS.md section 7 additionally requires a discharged "
          "dependency closure, which this instrument does not establish.")

    doc = {
        "schema": "openssl-rs/campaign/safe-c33/freeze/v1",
        "candidate_tag": "b61",
        "generated_utc": subprocess.check_output(
            ["date", "-u", "+%FT%TZ"], text=True).strip(),
        "freeze_kind": "tool-only re-freeze",
        "freeze_reason": (
            "forensics/tools/consumer_closure.py changed (declared_spans, the "
            "declared-definition-set resolution rule). The tool is "
            "build-relevant evidence, so the candidate identity moves even though "
            "no Rust source, census or artefact did."),
        "source": {
            "head": S,
            "head_subject": git("log", "-1", "--format=%s", S),
            "source_unchanged_since_b58": not src_vs_s,
            "src_diff_vs_S": src_vs_s or None,
            "crate_version": census["identity"]["crate_version"],
            "src_rs_files": census["identity"]["src_rs_files"],
            "src_content_sha256": census["identity"]["src_content_sha256"],
            "src_content_hash_rule": census["identity"]["src_content_hash_rule"],
            "source_tree_digest": {
                "count": digest["count"], "sha256": digest["sha256"],
                "matches_b58_freeze": digest["sha256"] == (
                    ((old.get("source") or {}).get("source_tree_digest")
                     or {}).get("sha256")),
                "rule": ("sha256 over canonical JSON of sorted "
                         "[relpath,size,sha256] for src/, Cargo.toml, "
                         "Cargo.lock, build.rs "
                         "(forensics/tools/phase7_courts.py::_source_tree_digest)"),
            },
        },
        "candidate_identity": {
            "source_head": S,
            "tool_sha256": sha,
            "census_sha256": sha256_file(CENSUS),
            "libcrypto_so_3_sha256": artefacts["libcrypto.so.3"]["sha256"],
            "libssl_so_3_sha256": artefacts["libssl.so.3"]["sha256"],
            "ssh_sha256": artefacts["ssh"]["sha256"],
            "sshd_sha256": artefacts["sshd"]["sha256"],
            "rule": ("source head + instrument sha + census sha + measured "
                     "artefact digests; a change to any one of them is a new "
                     "candidate"),
        },
        "tool": {
            "path": "forensics/tools/consumer_closure.py",
            "sha256": sha,
            "version": ssh["tool"]["version"],
            "sha256_at_b58_freeze_record": (old.get("tool") or {}).get("sha256"),
            "changed_since_b58_freeze_record": (
                sha != (old.get("tool") or {}).get("sha256")),
            "change_scope": (
                "additive: load_boundaries carries declared_spans; "
                "resolve_declared_spans + _declared_spans_validated implement the "
                "set rule; adjudicate uses them and records the declared "
                "definitions in span_discharge; self-test cases added. No "
                "existing classification, threshold or accepted path changed."),
            "receipt_generator": art(
                "forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                "b60_generate.py"),
            "receipt": art(
                "forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                "b60-free-lock-operations.json"),
            "loader_projection": art(
                "forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                "b60-free-lock-operations-sites.json"),
            "declaration_note": (
                "b61 declares no new boundary receipt. The b60 free_lock "
                "generator, receipt and loader projection are the declarations "
                "still in force, and the digests above are those b60 files as "
                "they exist on disk"),
            "version_note": (
                "version 5 -> 6 marks the added resolution rule; the sha is the "
                "binding identity and every receipt below carries both"),
            "inputs": {
                "ledger": art("forensics/memory-safety/campaign/safe-c33/"
                              "CAMPAIGN-STATUS.json"),
                "state": art("forensics/memory-safety/campaign/safe-c33/state.json"),
                "enrolment_blockers": dict(
                    art("forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                        "callback-enrolment-blockers.json"),
                    note=("an uncommitted working-tree input: the b59 admission-"
                          "coordinate correction (sha 46d1e5fc..., also recorded "
                          "in atlas-refresh/b59-close18.json). It is what the two "
                          "closures above actually ran with; recorded so the "
                          "identity is not silent about a working-tree input")),
            },
        },
        "artefacts": {
            "install_prefix": "court/freeze-b58/install",
            "artefact_checks": artefact_checks,
            "all_artefacts_match_b58": all(v["matches_b58_freeze"]
                                           for v in artefact_checks.values()),
            "files": artefacts,
            "resolved_libcrypto_sha256": artefacts["libcrypto.so.3"]["sha256"],
            "consumer_source": "OpenSSH 9.9p1, pinned tarball "
                               "court/tmp/openssh-closure/openssh-9.9p1.tar.gz",
            "note": ("not rebuilt by this batch. Each digest was recomputed here "
                     "and compared with the b58 record; the comparison result is "
                     "recorded per artefact"),
        },
        "census": {
            "path": "court/freeze-b58/census-b58.json",
            "sha256": sha256_file(CENSUS),
            "bytes": CENSUS.stat().st_size,
            "source_head": census["identity"]["source_head"],
            "matches_b58_freeze": sha256_file(CENSUS) == (
                ((old.get("census") or {}).get("sha256"))),
            "note": "unchanged: the census is source-derived and the source did not move",
        },
        "closures": {
            "ssh": closure("ssh", ssh),
            "sshd": closure("sshd", sshd),
            "run_script": art("court/freeze-b61/run_closure_b61.sh"),
            "same_flags_as_b58": True,
            "safe_compatible": False,
            "safe_compatible_reason": safe_compatible_reason,
        },
        "bound_operation": {
            "receipt": "atlas-refresh/b60-free-lock-operations.json",
            "loader_projection": "atlas-refresh/b60-free-lock-operations-sites.json",
            "item": "free_lock",
            "file": "src/runtime/thread.rs",
            "definition_count": 2,
            "set_sha256": receipt["bound_span_set"]["set_sha256"],
            "definitions": [
                {"start_line": d["start_line"], "end_line": d["end_line"],
                 "def_line": d["def_line"], "span_sha256": d["span_sha256"],
                 "cfg_predicate_sha256": hashlib.sha256(
                     d["cfg"].encode("utf-8")).hexdigest(),
                 "cfg_predicate": ("verbatim in the receipt "
                                   "(bound_span_set.definitions[].cfg); the "
                                   "digest above is over that exact text")}
                for d in receipt["bound_span_set"]["definitions"]],
            "ledger_verdict_source": "boundary-sweep-B56 (rows)",
            "field_precedence": (
                "when a boundary row carries both span_sha256 and declared_spans, "
                "the declared set is the acceptance evidence and span_sha256 is "
                "not consulted (there is no single span to compare for a "
                "multiply-defined item). No row in the corpus carries both; the "
                "precedence is stated so it is not an implicit assumption"),
            "note": ("the definitions and hashes are inside the receipt; this is "
                     "the summary a reader needs to re-run the resolution"),
        },
        "controls_run": {
            "command": ("python3 forensics/memory-safety/campaign/safe-c33/"
                        "atlas-refresh/b60_generate.py --controls"),
            "returncode": controls.returncode,
            "stdout": controls.stdout.strip().splitlines(),
            "stderr_tail": controls.stderr.strip().splitlines()[-5:],
        },
        "self_test": {
            "command": "python3 forensics/tools/consumer_closure.py --self-test",
            "returncode": self_test.returncode,
            "observed": "PASS" if self_test.returncode == 0 else "FAILED",
            "failure": self_test_failure,
            "note": self_test_note,
        },
        "identity_findings": [
            {
                "finding": ("the b58 freeze receipt "
                            "atlas-refresh/b58-candidate-freeze.json records tool "
                            "sha 8f0379bb... while the closures it names were "
                            "produced by tool e2e4eed1..., and its closure "
                            "digests (e8932799... / 209e6f55...) and counts "
                            "(175 DISCHARGED / 148 BLOCKED, 78 target-bounded) do "
                            "not match the files on disk (912fcd82... / "
                            "3c49c224..., 305/18, 32 target-bounded)"),
                "action": ("recorded here, not repaired: rewriting a past "
                           "freeze is an adjudication decision, not a "
                           "measurement. b61 binds every digest to the file this "
                           "batch actually produced"),
                "impact": ("none on b61: its source, census and artefacts are "
                           "independently recomputed and compared above"),
            }
        ],
        "oom": {
            "closure_runs": {
                "cap": {
                    "value": None,
                    "note": ("the b61 closure runs were executed before this "
                             "generator; their cap was not captured by "
                             "run_closure_b61.sh and is not recorded in either "
                             "receipt, so it is unknown rather than guessed")},
                "available_gib_before": {
                    "value": None,
                    "note": ("not measured when the b61 closures ran and not "
                             "derivable from the closure receipts")},
                "closure_rlimit_data_kib": {
                    "value": None,
                    "note": ("run_closure_b61.sh sets no RLIMIT_DATA and the "
                             "receipts do not record one")},
                "wall_seconds": {fam: logs[fam]["wall_seconds"]
                                 for fam in ("ssh", "sshd")},
                "returncodes": {fam: logs[fam]["rc"]
                                for fam in ("ssh", "sshd")},
                "wall_seconds_source": {fam: logs[fam]["path"]
                                        for fam in ("ssh", "sshd")},
                "wall_seconds_derivation": (
                    "read from WALL_SECONDS= / RC= in the retained "
                    "run_closure_b61.sh output named by "
                    "wall_seconds_source; court/ is git-ignored, so those "
                    "logs are local run artefacts and not part of the "
                    "evidence commit. When a log is absent the value is null "
                    "rather than inferred"),
                "one_heavy_command_at_a_time": True,
            },
            "generator_run": generator_run,
        },
        "gates": {
            "rust_source": "not run: no Rust source changed",
            "fmt_clippy": "not run: no Rust source changed",
            "closure_runs": {
                "ssh": f"{ssh['verdict']['state']}, {len(ssh['refusals'])} refusals",
                "sshd": f"{sshd['verdict']['state']}, {len(sshd['refusals'])} refusals",
            },
            "python_syntax": ("py_compile of the instrument: OK"
                              if py_compile.returncode == 0 else
                              f"py_compile of the instrument: FAILED "
                              f"(rc={py_compile.returncode})"),
            "declared_span_controls": controls_gate,
            "element_7": element_7,
        },
        "counts": {
            "ssh": {"obligations": ssh["counts"]["reachable_production_obligations"],
                    "DISCHARGED": ssh["counts"]["DISCHARGED"],
                    "BLOCKED": ssh["counts"]["BLOCKED"],
                    "UNKNOWN": ssh["counts"]["UNKNOWN"]},
            "sshd": {"obligations": sshd["counts"]["reachable_production_obligations"],
                     "DISCHARGED": sshd["counts"]["DISCHARGED"],
                     "BLOCKED": sshd["counts"]["BLOCKED"],
                     "UNKNOWN": sshd["counts"]["UNKNOWN"]},
        },
        "not_run": [
            "cargo fmt / clippy / library tests: no Rust source changed, and the "
            "instrument is Python; the Rust court is unchanged since b58",
            "BOUNDARY / SEAL evidence for RUNTIME_CONCURRENCY: not claimed here",
        ],
        "non_claims": [
            ("The instrument change is additive and exercises only the "
             "declared-definition-set path; no existing classification, threshold "
             "or accepted path was altered. That a pre-existing discharge still "
             "binds at b61 is shown by the per-id movement lists, not asserted."),
            (f"{ssh['counts']['BLOCKED']} BLOCKED / "
             f"{ssh['counts']['UNKNOWN']} UNKNOWN (ssh) and "
             f"{sshd['counts']['BLOCKED']} BLOCKED / "
             f"{sshd['counts']['UNKNOWN']} UNKNOWN (sshd) is a statement "
             "about this instrument's queue at this candidate, not a "
             "SAFE_COMPATIBLE promotion."),
            ("B56's off-profile (`Box`) definition is verified by inspection only; "
             "the verdict is transcribed, not re-earned."),
        ],
    }
    OUT.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"[b61-freeze] tool sha256 {sha}")
    print(f"[b61-freeze] artefacts match b58: {doc['artefacts']['all_artefacts_match_b58']}")
    print(f"[b61-freeze] source tree matches b58: "
          f"{doc['source']['source_tree_digest']['matches_b58_freeze']}")
    print(f"[b61-freeze] controls rc={controls.returncode} "
          f"self-test rc={self_test.returncode}")
    for fam in ("ssh", "sshd"):
        c = doc["closures"][fam]
        print(f"[b61-freeze] {fam}: {c['counts']['DISCHARGED']}/"
              f"{c['counts']['reachable_production_obligations']} discharged, "
              f"{c['counts']['BLOCKED']} blocked, refusals={len(c['refusals'])}, "
              f"e7={c['element_7']['status']} "
              f"target_bounded={c['element_7']['target_bounded_unresolved_sites']}")
        m = c["movement_vs_b59"]
        print(f"[b61-freeze] {fam} movement: lost={m['discharged_to_blocked']} "
              f"boundary_changed={m['discharged_boundary_changed']} "
              f"gained={m['blocked_to_discharged']}")
    print(f"[b61-freeze] wrote {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
