#!/usr/bin/env python3
"""Write court/freeze-b73/FREEZE-b73.json from the b73 artefacts.

Every asserted value is measured here: the candidate source head and the
source-tree digest come from the census and the working tree, each artefact
digest is recomputed from the file it names, the closure sections are read from
the two b73 receipts, and the git fields are read from the repository.  Nothing
is copied from an earlier freeze document, so a stale self-reference cannot
survive the copy.

The b73 candidate is the eng_list repair (source head is the census's
``identity.source_head``).  The instrument was edited after the two b73
closures were produced, so the freeze records the closure-bound instrument and
the current one separately; the closures must be re-run to bind the current
instrument (AGENTS.md section 22).
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CAMPAIGN = REPO / "forensics/memory-safety/campaign/safe-c33"
OUT = REPO / "court/freeze-b73/FREEZE-b73.json"
CENSUS = REPO / "court/freeze-b73/census-b73.json"
TOOL = REPO / "forensics/tools/consumer_closure.py"
LEDGER = REPO / "forensics/downstream/build-link-atlas.json"
REPINS = CAMPAIGN / "atlas-refresh/element7-b73-repin2.json"
INSTALL = "court/freeze-b73/install"

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


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, cwd=str(REPO)).strip()


def load(rel: str) -> dict:
    return json.loads((REPO / rel).read_text())


def cgroup(name: str):
    p = Path("/sys/fs/cgroup") / name
    return p.read_text().strip() if p.is_file() else None


def main() -> int:
    census = load("court/freeze-b73/census-b73.json")
    ssh = load("evidence/closure-ssh-b73.json")
    sshd = load("evidence/closure-sshd-b73.json")
    repins = (json.loads(REPINS.read_text()) if REPINS.is_file() else None)

    source_head = census["identity"]["source_head"]
    src_vs_frozen = git("diff", "--stat", source_head, "--", "src", "Cargo.toml",
                        "Cargo.lock", "build.rs")
    tree_digest = phase7_courts._source_tree_digest()
    tool_sha = sha256_file(TOOL)

    artefact_paths = {
        "libcrypto.so.3": f"{INSTALL}/lib/libcrypto.so.3",
        "libssl.so.3": f"{INSTALL}/lib/libssl.so.3",
        "libcrypto.a": f"{INSTALL}/lib/libcrypto.a",
        "libssl.a": f"{INSTALL}/lib/libssl.a",
        "legacy.so": f"{INSTALL}/lib/ossl-modules/legacy.so",
        "openssl": f"{INSTALL}/bin/openssl",
        "ssh": "court/tmp/openssh-closure/client-b73/openssh-9.9p1/ssh",
        "sshd": "court/tmp/openssh-closure/server-b73/openssh-9.9p1/sshd",
        "sshd_session": ("court/tmp/openssh-closure/server-b73/openssh-9.9p1/"
                         "sshd-session"),
    }
    artefacts = {name: art(rel) for name, rel in artefact_paths.items()}

    census_binaries = (census["identity"].get("binary") or {}).get("artefacts") or {}
    install_matches_census = {
        name: (census_binaries.get(name) or {}).get("sha256") == artefacts[name]["sha256"]
        for name in ("libcrypto.so.3", "libssl.so.3", "legacy.so", "openssl")
        if name in census_binaries
    }

    self_test = subprocess.run(
        [sys.executable, str(TOOL), "--self-test"], cwd=str(REPO),
        text=True, capture_output=True)
    py_compile = subprocess.run(
        [sys.executable, "-m", "py_compile",
         "forensics/tools/consumer_closure.py"], cwd=str(REPO),
        text=True, capture_output=True)
    self_test_text = (self_test.stdout or "") + (self_test.stderr or "")
    self_test_tail = [line for line in self_test_text.splitlines() if line.strip()][-3:]

    def element_7(doc: dict) -> dict:
        return doc["precision"]["predicate_element_7"]

    def closure(name: str, doc: dict) -> dict:
        rec = {
            "receipt": f"evidence/closure-{name}-b73.json",
            "sha256": sha256_file(REPO / f"evidence/closure-{name}-b73.json"),
            "bytes": (REPO / f"evidence/closure-{name}-b73.json").stat().st_size,
            "artifact": doc["artifact_identity"]["path"],
            "artifact_sha256": doc["artifact_identity"]["sha256"],
            "closure_bound_tool_sha256": doc["tool"]["sha256"],
            "counts": {k: v for k, v in doc["counts"].items()
                       if not isinstance(v, (dict, list))},
            "by_mechanism": doc["counts"]["by_mechanism"],
            "verdict": doc["verdict"],
            "refusals": doc["refusals"],
            "element_7": element_7(doc),
            "source_identity": {
                "repository_head": doc["source_identity"]["repository_head"],
                "inventory_source_head": doc["source_identity"]["inventory_source_head"],
            },
        }
        return rec

    # The ledger row the closure's ledger join reads.  Record what it carries
    # and what this freeze proves; the generator never edits the ledger.
    ledger = json.loads(LEDGER.read_text())
    body = ledger.get("body") or ledger
    row = next((r for r in body.get("runs") or []
                if r.get("family_id") == "family:openssh"
                and r.get("subject") == "candidate"), None)
    ledger_binding = {
        "source": "forensics/downstream/build-link-atlas.json",
        "lookup": "body.runs[family_id=family:openssh, subject=candidate]",
        "run_id": (row or {}).get("run_id"),
        "artifact_rel": ((row or {}).get("linkage") or {}).get("artifact_rel"),
        "recorded_artifact_sha256": ((row or {}).get("linkage") or {}).get(
            "artifact_sha256"),
        "recorded_candidate_install_libcrypto_sha256": (
            body.get("candidate_identity") or {}).get("libcrypto_so_3_sha256"),
        "freeze_proven_artifact_sha256": artefacts["ssh"]["sha256"],
        "freeze_proven_install_libcrypto_sha256": artefacts["libcrypto.so.3"]["sha256"],
        "ssh_receipt_artifact_sha256": ssh["artifact_identity"]["sha256"],
        "sshd_receipt_artifact_sha256": sshd["artifact_identity"]["sha256"],
        "recorded_matches_freeze_proven_ssh": (
            ((row or {}).get("linkage") or {}).get("artifact_sha256")
            == artefacts["ssh"]["sha256"]),
        "note": ("the ledger row names artifact_rel='ssh'; one row cannot also "
                 "bind the sshd digest. The row is updated to the freeze-proven "
                 "ssh digest so the ssh closure's artifact_matches_this_build can "
                 "be a real comparison; sshd's binding is recorded as a residual "
                 "until the ledger join is per-artifact."),
    }

    element7 = {fam: element_7(d) for fam, d in (("ssh", ssh), ("sshd", sshd))}
    repin_summary = None
    if repins is not None:
        repin_summary = {
            "path": "atlas-refresh/element7-b73-repin2.json",
            "sha256": sha256_file(REPINS),
            "artifact_sha256": repins.get("artifact", {}).get("sha256"),
            "reconciliation": repins.get("reconciliation"),
            "class_counts": {k: {"b61_count": v.get("b61_count"),
                                 "b73_recovered": v.get("b73_recovered")}
                             for k, v in (repins.get("classes") or {}).items()},
        }

    safe_compatible_reason = (
        "consumer_closure.py never promotes: verdict.safe_compatible is a "
        "hard-coded False. Measured at this candidate: "
        + "; ".join(
            f"{fam} {d['counts']['DISCHARGED']}/"
            f"{d['counts']['reachable_production_obligations']} DISCHARGED, "
            f"{d['counts']['BLOCKED']} BLOCKED, "
            f"{d['counts']['UNKNOWN']} UNKNOWN, element 7 "
            f"{element7[fam]['status']} "
            f"({element7[fam]['target_bounded_unresolved_sites']} "
            f"target-bounded, {element7[fam]['contract_bounded_sites']} "
            "contract-bounded)"
            for fam, d in (("ssh", ssh), ("sshd", sshd)))
        + ". AGENTS.md section 7 additionally requires a discharged "
          "dependency closure, which this instrument does not establish.")

    doc = {
        "schema": "openssl-rs/campaign/safe-c33/freeze/v1",
        "candidate_tag": "b73",
        "generated_utc": subprocess.check_output(
            ["date", "-u", "+%FT%TZ"], text=True).strip(),
        "freeze_kind": "source-and-artefact freeze",
        "freeze_reason": (
            "S is the eng_list TOCTOU repair. The libcrypto/libssl install, the "
            "OpenSSH consumer binaries and the census were rebuilt at S; the "
            "element-7 re-pin record was regenerated against the b73 DSO."),
        "source": {
            "head": source_head,
            "head_subject": git("log", "-1", "--format=%s", source_head),
            "branch": census["identity"].get("branch"),
            "src_rs_files": census["identity"]["src_rs_files"],
            "crate_version": census["identity"]["crate_version"],
            "src_content_sha256": census["identity"]["src_content_sha256"],
            "src_content_hash_rule": census["identity"]["src_content_hash_rule"],
            "source_tree_digest": {
                "count": tree_digest["count"], "sha256": tree_digest["sha256"],
                "rule": ("sha256 over canonical JSON of sorted "
                         "[relpath,size,sha256] for src/, Cargo.toml, "
                         "Cargo.lock, build.rs "
                         "(forensics/tools/phase7_courts.py::_source_tree_digest)"),
            },
            "working_tree": {
                "repository_head": git("rev-parse", "HEAD"),
                "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
                "tracked_dirty": bool(git("status", "--porcelain",
                                          "--untracked-files=no")),
                "modified_paths": sorted(
                    line.split()[-1] for line in
                    git("status", "--porcelain", "--untracked-files=no").splitlines()),
            },
            "src_diff_vs_frozen_candidate": src_vs_frozen or None,
        },
        "candidate_identity": {
            "source_head": source_head,
            "tool_sha256": tool_sha,
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
            "sha256": tool_sha,
            "version": ssh["tool"].get("version"),
            "closure_bound_sha256": ssh["tool"]["sha256"],
            "changed_since_closures": tool_sha != ssh["tool"]["sha256"],
            "change_note": (
                "the two b73 closures were produced by "
                f"{ssh['tool']['sha256']}; this freeze is written after the "
                "element-7 re-pin and the mechanism-carry fix, so a re-run is "
                "required to bind the current instrument (AGENTS.md section 22)"),
            "inputs": {
                "census": art("court/freeze-b73/census-b73.json"),
                "state": art("forensics/memory-safety/campaign/safe-c33/state.json"),
                "campaign_status": art(
                    "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json"),
                "enrolment_blockers": art(
                    "forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                    "callback-enrolment-blockers.json"),
            },
        },
        "artefacts": {
            "install_prefix": INSTALL,
            "files": artefacts,
            "install_matches_census": install_matches_census,
            "all_install_artefacts_match_census": all(install_matches_census.values()),
            "resolved_libcrypto_sha256": artefacts["libcrypto.so.3"]["sha256"],
            "consumer_source": ("OpenSSH 9.9p1, relinked by "
                                "court/freeze-b73/build-openssh-b73.sh"),
            "note": ("each digest is recomputed from the file named in this "
                     "working tree; the comparison against the census's "
                     "binary artefact digests is recorded per file"),
        },
        "build": {
            "openssh_relink_script": art("court/freeze-b73/build-openssh-b73.sh"),
            "openssh_build_log": art("court/freeze-b73/build-openssh-b73.log"),
            "openssh_timings": art("court/freeze-b73/openssh-build-timings.json"),
            "build_log": art("court/freeze-b73/build-b73.log"),
            "census_script": art("court/freeze-b73/census-clippy-b73.sh"),
        },
        "census": {
            "path": "court/freeze-b73/census-b73.json",
            "sha256": sha256_file(CENSUS),
            "bytes": CENSUS.stat().st_size,
            "source_head": census["identity"]["source_head"],
            "delta_vs": census.get("delta_vs_previous", {}).get("previous"),
            "operation_counts": (census.get("contracts") or {}).get(
                "operation_counts"),
        },
        "closures": {
            "ssh": closure("ssh", ssh),
            "sshd": closure("sshd", sshd),
            "run_script": art("court/freeze-b73/run_closure_b73.sh"),
            "safe_compatible": False,
            "safe_compatible_reason": safe_compatible_reason,
        },
        "element7_repin": repin_summary,
        "ledger_binding": ledger_binding,
        "gates": {
            "closure_verdicts": {
                "ssh": ssh["verdict"]["state"],
                "sshd": sshd["verdict"]["state"],
            },
            "python_syntax": ("py_compile of the instrument: OK"
                              if py_compile.returncode == 0 else
                              f"py_compile of the instrument: FAILED "
                              f"(rc={py_compile.returncode})"),
            "self_test": {
                "returncode": self_test.returncode,
                "tail": self_test_tail,
            },
            "rust_source": "not run by this generator: no Rust source changed",
        },
        "oom": {
            "generator_run": {
                "cap_env": {k: os.environ.get(k) for k in (
                    "OPENSSL_RS_COURT_MEM", "OPENSSL_RS_COURT_MEMSWAP",
                    "OPENSSL_RS_COURT_DATA")},
                "cgroup_memory_max": cgroup("memory.max"),
                "cgroup_memory_events": cgroup("memory.events"),
            },
            "closure_runs": {
                "note": ("the b73 closure cap was set by the caller of "
                         "run_closure_b73.sh; the receipts do not record it and "
                         "it is not derivable here, so it is not asserted"),
            },
        },
        "not_run": [
            "no Rust source changed by this freeze; fmt/clippy/library tests "
            "belong to the source candidate and are unchanged",
            "the two b73 closures are bound to the older instrument and must be "
            "re-run after this freeze",
        ],
        "non_claims": [
            ("the closures named here are measurements of the candidate at S "
             "with the closure-bound instrument; they are not re-measured by "
             "this generator"),
            (f"{ssh['counts']['BLOCKED']} BLOCKED / {ssh['counts']['UNKNOWN']} "
             f"UNKNOWN (ssh) and {sshd['counts']['BLOCKED']} BLOCKED / "
             f"{sshd['counts']['UNKNOWN']} UNKNOWN (sshd) is a statement about "
             "this instrument's queue at this candidate, not a SAFE_COMPATIBLE "
             "promotion"),
            ("element 7 is reported exactly as the receipts measured it; the "
             "re-pin record is separate evidence about the instrument and is "
             "not substituted for a re-run"),
        ],
    }
    OUT.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"[b73-freeze] source head {source_head}")
    print(f"[b73-freeze] tool sha256 {tool_sha}")
    print(f"[b73-freeze] closure tool {ssh['tool']['sha256']} "
          f"(changed={doc['tool']['changed_since_closures']})")
    print(f"[b73-freeze] install matches census: "
          f"{doc['artefacts']['all_install_artefacts_match_census']}")
    print(f"[b73-freeze] self-test rc={self_test.returncode}")
    print(f"[b73-freeze] ledger recorded={ledger_binding['recorded_artifact_sha256']}")
    print(f"[b73-freeze] freeze-proven ssh={ledger_binding['freeze_proven_artifact_sha256']}")
    print(f"[b73-freeze] ledger matches freeze: "
          f"{ledger_binding['recorded_matches_freeze_proven_ssh']}")
    print(f"[b73-freeze] wrote {OUT.relative_to(REPO)}")
    print(f"[b73-freeze] sha256 {sha256_file(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
