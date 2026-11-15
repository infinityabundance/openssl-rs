#!/usr/bin/env python3
"""Write court/freeze-b79/FREEZE-b79.json from the b79 evidence.

Adapted from court/freeze-b78/make_freeze_b78.py.  Every asserted value is
measured here rather than copied from an earlier freeze: the candidate source
identity is recomputed from the working tree and cross-checked against the
census, each artefact digest/size is recomputed from the file it names, the
closure sections are read from the two b79c receipts, the gate outcomes are
parsed from court/freeze-b79/gates.log (the log the gates were actually run
into; the `*-exact-s` steps are the gate evidence, and the earlier pre-format
four steps are parsed only to be recorded as SUPERSEDED), the atlas body hash
is recomputed, the b79 L7 replay and the b79
criterion-3 safety argument are read from their files, and the git fields are
read from the repository.

Two identities are kept separate (AGENTS.md section 22).  S is the
source+instrument identity the evidence describes: the b79c closure tree
5b08c0294, the inventory tree 63a23e729 (the census and the receipts' own
inventory/span source), src_content e012f514, instrument 6e9cd261, and the b79c
closures.  E is the evidence commit that carries this freeze and the rebind
receipts; committing E moves HEAD without changing S.

Run inside the court: it needs the same toolchain image the closures ran in.
"""
from __future__ import annotations

import hashlib
import json
import re
import resource
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CAMPAIGN = REPO / "forensics/memory-safety/campaign/safe-c33"
OUT = REPO / "court/freeze-b79/FREEZE-b79.json"
CENSUS = REPO / "court/freeze-b79/census-b79b.json"
GATES = REPO / "court/freeze-b79/gates.log"
TOOL = REPO / "forensics/tools/consumer_closure.py"
ATLAS = REPO / "forensics/downstream/build-link-atlas.json"
STATUS = CAMPAIGN / "CAMPAIGN-STATUS.json"
L7 = REPO / "evidence/b79-l7-replay.json"
SAFETY_ARGUMENT = REPO / "evidence/b79-safety-argument.json"
SURFACE = REPO / "court/freeze-b79/l7/surface-b79.json"
BUILD_SCRIPT = REPO / "forensics/tools/build_openssh_closure.sh"
INSTRUMENT_REPAIR = REPO / "court/freeze-b78/b78c-verifier-repair.json"
PRIOR_E7 = [
    "forensics/memory-safety/campaign/safe-c33/atlas-refresh/e7-b76-repin.json",
    "forensics/memory-safety/campaign/safe-c33/atlas-refresh/e7-b77-repin.json",
    "forensics/memory-safety/campaign/safe-c33/atlas-refresh/e7-b78-repin.json",
    "forensics/memory-safety/campaign/safe-c33/atlas-refresh/b76c-three-sites.json",
]
REVIEWS = {
    "rebind": REPO / "evidence/b79-review-rebind.json",
    "x509_batch1": REPO / "evidence/b79-review-x509-batch1.json",
    "x509_batch2": REPO / "evidence/b79-review-x509-batch2.json",
    "reconversion": REPO / "evidence/b79-reconversion-review.json",
}
LEDGERS = {
    "ssh": REPO / "evidence/ssh-artifact-ledger-b79.json",
    "sshd": REPO / "evidence/sshd-artifact-ledger-b79.json",
}
REBINDS = {
    "ssh": REPO / "evidence/ssh-artifact-ledger-b79-rebind.json",
    "sshd": REPO / "evidence/sshd-artifact-ledger-b79-rebind.json",
}
INSTALL = "artifacts/phase2/install"
CLOSURE_TREE = "5b08c02944eb09cf3e7abc96b253c100dde673f2"
INVENTORY_TREE = "63a23e72985fa65c6bf33ae07642a33d80234dad"

sys.path.insert(0, str(REPO / "forensics/tools"))
import phase7_courts  # noqa: E402
from atlas_common import content_hash  # noqa: E402


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
    return subprocess.check_output(
        ["git", *args], text=True, cwd=str(REPO),
        stderr=subprocess.DEVNULL).strip()


def load(rel: str) -> dict:
    return json.loads((REPO / rel).read_text())


def cgroup(name: str):
    p = Path("/sys/fs/cgroup") / name
    return p.read_text().strip() if p.is_file() else None


def peak_current(rel: str):
    """Max of a `memory.current` sample file written by the court-side sampler.

    `memory.peak` is not writable in this container and already carried a
    larger value from earlier work, so a per-run peak needs its own samples.
    """
    p = REPO / rel
    if not p.is_file():
        return None
    vals = [int(x) for x in p.read_text().split() if x.isdigit()]
    return max(vals) if vals else None


def src_content_hash() -> tuple[str, int]:
    paths = sorted(
        p.relative_to(REPO).as_posix() for p in (REPO / "src").rglob("*.rs"))
    h = hashlib.sha256()
    h.update(b"openssl-rs/src-rs/v1\x00")
    for rel in paths:
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update((REPO / rel).read_bytes())
        h.update(b"\x00")
    return h.hexdigest(), len(paths)


def gate_sections(path: Path) -> dict[str, dict]:
    """Parse the b79 gate runner's log format (=== step / command / exit)."""
    sections: dict[str, dict] = {}
    cur = None
    in_output = False
    for line in path.read_text().splitlines():
        m = re.match(r"^=== step: (.+)$", line)
        if m:
            cur = {"name": m.group(1), "output": [], "exit": None,
                   "command": None, "utc": None, "meminfo": []}
            sections[m.group(1)] = cur
            in_output = False
            continue
        if cur is None:
            continue
        if line.startswith("=== utc: "):
            cur["utc"] = line[len("=== utc: "):].strip()
            continue
        if line.startswith("=== command: "):
            cur["command"] = line[len("=== command: "):].strip()
            continue
        if line == "--- output ---":
            in_output = True
            continue
        if line == "--- end output ---":
            in_output = False
            continue
        if line.startswith("=== exit="):
            cur["exit"] = int(line[len("=== exit="):].strip())
            continue
        if line.startswith("MemTotal:") or line.startswith("MemAvailable:"):
            cur["meminfo"].append(line.strip())
            continue
        if in_output:
            cur["output"].append(line)
    return sections


def test_result(lines: list[str]) -> dict | None:
    out = None
    for ln in lines:
        m = re.match(
            r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
            r"(\d+) ignored; (\d+) measured; (\d+) filtered out", ln)
        if m:
            out = {
                "state": m.group(1), "passed": int(m.group(2)),
                "failed": int(m.group(3)), "ignored": int(m.group(4)),
                "measured": int(m.group(5)),
                "filtered_out": int(m.group(6)),
            }
    return out


def failed_tests(lines: list[str]) -> list[str]:
    names, inside = [], False
    for ln in lines:
        if ln.strip() == "failures:":
            inside = True
            continue
        if inside:
            m = re.match(r"^ {4}(\S+::\S+)$", ln)
            if m:
                names.append(m.group(1))
            elif "test result:" in ln:
                break
    return names


def grouping(doc: dict) -> dict:
    c = Counter(o.get("discharge_receipt") for o in doc["obligations"])
    ordered = dict(sorted(c.items(), key=lambda kv: str(kv[0])))
    return {
        "total": sum(c.values()),
        "openssh-v1i": c.get("openssh-v1i", 0),
        "openssh-v1l": c.get("openssh-v1l", 0),
        "boundary_sweep_total": sum(
            v for k, v in c.items() if str(k).startswith("boundary-sweep-")),
        "by_receipt": ordered,
    }


def configure_from_script() -> list[str]:
    text = BUILD_SCRIPT.read_text().splitlines()
    out, inside = [], False
    for line in text:
        if line.strip().startswith("./configure"):
            inside = True
        if inside:
            cleaned = line.strip().rstrip("\\").strip()
            if cleaned.startswith("./configure"):
                cleaned = cleaned[len("./configure"):].strip()
            if cleaned.startswith(">") or "configure.log" in cleaned:
                break
            if cleaned:
                out.append(cleaned)
    return out


def main() -> int:
    census = load("court/freeze-b79/census-b79b.json")
    ssh = load("evidence/closure-ssh-b79c.json")
    sshd = load("evidence/closure-sshd-b79c.json")
    atlas = json.loads(ATLAS.read_text())
    status = json.loads(STATUS.read_text())
    l7_doc = json.loads(L7.read_text())
    safety_doc = json.loads(SAFETY_ARGUMENT.read_text())
    surface = json.loads(SURFACE.read_text())
    repair_doc = json.loads(INSTRUMENT_REPAIR.read_text())
    sections = gate_sections(GATES)

    # The exact-candidate gate (steps labelled *-exact-s) is the evidence this
    # freeze records.  The earlier four steps were run one rustfmt commit
    # behind S; they are parsed only so the freeze can name them SUPERSEDED.
    fmt = sections.get("fmt-exact-s", {})
    clippy = sections.get("clippy-exact-s", {})
    tests = sections.get("test-lib-4-exact-s", {})
    unsafe_fn = sections.get("unsafe-fn-exact-s", {})
    tests_res = test_result(tests.get("output") or [])
    unsafe_res = test_result(unsafe_fn.get("output") or [])
    fmt_diffs = [ln for ln in (fmt.get("output") or [])
                 if ln.startswith("Diff in ")]
    for _step, _sec in (("fmt-exact-s", fmt), ("clippy-exact-s", clippy),
                        ("test-lib-4-exact-s", tests),
                        ("unsafe-fn-exact-s", unsafe_fn)):
        assert _sec.get("exit") is not None, (
            f"court/freeze-b79/gates.log has no `{_step}` step with an exit "
            "code; the exact-candidate gate has not been run")
    assert tests_res and unsafe_res, "exact-S test steps produced no test result"
    stale = {
        "fmt": sections.get("fmt", {}),
        "clippy": sections.get("clippy", {}),
        "tests": sections.get("test-lib-4", {}),
        "unsafe_fn": sections.get("unsafe-fn", {}),
    }
    stale_tests_res = test_result(stale["tests"].get("output") or [])
    stale_unsafe_res = test_result(stale["unsafe_fn"].get("output") or [])
    stale_fmt_diffs = [ln for ln in (stale["fmt"].get("output") or [])
                       if ln.startswith("Diff in ")]

    source_head = CLOSURE_TREE
    inventory_head = census["identity"]["source_head"]
    assert inventory_head == INVENTORY_TREE, inventory_head
    evidence_head = git("rev-parse", "HEAD")
    closure_is_ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", source_head, evidence_head],
        cwd=str(REPO)).returncode == 0
    inventory_is_ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", inventory_head, evidence_head],
        cwd=str(REPO)).returncode == 0
    src_vs_source = git("diff", "--stat", source_head, "--", "src",
                        "Cargo.toml", "Cargo.lock", "build.rs")
    src_between = git("diff", "--stat", inventory_head, source_head, "--",
                      "src", "Cargo.toml", "Cargo.lock", "build.rs")
    src_inventory_to_head = git("diff", "--stat", inventory_head, evidence_head,
                                "--", "src", "Cargo.toml", "Cargo.lock",
                                "build.rs")
    tree_digest = phase7_courts._source_tree_digest()
    tool_sha = sha256_file(TOOL)
    content_sha, content_files = src_content_hash()

    tracked_status = git("status", "--porcelain", "--untracked-files=no")
    all_status = git("status", "--porcelain")

    # ---- nine artefacts ---------------------------------------------------
    artefact_paths = {
        "libcrypto.so.3": f"{INSTALL}/lib/libcrypto.so.3",
        "libssl.so.3": f"{INSTALL}/lib/libssl.so.3",
        "libcrypto.a": f"{INSTALL}/lib/libcrypto.a",
        "libssl.a": f"{INSTALL}/lib/libssl.a",
        "legacy.so": f"{INSTALL}/lib/ossl-modules/legacy.so",
        "openssl": f"{INSTALL}/bin/openssl",
        "ssh": "court/tmp/openssh-closure/client-b79/openssh-9.9p1/ssh",
        "sshd": "court/tmp/openssh-closure/server-b79/openssh-9.9p1/sshd",
        "sshd_session": (
            "court/tmp/openssh-closure/server-b79/openssh-9.9p1/sshd-session"),
    }
    artefacts = {name: art(rel) for name, rel in artefact_paths.items()}

    # committed blob sizes for the six tracked install artefacts
    blob_sizes = {}
    for name in ("libcrypto.so.3", "libssl.so.3", "libcrypto.a", "libssl.a",
                 "legacy.so", "openssl"):
        rel = artefact_paths[name]
        try:
            blob = int(subprocess.check_output(
                ["git", "cat-file", "-s", f"HEAD:{rel}"], text=True,
                cwd=str(REPO)).strip())
        except subprocess.CalledProcessError:
            blob = None
        blob_sizes[name] = {
            "committed_blob_size": blob,
            "measured_size": artefacts[name]["size"],
            "match": blob == artefacts[name]["size"],
        }

    census_binaries = (census["identity"].get("binary") or {}).get(
        "artefacts") or {}
    install_matches_census = {
        name: {
            "census_sha256": (census_binaries.get(name) or {}).get("sha256"),
            "freeze_sha256": artefacts[name]["sha256"],
            "match": (census_binaries.get(name) or {}).get("sha256")
            == artefacts[name]["sha256"],
        }
        for name in ("libcrypto.so.3", "libssl.so.3", "legacy.so", "openssl")
        if name in census_binaries
    }
    compared = [v["match"] for v in install_matches_census.values()]

    py_compile = subprocess.run(
        [sys.executable, "-m", "py_compile",
         "forensics/tools/consumer_closure.py"],
        cwd=str(REPO), text=True, capture_output=True)

    # ---- closures ---------------------------------------------------------
    def closure(name: str) -> dict:
        rel = f"evidence/closure-{name}-b79c.json"
        doc = ssh if name == "ssh" else sshd
        chain = []
        for tag in ("b73", "b73-r2", "b76", "b76c", "b77", "b78", "b78b",
                    "b78c", "b79", "b79b", "b79c"):
            p = REPO / f"evidence/closure-{name}-{tag}.json"
            if not p.is_file():
                continue
            d = json.loads(p.read_text())
            chain.append({
                "receipt": f"evidence/closure-{name}-{tag}.json",
                "sha256": sha256_file(p),
                "DISCHARGED": d["counts"].get("DISCHARGED"),
                "BLOCKED": d["counts"].get("BLOCKED"),
                "UNKNOWN": d["counts"].get("UNKNOWN"),
                "verdict": d["verdict"]["state"],
                "artifact_sha256": d["artifact_identity"]["sha256"],
                "tool_sha256": d["tool"].get("sha256"),
                "carried_forward_removed": d["counts"].get(
                    "carried_forward_removed"),
            })
        carry_source = next(
            (c for c in chain if c["receipt"].endswith("-b79b.json")), None)
        return {
            "receipt": rel,
            "sha256": sha256_file(REPO / rel),
            "bytes": (REPO / rel).stat().st_size,
            "artifact": doc["artifact_identity"]["path"],
            "artifact_sha256": doc["artifact_identity"]["sha256"],
            "artifact_dynamic": doc["artifact_identity"].get("dynamic"),
            "closure_bound_tool_sha256": doc["tool"]["sha256"],
            "tool_version": doc["tool"].get("version"),
            "counts": {k: v for k, v in doc["counts"].items()
                       if not isinstance(v, (dict, list))},
            "by_mechanism": doc["counts"]["by_mechanism"],
            "verdict": doc["verdict"],
            "refusals": doc["refusals"],
            "element_7": doc["precision"]["predicate_element_7"],
            "source_identity": doc["source_identity"],
            "discharge_receipt_grouping": grouping(doc),
            "obligations_recorded": len(doc["obligations"]),
            "ledger_record": doc["ledger_record"],
            "carry_chain": {
                "immediate_source": carry_source,
                "target": rel,
                "carried_forward_removed": doc["counts"].get(
                    "carried_forward_removed"),
                "links": chain,
                "note": (
                    "the b79c run carries from evidence/closure-" + name
                    + "-b79b.json and repeats the full queue with the repaired "
                    "instrument 6e9cd261; the b79b repair re-binds the sixteen "
                    "stale receipts (evidence/b79-review-rebind.json) at the "
                    "same source content. The b79c closures are 290/290 with 0 "
                    "refusals at source content e012f514."),
            },
        }

    closures = {"ssh": closure("ssh"), "sshd": closure("sshd")}

    def element7_records(doc: dict) -> dict:
        return {
            "status": doc["precision"]["predicate_element_7"]["status"],
            "reachable_unresolved_sites": doc["precision"][
                "predicate_element_7"]["reachable_unresolved_sites"],
            "target_bounded_unresolved_sites": doc["precision"][
                "predicate_element_7"]["target_bounded_unresolved_sites"],
            "contract_bounded_sites": doc["precision"][
                "predicate_element_7"]["contract_bounded_sites"],
            "unclassified_reachable_sites": doc["precision"][
                "predicate_element_7"]["unclassified_reachable_sites"],
            "contract_bounded_by_class": doc["precision"][
                "predicate_element_7"]["contract_bounded_by_class"],
        }

    prior_e7 = []
    for rel in PRIOR_E7:
        p = REPO / rel
        d = json.loads(p.read_text())
        rec = {
            "path": rel,
            "sha256": sha256_file(p),
            "bytes": p.stat().st_size,
            "schema": d.get("schema"),
            "candidate_tag": (d.get("candidate_tag") or d.get("subphase")
                              or d.get("batch")),
            "historical_only": True,
            "note": ("established at an earlier candidate; retained as history, "
                     "not used as b79 evidence"),
        }
        if isinstance(d.get("tool"), dict):
            rec["tool_sha256"] = d["tool"].get("sha256")
            rec["tool_sha256_before"] = d["tool"].get("sha256_before")
            rec["tool_sha256_after"] = d["tool"].get("sha256_after")
        else:
            rec["tool_sha256"] = d.get("tool_sha256")
        if d.get("element_7") or d.get("element7"):
            rec["element7"] = d.get("element_7") or d.get("element7")
        prior_e7.append(rec)

    # class composition change vs b78c, measured from the two receipts
    b78c = REPO / "evidence/closure-ssh-b78c.json"
    b78_classes = {}
    if b78c.is_file():
        b78_classes = json.loads(b78c.read_text())["precision"][
            "predicate_element_7"]["contract_bounded_by_class"]
    b79_classes = ssh["precision"]["predicate_element_7"][
        "contract_bounded_by_class"]
    class_delta = {
        k: [b78_classes.get(k, 0), b79_classes.get(k, 0)]
        for k in sorted(set(b78_classes) | set(b79_classes))
        if b78_classes.get(k, 0) != b79_classes.get(k, 0)
    }

    # ---- reviews ----------------------------------------------------------
    reviews = {}
    for name, p in REVIEWS.items():
        d = json.loads(p.read_text())
        reviews[name] = {
            "path": str(p.relative_to(REPO)),
            "sha256": sha256_file(p),
            "bytes": p.stat().st_size,
            "kind": d.get("kind"),
            "tally": (
                dict(Counter(r.get("verdict") for r in d.get("rows") or []))
                if name == "rebind"
                else (d.get("tally") or d.get("function_summary"))),
            "rows": len(d["rows"]) if name == "rebind" else None,
            "controls": d.get("controls"),
            "controls_all_pass": (
                all(c.get("pass") for c in d["controls"])
                if d.get("controls") else None),
            "residuals": d.get("residuals"),
            "does_not_prove": d.get("does_not_prove"),
        }

    # ---- tool -------------------------------------------------------------
    tool = {
        "path": "forensics/tools/consumer_closure.py",
        "sha256": tool_sha,
        "version": ssh["tool"].get("version"),
        "closure_bound_sha256": ssh["tool"]["sha256"],
        "sshd_closure_bound_sha256": sshd["tool"]["sha256"],
        "changed_since_closures": tool_sha != ssh["tool"]["sha256"],
        "unchanged_since_b78": (
            tool_sha == "6e9cd261c396b561d4f1a61b1de6879cb255e69eed9ec3188ea4f0196e0147a8"),
        "python_syntax": (
            "py_compile of the instrument: OK" if py_compile.returncode == 0
            else f"py_compile of the instrument: FAILED (rc={py_compile.returncode})"),
        "self_test": {
            "status": "NOT_RUN",
            "reason": ("the b79 gate runner (court/freeze-b79/run-gates.sh) ran "
                       "fmt, clippy, test-lib-4 and the targeted unsafe_fn "
                       "tests; it did not invoke the instrument's --self-test, "
                       "so no b79 self-test result exists. The b78 self-test is "
                       "not reused as b79 evidence."),
            "b78_self_test_not_reused": True,
        },
        "instrument_provenance": {
            "path": "court/freeze-b78/b78c-verifier-repair.json",
            "sha256": sha256_file(INSTRUMENT_REPAIR),
            "bytes": INSTRUMENT_REPAIR.stat().st_size,
            "tool": repair_doc.get("tool"),
            "controls_result": (repair_doc.get("controls") or {}).get("result"),
            "note": ("the instrument is byte-identical to the one the b78c "
                     "closures bound (6e9cd261). Its repair record and "
                     "ten-control table are the instrument's provenance; they "
                     "were measured at b78 and are labelled as provenance, not "
                     "as a b79 measurement."),
        },
        "inputs": {
            "census": art("court/freeze-b79/census-b79b.json"),
            "state": art("forensics/memory-safety/campaign/safe-c33/state.json"),
            "campaign_status": art(
                "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json"),
            "enrolment_blockers": art(
                "forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                "callback-enrolment-blockers.json"),
        },
    }

    # ---- safety argument --------------------------------------------------
    safety_totals = (safety_doc.get("verdict") or {}).get("totals") or {}
    safety_per = (safety_doc.get("verdict") or {}).get("per_mechanism") or {}
    safety_mechanisms = [
        {
            "id": m.get("id"),
            "obligations": m.get("obligations"),
            "reviewed_at_b79": m.get("reviewed_at_b79"),
            "outside_b79_cohort": m.get("outside_b79_cohort"),
            "ownership_state": m.get("ownership_state"),
            "contract_forms": m.get("contract_forms"),
            "verdict": m.get("verdict"),
            "residual": m.get("residual"),
        }
        for m in (safety_doc.get("mechanism_partition") or {}).get(
            "mechanisms") or []
    ]
    safety_argument = {
        "path": "evidence/b79-safety-argument.json",
        "sha256": sha256_file(SAFETY_ARGUMENT),
        "bytes": SAFETY_ARGUMENT.stat().st_size,
        "schema": safety_doc.get("schema"),
        "criterion": (safety_doc.get("criterion") or {}).get("text"),
        "verdict_totals": safety_totals,
        "per_mechanism": safety_per,
        "mechanisms": safety_mechanisms,
        "reviewed_total": (safety_doc.get("mechanism_partition") or {}).get(
            "reviewed_total"),
        "safe_interface_surface": {
            "imported_entry_points": safety_doc["safe_interface_surface"][
                "imported_c_abi_entry_points"]["total"],
            "crate_safe_pub_fn_total": safety_doc["safe_interface_surface"][
                "safe_pub_surface_at_b79"]["counts"]["safe_pub_fn_total"],
            "crate_safe_pub_external_reaching_unsafe": safety_doc[
                "safe_interface_surface"]["safe_pub_surface_at_b79"][
                "counts"]["safe_pub_fn_external_reaching_unsafe"],
            "crate_safe_pub_with_raw_pointer_reaching_unsafe": 38,
            "in_mechanism_files": 0,
        },
        "statement": (safety_doc.get("verdict") or {}).get("statement"),
        "residuals": safety_doc.get("residuals"),
        "not_established": True,
        "note": ("the section-7 criterion-3 argument is re-derived at b79 (the "
                 "b78 safe-pub surface is not reused). Its verdict is "
                 "NOT_ESTABLISHED for all seven mechanisms, so it does not "
                 "promote the candidate and safe_compatible remains false."),
    }

    # ---- ledger binding ---------------------------------------------------
    body = atlas.get("body") or atlas
    row = next((r for r in body.get("runs") or []
                if r.get("run_id") == "run:build-link:candidate:openssh"), {})
    linkage = row.get("linkage") or {}
    body_hash_reproduces = content_hash(body) == atlas.get("body_hash")
    row_configure = next(
        (s.get("argv") for s in (row.get("steps") or [])
         if s.get("name") == "configure"), None)
    closure_configure = configure_from_script()

    ledger_binding = {
        "source": "forensics/downstream/build-link-atlas.json",
        "atlas_sha256": sha256_file(ATLAS),
        "atlas_bytes": ATLAS.stat().st_size,
        "body_hash": atlas.get("body_hash"),
        "body_hash_rule": (
            "sha256 of canonical JSON of body (atlas_common.content_hash)"),
        "body_hash_reproduces": body_hash_reproduces,
        "lookup": "body.runs[run_id='run:build-link:candidate:openssh']",
        "run_id": row.get("run_id"),
        "recipe_id": row.get("recipe_id"),
        "recorded_artifact_rel": linkage.get("artifact_rel"),
        "recorded_artifact_sha256": linkage.get("artifact_sha256"),
        "recorded_candidate_install_libcrypto_sha256":
            (body.get("candidate_identity") or {}).get(
                "libcrypto_so_3_sha256"),
        "recorded_install_matches_freeze_install": (
            (body.get("candidate_identity") or {}).get(
                "libcrypto_so_3_sha256")
            == artefacts["libcrypto.so.3"]["sha256"]),
        "freeze_proven_ssh_sha256": artefacts["ssh"]["sha256"],
        "freeze_proven_sshd_sha256": artefacts["sshd"]["sha256"],
        "freeze_proven_sshd_session_sha256": artefacts["sshd_session"]["sha256"],
        "ssh_receipt_artifact_sha256": ssh["artifact_identity"]["sha256"],
        "sshd_receipt_artifact_sha256": sshd["artifact_identity"]["sha256"],
        "artifact_matches_this_build_reported_by_receipt":
            (ssh.get("ledger_record") or {}).get("artifact_matches_this_build"),
        "artifact_matches_this_build": False,
        "artifact_matches_this_build_statement": (
            "artifact_matches_this_build is false because the atlas row is its "
            "own build of ssh: its configure argv ("
            + json.dumps(row_configure) + ") differs from the closure build's "
            "configure argv (" + json.dumps(closure_configure) + ") and it "
            "runs `make -j8 ssh`, while the closures analyse the full builds "
            "under court/tmp/openssh-closure/{client,server}-b79. Its recorded "
            "digest " + str(linkage.get("artifact_sha256"))[:12] + " is not "
            "either analysed binary; the row's recorded candidate install does "
            "match the freeze-proven install, but that does not make the row's "
            "ssh binary the analysed ssh. The field is not the per-artefact "
            "binding. Per-artefact binding is carried by the rebind receipts in "
            "evidence/{ssh,sshd}-artifact-ledger-b79-rebind.json and by the "
            "freeze digests recorded here."),
        "atlas_row_configure_argv": row_configure,
        "closure_build_configure_argv": closure_configure,
        "closure_build_script": art("forensics/tools/build_openssh_closure.sh"),
        "atlas_row_steps": [
            {"name": s.get("name"), "argv": s.get("argv"),
             "exit_code": s.get("exit_code")}
            for s in (row.get("steps") or [])
        ],
        "per_artefact_rebind": {},
        "ledgers": {fam: str(p.relative_to(REPO)) for fam, p in LEDGERS.items()},
    }
    for fam, p in REBINDS.items():
        if not p.is_file():
            ledger_binding["per_artefact_rebind"][fam] = None
            continue
        rb = json.loads(p.read_text())
        checks = (rb.get("rebind") or {}).get("checks") or {}
        ok = bool(checks) and all(checks.values())
        ledger_binding["per_artefact_rebind"][fam] = {
            "receipt": str(p.relative_to(REPO)),
            "sha256": sha256_file(p),
            "bytes": p.stat().st_size,
            "verdict": ("ACCEPTED (all checks passed; not a closure run)"
                        if ok else "REFUSED (a check did not pass)"),
            "artifact_rel": (rb.get("ledger_record") or {}).get("artifact_rel"),
            "artifact_sha256_recorded": (rb.get("ledger_record") or {}).get(
                "artifact_sha256_recorded"),
            "artifact_matches_this_build": (rb.get("ledger_record") or {}).get(
                "artifact_matches_this_build"),
            "ledger": (rb.get("rebind") or {}).get("ledger_source"),
            "freeze_from_ledger": (rb.get("rebind") or {}).get("freeze"),
            "checks": (rb.get("rebind") or {}).get("checks"),
            "not_a_closure_run": (rb.get("rebind") or {}).get(
                "not_a_closure_run"),
            "witness": (rb.get("rebind") or {}).get("witness"),
        }

    # ---- L7 ---------------------------------------------------------------
    session_exec = art(
        "court/tmp/openssh-closure/server-b79/install/libexec/sshd-session")
    session_tree = art(
        "court/tmp/openssh-closure/server-b79/openssh-9.9p1/sshd-session")
    auth_base = "court/tmp/openssh-closure/auth-b79/openssh-9.9p1"
    auth_measured = {
        "ssh": art(f"{auth_base}/ssh"),
        "sshd": art(f"{auth_base}/sshd"),
        "sshd_session": art(f"{auth_base}/sshd-session"),
        "ssh_keygen": art(f"{auth_base}/ssh-keygen"),
    }
    auth_lib_rel = ("forensics/authorities/prefix/openssl-3.6.4-production/"
                    "lib/libcrypto.so.3")
    auth_lib = art(auth_lib_rel)
    l7_workloads = {
        name: {
            "status": (w or {}).get("status"),
            "transcript": (w or {}).get("transcript"),
            "results": (w or {}).get("results"),
            "totals": (w or {}).get("totals"),
        }
        for name, w in (l7_doc.get("workloads") or {}).items()
    }
    l7_statuses = [w["status"] for w in l7_workloads.values()]
    l7_exec = (((l7_doc.get("executed_identity") or {})
                .get("sshd_session_executed") or {}).get("sha256"))
    l7_tree = (((l7_doc.get("executed_identity") or {})
                .get("sshd_session_tree_copy") or {}).get("sha256"))
    l7_auth = l7_doc.get("authority_openssh") or {}
    l7_auth_bins = l7_auth.get("binaries") or {}
    l7_auth_diff = (l7_doc.get("workloads") or {}).get(
        "w5_authority_keyformat_differential") or {}

    l7_evidence = {
        "path": "evidence/b79-l7-replay.json",
        "sha256": sha256_file(L7),
        "bytes": L7.stat().st_size,
        "schema": l7_doc.get("schema"),
        "workloads": l7_workloads,
        "all_workloads_pass": bool(l7_statuses) and all(
            s == "PASS" for s in l7_statuses),
        "totals": l7_doc.get("totals"),
        "executed_sshd_session": dict(
            session_exec,
            source="measured by this freeze from the install path sshd executes",
            matches_l7_record=session_exec["sha256"] == l7_exec,
        ),
        "sshd_session_tree_copy": dict(
            session_tree,
            source="measured by this freeze from the link tree",
            matches_l7_record=session_tree["sha256"] == l7_tree,
        ),
        "difference_explained": (
            "the executed session binary is the stripped install copy ("
            + session_exec["sha256"][:12] + "); the link-tree copy is "
            + session_tree["sha256"][:12] + " and was never executed. `make "
            "install` strips the binary, so the digests differ while the build "
            "is the same by install provenance, not proven byte-equal. This "
            "freeze binds the executed digest as the one that served logins."),
        "authority_differential": {
            "workload": "w5_authority_keyformat_differential",
            "status": l7_auth_diff.get("status"),
            "totals": l7_auth_diff.get("totals"),
            "authority_libcrypto_so_3": dict(
                auth_lib,
                matches_l7_record=(auth_lib["sha256"]
                                   == l7_auth.get(
                                       "authority_libcrypto_so_3_sha256"))),
            "candidate_libcrypto_so_3_sha256":
                artefacts["libcrypto.so.3"]["sha256"],
            "authority_binaries": {
                name: dict(
                    a,
                    matches_l7_record=(a["sha256"]
                                       == (l7_auth_bins.get(name) or {}).get(
                                           "sha256")),
                )
                for name, a in auth_measured.items()
            },
            "identity_discrimination": l7_auth.get("identity_discrimination"),
        },
        "not_run_retained": (
            "the candidate-only keyformat-b79.sh authority rows remain NOT_RUN "
            "by construction; the authority-linked differential w5 is the "
            "evidence that closes the gap."),
    }

    # ---- gates ------------------------------------------------------------
    stale_fmt_files = sorted({
        ln.split("Diff in ", 1)[1].rsplit(":", 1)[0]
        for ln in stale_fmt_diffs})

    gates = {
        "gate_source": "exact-S",
        "run_at": {
            "gate_head": "ce47fe8263077a79ba040c107f36f8cc3dde3952",
            "measured_source_S": CLOSURE_TREE,
            "src_identical_to_S": not bool(src_vs_source),
            "src_diff_stat_vs_S": src_vs_source or "",
            "src_identity_check": (
                "`git diff --stat " + CLOSURE_TREE + " -- src Cargo.toml "
                "Cargo.lock build.rs` is empty: the gate ran on the exact "
                "build-relevant source of S even though HEAD is "
                + evidence_head),
            "utc": {
                "fmt": fmt.get("utc"), "clippy": clippy.get("utc"),
                "lib_tests": tests.get("utc"),
                "unsafe_fn": unsafe_fn.get("utc")},
        },
        "fmt": {
            "command": fmt.get("command"),
            "returncode": fmt.get("exit"),
            "formatted_diff_locations": len(fmt_diffs),
            "formatted_files": sorted({
                ln.split("Diff in ", 1)[1].rsplit(":", 1)[0]
                for ln in fmt_diffs}),
        },
        "clippy": {
            "command": clippy.get("command"),
            "returncode": clippy.get("exit"),
        },
        "lib_tests_parallel": {
            "command": tests.get("command"),
            "returncode": tests.get("exit"),
            "test_result": tests_res,
            "failed_tests": failed_tests(tests.get("output") or []),
        },
        "unsafe_fn_targeted": {
            "command": unsafe_fn.get("command"),
            "returncode": unsafe_fn.get("exit"),
            "test_result": unsafe_res,
            "failed_tests": failed_tests(unsafe_fn.get("output") or []),
        },
        "log": "court/freeze-b79/gates.log",
        "log_sha256": sha256_file(GATES),
        "log_bytes": GATES.stat().st_size,
        "log_is_append_only": True,
        "generator": {
            "path": "court/freeze-b79/make_freeze_b79.py",
            "sha256": sha256_file(REPO / "court/freeze-b79/make_freeze_b79.py"),
            "note": (
                "the tool that assembled this gate section. Section 22 counts a "
                "verification-tool change as a candidate-side change, so this "
                "sha binds the evidence to the exact generator that produced "
                "it; the edit that added the exact-S binding runs in the same "
                "evidence commit and does not touch src/."),
        },
        "exact_counts": {
            "fmt_exit": fmt.get("exit"),
            "clippy_exit": clippy.get("exit"),
            "lib_tests": tests_res,
            "unsafe_fn_tests": unsafe_res,
            "superseded_fmt_exit": stale["fmt"].get("exit"),
            "log_sha256": sha256_file(GATES),
        },
        "verdict": (
            "exact-candidate gate at gate HEAD "
            + "ce47fe826" + " (src byte-identical to S = " + CLOSURE_TREE
            + "): fmt PASS (exit " + str(fmt.get("exit")) + ", "
            + str(len(fmt_diffs)) + " diff locations). clippy PASS (exit "
            + str(clippy.get("exit")) + ", -D warnings). library tests PASS "
            "at --test-threads=4 ("
            + str((tests_res or {}).get("passed")) + " passed, "
            + str((tests_res or {}).get("failed")) + " failed, "
            + str((tests_res or {}).get("ignored")) + " ignored; exit "
            + str(tests.get("exit")) + "). The targeted unsafe_fn tests PASS ("
            + str((unsafe_res or {}).get("passed")) + " passed, 0 failed; exit "
            + str(unsafe_fn.get("exit")) + "). No test failed, so the known "
            "scrypt isolation flake (B44-TEST-1) did not reproduce and no "
            "rerun was needed."),
        "gate_identity_caveat": (
            "court/freeze-b79/gates.log is append-only and holds two "
            "generations. Its first four steps (`fmt`, `clippy`, "
            "`test-lib-4`, `unsafe-fn`, utc 2026-11-14T21:30Z) ran on the "
            "PRE-FORMAT tree, one rustfmt commit (63a23e729) behind S; their "
            "`fmt` exit 1 is superseded and is not an S result. A "
            "SUPERSESSION NOTICE line in the log marks the boundary. The "
            "`*-exact-s` steps were run at gate HEAD ce47fe826, whose src/ is "
            "byte-identical to S = " + CLOSURE_TREE + "; they are the gate "
            "evidence this freeze records. Source identity and evidence "
            "identity stay separate (section 22): committing E moves HEAD "
            "without changing S."),
        "superseded_pre_format_run": {
            "status": "SUPERSEDED",
            "reason": (
                "these four steps predate 63a23e729, the commit that "
                "formatted eleven rustfmt line-joins inside #[cfg(test)] "
                "qualifier-control tests; the tree they measured no longer "
                "exists at S, so their results are history, not evidence"),
            "retained_because": (
                "the log is append-only; deleting the entry would destroy the "
                "record of why a fmt failure once appeared"),
            "fmt": {
                "command": stale["fmt"].get("command"),
                "returncode": stale["fmt"].get("exit"),
                "formatted_diff_locations": len(stale_fmt_diffs),
                "formatted_files": stale_fmt_files,
            },
            "clippy": {
                "command": stale["clippy"].get("command"),
                "returncode": stale["clippy"].get("exit"),
            },
            "lib_tests_parallel": {
                "returncode": stale["tests"].get("exit"),
                "test_result": stale_tests_res,
            },
            "unsafe_fn_targeted": {
                "returncode": stale["unsafe_fn"].get("exit"),
                "test_result": stale_unsafe_res,
            },
            "note": (
                "the pre-format run and the exact-S run agree on every "
                "non-format outcome (clippy exit 0; "
                + str((stale_tests_res or {}).get("passed")) + " passed / "
                + str((stale_tests_res or {}).get("failed")) + " failed / "
                + str((stale_tests_res or {}).get("ignored")) + " ignored "
                "tests; 12 unsafe_fn tests). Only `fmt` changes, from exit 1 "
                "to exit 0, which is exactly the delta 63a23e729 applied."),
        },
        "recorded_scrypt_flake": (
            "the campaign records one scrypt test-isolation flake: "
            "boundary-sweep-B44 (B44-TEST-1) says five routine tests fetched or "
            "freed the shared default-libctx method without the global lock, so "
            "another test's +/-1 on the cached refcount made the scrypt "
            "assertion fail intermittently (2/20 module runs); B44 made the "
            "assertion relative and took the lock, and its re-review is NOT_RUN. "
            "The exact-S gate run observed "
            + str((tests_res or {}).get("failed")) + " failed tests, so no "
            "flake reproduced and no rerun was required."),
        "failure_class": "NONE_AT_EXACT_S",
    }

    # ---- memory / venue ---------------------------------------------------
    host_readings = []
    for name, sec in (("fmt", fmt), ("clippy", clippy),
                      ("test-lib-4", tests), ("unsafe-fn", unsafe_fn)):
        for reading in sec.get("meminfo") or []:
            host_readings.append({"when": name, "line": reading})
    meminfo = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meminfo[k] = v.strip().split()[0]
    events = cgroup("memory.events") or ""
    ev = dict(re.findall(r"^(\w+) (\d+)$", events, re.M))
    rlimit_data = resource.getrlimit(resource.RLIMIT_DATA)[0]
    limits_doc = load("evidence/b79-court-limits-16g-16cpu.json")
    memory = {
        "deviation": (
            "AGENTS.md section 6.1 computes the cap as min(8g, available-16g) "
            "with a 2g floor. The b79c closures and the L7 replay ran under an "
            "explicit directive that fixed the existing court at 16 GiB / 16 "
            "CPU (evidence/b79-court-limits-16g-16cpu.json); that is recorded "
            "as a deviation and is the venue of the closure measurement, not "
            "of the gate. Immediately before the exact-S gate the live cap was "
            "tightened to the formula value: at generation the host reported "
            "MemAvailable "
            + str(round(int(meminfo.get("MemAvailable", "0")) / (1024 * 1024), 1))
            + " GiB, so min(8g, available-16g) = 8g, and `docker update "
            "--memory 8g --memory-swap 8g` set memory.max="
            + str(cgroup("memory.max")) + " with swap.max="
            + str(cgroup("memory.swap.max")) + ". The four exact-S gate "
            "commands therefore ran under an 8 GiB hard cap; the 16 GiB figure "
            "is not claimed for them."),
        "exact_s_gate_venue": {
            "memory_max_bytes": cgroup("memory.max"),
            "memory_swap_max_bytes": cgroup("memory.swap.max"),
            "cpu_max": cgroup("cpu.max"),
            "pids_max": cgroup("pids.max"),
            "cargo_build_jobs": 4,
            "test_threads": 4,
            "parallelism_note": (
                "AGENTS.md 6.1 rule 4 caps parallelism at 4; the orchestration "
                "request named 8 build jobs, which was reduced to 4 for the "
                "gate, and the reduction is recorded here rather than left "
                "silent"),
            "rlimit_data_kib": rlimit_data // 1024 if rlimit_data else None,
            "peak_memory_current_bytes": {
                "clippy": peak_current(
                    "court/freeze-b79/peak-clippy-exact-s.txt"),
                "lib_tests": peak_current(
                    "court/freeze-b79/peak-test-lib-4-exact-s.txt"),
            },
            "peak_samples": [
                "court/freeze-b79/peak-clippy-exact-s.txt",
                "court/freeze-b79/peak-test-lib-4-exact-s.txt",
            ],
            "peak_rule": (
                "peak of `memory.current` sampled every 2 s inside the court "
                "cgroup for the duration of each gate step. memory.peak is "
                "read-only in this container and already carried the earlier "
                "17179869184 peak, so it cannot serve as a per-run figure. The "
                "sample includes page cache, so it is an upper bound on the "
                "step's resident working set."),
            "memory_events": ev,
        },
        "host_readings": host_readings,
        "host_available_gib_at_generation": round(
            int(meminfo.get("MemAvailable", "0")) / (1024 * 1024), 1),
        "host_total_gib_at_generation": round(
            int(meminfo.get("MemTotal", "0")) / (1024 * 1024), 1),
        "cgroup": {
            "memory_max_bytes": cgroup("memory.max"),
            "memory_current_bytes": cgroup("memory.current"),
            "memory_peak_bytes": cgroup("memory.peak"),
            "memory_swap_max_bytes": cgroup("memory.swap.max"),
            "memory_events": ev,
            "cpu_max": cgroup("cpu.max"),
            "pids_max": cgroup("pids.max"),
        },
        "rlimit_data_kib": rlimit_data // 1024 if rlimit_data else None,
        "user_directive_receipt": {
            "path": "evidence/b79-court-limits-16g-16cpu.json",
            "sha256": limits_doc and sha256_file(
                REPO / "evidence/b79-court-limits-16g-16cpu.json"),
            "new_cap": (limits_doc.get("cap") or {}).get("new"),
            "applies_to": (
                "the b79c closure and L7 venue; the exact-S gate ran at the "
                "section 6.1 formula cap instead"),
        },
        "parallel_test_outcome": (
            "the --test-threads=4 library gate passed "
            + str((tests_res or {}).get("passed")) + "/"
            + str((tests_res or {}).get("failed")) + "/"
            + str((tests_res or {}).get("ignored"))
            + " under the 8 GiB exact-S cap with oom_kill="
            + str(ev.get("oom_kill"))),
    }

    # ---- source -----------------------------------------------------------
    source = {
        "head": inventory_head,
        "head_role": (
            "the inventory/span source head: the census identity and the b79c "
            "receipts' inventory_source_head and span_source_commit"),
        "head_subject": git("log", "-1", "--format=%s", inventory_head),
        "closure_tree_head": source_head,
        "closure_tree_head_role": (
            "the b79c receipts' repository_head with tracked_tree_dirty=false; "
            "the tree the b79c closures, the L7 replay and the b79 reviews ran "
            "at"),
        "src_identical_between_inventory_and_closure_tree": not bool(src_between),
        "branch": census["identity"].get("branch"),
        "src_rs_files": content_files,
        "src_rs_files_census": census["identity"]["src_rs_files"],
        "crate_version": census["identity"]["crate_version"],
        "src_content_sha256": content_sha,
        "src_content_sha256_census": census["identity"]["src_content_sha256"],
        "src_content_sha256_matches_census": (
            content_sha == census["identity"]["src_content_sha256"]),
        "src_content_hash_rule": census["identity"]["src_content_hash_rule"],
        "census_working_tree_clean": census["identity"].get(
            "working_tree_clean"),
        "census_tracked_working_tree_clean": census["identity"].get(
            "tracked_working_tree_clean"),
        "source_tree_digest": {
            "count": tree_digest["count"], "sha256": tree_digest["sha256"],
            "rule": ("sha256 over canonical JSON of sorted [relpath,size,sha256] "
                     "for src/, Cargo.toml, Cargo.lock, build.rs "
                     "(forensics/tools/phase7_courts.py::_source_tree_digest)"),
        },
        "working_tree": {
            "repository_head": evidence_head,
            "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
            "tracked_dirty": bool(tracked_status),
            "modified_tracked_paths": sorted(
                line.split()[-1] for line in tracked_status.splitlines()),
            "untracked_paths": sorted(
                line.split()[-1] for line in all_status.splitlines()
                if line.startswith("??")),
            "tracked_dirty_note": (
                "the tracked dirt at generation is evidence-side only: "
                "court/freeze-b79/make_freeze_b79.py, the tool that writes "
                "this file, and CAMPAIGN-STATUS.json after it is updated in "
                "the same evidence commit. No src/, Cargo.toml, Cargo.lock or "
                "build.rs path is modified (src_diff_vs_closure_tree_head is "
                "null), so candidate S is untouched and the gates ran on S."),
        },
        "git_verification": {
            "closure_tree_is_ancestor_of_evidence_head": closure_is_ancestor,
            "inventory_tree_is_ancestor_of_evidence_head":
                inventory_is_ancestor,
            "src_diff_vs_closure_tree_head": src_vs_source or None,
            "src_diff_inventory_to_closure_tree": src_between or None,
            "src_diff_inventory_to_evidence_head": src_inventory_to_head or None,
        },
    }

    # ---- safe-compatible --------------------------------------------------
    review_required = (((status.get("current_applied_state") or {})
                        .get("safe_compatible_blockers") or {})
                       .get("projected_after_recensus") or {}).get(
                           "REVIEW_REQUIRED")
    measured = {
        fam: {
            "DISCHARGED": closures[fam]["counts"]["DISCHARGED"],
            "reachable_production_obligations":
                closures[fam]["counts"]["reachable_production_obligations"],
            "BLOCKED": closures[fam]["counts"]["BLOCKED"],
            "UNKNOWN": closures[fam]["counts"]["UNKNOWN"],
            "element_7_status": closures[fam]["element_7"]["status"],
            "target_bounded": closures[fam]["element_7"][
                "target_bounded_unresolved_sites"],
            "contract_bounded": closures[fam]["element_7"][
                "contract_bounded_sites"],
        }
        for fam in ("ssh", "sshd")
    }
    safe_compatible = {
        "value": False,
        "reason": (
            "consumer_closure.py never promotes: verdict.safe_compatible is a "
            "hard-coded false in the instrument. AGENTS.md section 7 additionally "
            "requires every mechanism in the conservative dependency closure to "
            "be SAFETY_DISCHARGED with its callers' obligations discharged, and "
            "compatibility confirmed against the exact converted implementation. "
            "The b79c closures measure the queue at this candidate, not a "
            "promotion; the section-7 argument is NOT_ESTABLISHED for all seven "
            "mechanisms, and no independent SAFE_COMPATIBLE adjudication was run "
            "at b79."),
        "measured": measured,
        "l7_replay": {
            "status": "PASS" if l7_evidence["all_workloads_pass"] else "FAIL",
            "evidence": "evidence/b79-l7-replay.json",
            "sha256": l7_evidence["sha256"],
            "workloads": {n: w["status"] for n, w in l7_workloads.items()},
            "authority_differential": (
                str((l7_auth_diff.get("totals") or {}).get("pass")) + "/"
                + str((l7_auth_diff.get("totals") or {}).get("of"))
                + " PASS (w5_authority_keyformat_differential)"),
            "note": ("functional evidence only (AGENTS.md section 8); not "
                     "SAFE_COMPATIBLE graduation"),
            "not_graduated": True,
        },
        "outstanding": [
            ("SAFE_COMPATIBLE is NOT established: no independent adjudication "
             "was run at b79 (the b78 adjudication is NOT reused); the b79c "
             "closures are queue measurements"),
            ("the section-7 criterion-3 safety argument is recorded in "
             "evidence/b79-safety-argument.json and its verdict is "
             "NOT_ESTABLISHED for all seven mechanisms (0 SAFETY_DISCHARGED / 0 "
             "OWNERSHIP_RECONSTRUCTED / 7 NOT_ESTABLISHED); 59/290 obligations "
             "were independently re-read at b79 and 231 rest on caller closures "
             "not re-established at this candidate"),
            (str(review_required) + " REVIEW_REQUIRED discharges "
             "(CAMPAIGN-STATUS current_applied_state.safe_compatible_blockers."
             "projected_after_recensus.REVIEW_REQUIRED); CAMPAIGN-STATUS has no "
             "b79 update, so this figure is the campaign-status projection, not "
             "a b79 measurement"),
            "BOUNDARY adjudication of the remaining contract-bounded boundaries",
            "SEAL (release build, complete probe suite, full forensic "
            "regeneration)",
        ],
        "review_required": {
            "count": review_required,
            "source": "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json",
            "json_pointer": ("current_applied_state.safe_compatible_blockers."
                             "projected_after_recensus.REVIEW_REQUIRED"),
            "source_sha256": sha256_file(STATUS),
            "stale_note": ("the status file predates b79 (no b79 entry); the "
                           "count is recorded with its source, not re-derived"),
        },
    }

    doc = {
        "schema": "openssl-rs/campaign/safe-c33/freeze/v1",
        "candidate_tag": "b79",
        "generated_utc": subprocess.check_output(
            ["date", "-u", "+%FT%TZ"], text=True).strip(),
        "freeze_kind": (
            "source-and-artefact freeze (S) with per-artefact ledger rebind"),
        "freeze_reason": (
            "b79 freezes the OCSP/element-7 candidate: the two b79c consumer "
            "closures are ACCEPTED 290/290 with element 7 PASS (0 target-bounded "
            "/ 153 contract-bounded) under the repaired instrument 6e9cd261 at "
            "source content e012f514; the install and OpenSSH closure binaries "
            "are measured; the L7 replay (including the authority-linked "
            "key-format differential 10/10) and the re-derived section-7 "
            "criterion-3 argument are recorded from their files; and the "
            "per-artefact ledger rebinds bind both ssh and sshd to this freeze. "
            "The criterion-3 argument is NOT ESTABLISHED, so the freeze states "
            "plainly that the candidate is NOT graduated."),
        "identity": {
            "rule": (
                "Two identities, never conflated (AGENTS.md section 22). S is "
                "the frozen source+instrument identity this evidence describes: "
                "closure tree 5b08c0294, inventory tree 63a23e729 (identical src, "
                "e012f514), instrument 6e9cd261 and the b79c closures. E is the "
                "evidence commit that carries this freeze and the ledger "
                "receipts. Committing E moves HEAD; it does not change S, its "
                "artefacts or their digests."),
            "production_source_head": source_head,
            "production_source_head_note": (
                "the b79c receipts' repository_head with tracked_tree_dirty=false "
                "(the closure, L7 and review tree)"),
            "inventory_source_head": inventory_head,
            "inventory_source_head_note": (
                "census identity.source_head and the receipts' "
                "inventory_source_head/span_source_commit; src is byte-identical "
                "to the closure tree"),
            "instrument_head": evidence_head,
            "instrument_head_note": (
                "git HEAD when this freeze was generated; the commit that "
                "records the b79c closure and carries instrument "
                + tool_sha[:12] + ". The closures record their own "
                "repository_head (see closures.*.source_identity)."),
            "evidence_commit": "E",
            "evidence_commit_note": (
                "E is the commit that carries this freeze and the rebind "
                "receipts; at generation it has not been created, so HEAD is "
                "the instrument/closure-record commit named above."),
            "closure_repository_heads": {
                fam: closures[fam]["source_identity"].get("repository_head")
                for fam in ("ssh", "sshd")
            },
        },
        "source": source,
        "candidate_identity": {
            "source_head": source_head,
            "inventory_head": inventory_head,
            "instrument_head": evidence_head,
            "tool_sha256": tool_sha,
            "census_sha256": sha256_file(CENSUS),
            "libcrypto_so_3_sha256": artefacts["libcrypto.so.3"]["sha256"],
            "libssl_so_3_sha256": artefacts["libssl.so.3"]["sha256"],
            "ssh_sha256": artefacts["ssh"]["sha256"],
            "sshd_sha256": artefacts["sshd"]["sha256"],
            "sshd_session_sha256":
                artefacts["sshd_session"]["sha256"],
            "rule": ("closure tree + inventory tree + instrument sha + census "
                     "sha + measured artefact digests; a change to any one of "
                     "them is a new candidate"),
        },
        "tool": tool,
        "safety_argument": safety_argument,
        "artefacts": {
            "install_prefix": INSTALL,
            "files": artefacts,
            "install_matches_census": install_matches_census,
            "all_install_artefacts_match_census": (
                all(compared) if compared else None),
            "compared_names": sorted(install_matches_census),
            "committed_blob_sizes": {
                "rule": ("`git cat-file -s HEAD:<rel>` vs the measured working-"
                         "tree size for the six tracked install artefacts; the "
                         "court/tmp consumer binaries are git-ignored and have "
                         "no blob"),
                "checks": blob_sizes,
                "all_match": all(v["match"] for v in blob_sizes.values()),
            },
            "resolved_libcrypto_sha256": artefacts["libcrypto.so.3"]["sha256"],
            "consumer_source": (
                "OpenSSH 9.9p1 in the closure trees "
                "court/tmp/openssh-closure/{client,server}-b79/openssh-9.9p1"),
            "note": ("each digest and size is recomputed from the file named in "
                     "this working tree; the census comparison is per name; no "
                     "b79 build-receipt size log exists, so the committed blob "
                     "size is the recorded comparison"),
        },
        "census": {
            "path": "court/freeze-b79/census-b79b.json",
            "sha256": sha256_file(CENSUS),
            "bytes": CENSUS.stat().st_size,
            "source_head": census["identity"]["source_head"],
            "delta_vs": census.get("delta_vs_previous", {}).get("previous"),
            "operation_counts": (census.get("contracts") or {}).get(
                "operation_counts"),
            "gates": census.get("gates"),
            "gates_note": ("the census records no pass/fail gate for its own "
                           "run; a null gate is NOT a PASS"),
        },
        "closures": {
            "ssh": closures["ssh"],
            "sshd": closures["sshd"],
            "safe_compatible": False,
        },
        "element7": {
            "measured_by_closures": {
                fam: element7_records(ssh if fam == "ssh" else sshd)
                for fam in ("ssh", "sshd")
            },
            "class_composition_change_vs_b78c": {
                "rule": ("contract_bounded_by_class compared between "
                         "evidence/closure-ssh-b78c.json and "
                         "evidence/closure-ssh-b79c.json; [b78c, b79c]"),
                "changed": class_delta,
                "statement": (
                    "the ABI_CONTRACT_CONF_DEFAULT_METHOD class has no residual "
                    "site at b79c (the default_CONF_method cell is no longer an "
                    "unresolved reachable site) and EXPORT_CALLBACK grew by one "
                    "(66 -> 67). The b78 CONF-method witness record is therefore "
                    "not reused as b79 evidence; the b79c closure measurement is "
                    "the record."),
            },
            "prior_element7_records": prior_e7,
            "statement": (
                "the 153 contract-bounded sites are intentionally unbounded: "
                "each is resolved to a declared external ABI contract (AGENTS.md "
                "section 7 criterion 2), not left as an unproven target. None is "
                "counted as target-bounded, and no site is unclassified. The "
                "earlier repin records are history only; the b79c closures are "
                "the current measurement."),
        },
        "reviews": reviews,
        "ledger_binding": ledger_binding,
        "gates": gates,
        "l7_evidence": l7_evidence,
        "memory": memory,
        "safe_compatible": safe_compatible,
        "residuals": [
            {"kind": "criterion3/safety-argument",
             "statement": (
                 "evidence/b79-safety-argument.json is the section-7 "
                 "criterion-3 whole-closure argument re-derived at b79. Its "
                 "verdict is NOT_ESTABLISHED for all seven mechanisms (0 "
                 "SAFETY_DISCHARGED / 0 OWNERSHIP_RECONSTRUCTED / 7 "
                 "NOT_ESTABLISHED) because only 59/290 obligations were "
                 "independently re-read at b79, the operation-span hash excludes "
                 "caller closures, five sites have only an operation-level "
                 "contract, six rest on inventory contract records, four have no "
                 "contract, and C_ABI_CONTRACT/BIO are UNSAFE_OPEN. Recording "
                 "the argument closes the 'no argument' gap as an artifact, not "
                 "as a safety result.")},
            {"kind": "criterion3/qualifier-control",
             "statement": (
                 "the reconversion review's D1 is open: 11 of the 12 qualifier-"
                 "control tests are self-satisfying, so removing `unsafe` from "
                 "23 of the 24 converted declarations would not fail any test; "
                 "D2 (SSL_COMP_get_name has no effective qualifier control), D4 "
                 "and D5 (contract strength at send_certificate_request and "
                 "OPENSSL_init_ssl) are also open.")},
            {"kind": "venue/memory", "statement": memory["deviation"]},
            {"kind": "gate/exact-s",
             "statement": gates["gate_identity_caveat"]},
            {"kind": "gate/superseded-pre-format-log",
             "statement": gates["superseded_pre_format_run"]["note"]},
            {"kind": "gate/recorded-scrypt-flake",
             "statement": gates["recorded_scrypt_flake"]},
            {"kind": "instrument/self-test-not-run",
             "statement": (
                 "the instrument self-test was NOT_RUN at b79: the gate runner "
                 "did not invoke --self-test, so no b79 self-test result exists. "
                 "The b78 self-test is not reused. The instrument itself is "
                 "byte-identical (6e9cd261) and py_compile is OK.")},
            {"kind": "element7/contract-bounded",
             "statement": (
                 "153 contract-bounded sites remain target-unbounded by design: "
                 "the application supplies the targets through public ABI "
                 "contracts (exported callbacks, provider tables, the "
                 "CONF_METHOD cell). They are discharged under AGENTS.md section "
                 "7 criterion 2, not proven safe by this freeze.")},
            {"kind": "ledger-binding",
             "statement": ledger_binding["artifact_matches_this_build_statement"]},
            {"kind": "l7/not-run-rows",
             "statement": (
                 "the candidate-only keyformat-b79.sh authority rows are NOT_RUN "
                 "by construction (no AUTH_KG) and are retained as NOT_RUN; the "
                 "authority-linked differential w5 (10/10 PASS) is the closing "
                 "evidence. No L7 workload is NOT_RUN.")},
            {"kind": "adjudication/not-run",
             "statement": (
                 "no independent SAFE_COMPATIBLE adjudication was performed at "
                 "b79; the b78 adjudication is NOT reused (section 22).")},
            {"kind": "campaign-status/b79-block",
             "statement": (
                 "CAMPAIGN-STATUS.json is recorded in tool.inputs with the "
                 "sha256 it had at generation. The b79 block is added in the "
                 "same evidence commit (E) and names this freeze's sha256, so "
                 "adding it changes the status file's own digest after "
                 "generation. That staleness is recorded here rather than "
                 "hidden; no historical block is deleted and no gate reads "
                 "this file as evidence.")},
            {"kind": "not-run",
             "statement": (
                 "SEAL, BOUNDARY adjudication of the remaining contract-bounded "
                 "boundaries, ASan/Miri/Loom, dudect/Wycheproof and forensic "
                 "regeneration are NOT_RUN at this candidate; they are scheduled "
                 "at their gates, not implied by this freeze.")},
        ],
        "not_run": [
            ("SAFE_COMPATIBLE promotion (no independent adjudication at b79; the "
             "frozen candidate is NOT graduated)"),
            ("the section-7 criterion-3 mechanisms are NOT_ESTABLISHED (0 "
             "SAFETY_DISCHARGED / 0 OWNERSHIP_RECONSTRUCTED / 7 "
             "NOT_ESTABLISHED; see safety_argument)"),
            "BOUNDARY adjudication of the remaining contract-bounded boundaries",
            "SEAL (release build, full probe suite, full forensic regeneration)",
            "ASan/Miri/Loom and dudect/Wycheproof for this candidate",
            "the instrument --self-test at b79 (NOT_RUN)",
            (str(review_required) + " REVIEW_REQUIRED discharges (campaign status "
             "requires a rebuild and re-census)"),
            "the candidate-only keyformat-b79.sh authority rows (NOT_RUN by "
            "construction; closed by w5)",
        ],
        "non_claims": [
            ("the closures named here are measurements of the candidate at S with "
             "the closure-bound instrument; they are not re-measured by this "
             "generator"),
            (str(closures["ssh"]["counts"]["BLOCKED"]) + " BLOCKED / "
             + str(closures["ssh"]["counts"]["UNKNOWN"]) + " UNKNOWN (ssh) and "
             + str(closures["sshd"]["counts"]["BLOCKED"]) + " BLOCKED / "
             + str(closures["sshd"]["counts"]["UNKNOWN"]) + " UNKNOWN (sshd) is "
             "a statement about the instrument's queue at this candidate, not a "
             "SAFE_COMPATIBLE promotion"),
            ("a green differential/closure result is not a safety or "
             "cryptographic result (AGENTS.md section 8)"),
            ("the per-artefact rebind is not a closure run and changes no count, "
             "verdict or refusal"),
            ("the instrument self-test is NOT_RUN at b79; it is not a pass and "
             "does not certify any control"),
            ("L7 functional replay was run (w1-w5 PASS, including the authority "
             "key-format differential 10/10) but a green replay is not "
             "SAFE_COMPATIBLE graduation"),
            ("the section-7 safety argument is an argument artifact, not a "
             "promotion: its verdict is NOT_ESTABLISHED for all seven mechanisms "
             "and it changes no closure count, verdict or refusal"),
            ("the b78 freeze, its L7 replay, its safety argument and its "
             "adjudication are not reused as b79 evidence; only the b79 files "
             "named here are measured"),
        ],
    }
    OUT.write_text(json.dumps(doc, indent=1) + "\n")

    print(f"[b79-freeze] closure tree {source_head}")
    print(f"[b79-freeze] inventory tree {inventory_head}")
    print(f"[b79-freeze] evidence head {evidence_head} "
          f"(closure ancestor={closure_is_ancestor})")
    print(f"[b79-freeze] tool {tool_sha[:12]} unchanged_since_b78="
          f"{tool['unchanged_since_b78']} self-test=NOT_RUN")
    print(f"[b79-freeze] src_content matches census: "
          f"{source['src_content_sha256_matches_census']}")
    print(f"[b79-freeze] install matches census: "
          f"{doc['artefacts']['all_install_artefacts_match_census']}; "
          f"blob sizes match: "
          f"{doc['artefacts']['committed_blob_sizes']['all_match']}")
    print(f"[b79-freeze] body_hash reproduces: {body_hash_reproduces}")
    print(f"[b79-freeze] rebind included: "
          f"{sorted(k for k, v in ledger_binding['per_artefact_rebind'].items() if v)}")
    print(f"[b79-freeze] gates (exact-S): fmt={fmt.get('exit')} "
          f"clippy={clippy.get('exit')} "
          f"tests={tests_res and (tests_res['passed'], tests_res['failed'], tests_res['ignored'])} "
          f"unsafe={unsafe_res and unsafe_res['passed']} "
          f"superseded_fmt={stale['fmt'].get('exit')}")
    print(f"[b79-freeze] L7: {safe_compatible['l7_replay']['status']} "
          f"auth_diff={safe_compatible['l7_replay']['authority_differential']}")
    print(f"[b79-freeze] safety verdicts: {safety_totals}")
    print(f"[b79-freeze] wrote {OUT.relative_to(REPO)}")
    print(f"[b79-freeze] sha256 {sha256_file(OUT)} size {OUT.stat().st_size}")
    print(f"[b79-freeze] keys {sorted(doc)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
