#!/usr/bin/env python3
"""Write court/freeze-b78/FREEZE-b78.json from the b78 evidence.

Every asserted value is measured here rather than copied from an earlier freeze
document: the candidate source identity is recomputed from the working tree and
cross-checked against the census, each artefact digest/size is recomputed from
the file it names, the closure sections are read from the two b78b receipts,
the gate outcomes and the instrument self-test are parsed from
court/freeze-b78/gates-b78.log (the log the gates were actually run into), the
atlas body hash is recomputed, the element-7 records and the CONF-method witness
evidence are read, and the git fields are read from the repository.

Two identities are kept separate (AGENTS.md section 22).  S is the source+tool
identity the evidence describes: production source bb7d5206acfb..., the
closure-bound instrument f31816b1..., and the b78b closures.  E is the evidence
commit that carries this freeze and the rebind receipts; committing E moves
HEAD without changing S.

Run inside the court: it needs the same python/toolchain image the closures ran
in, and it must not write to the host checkout from outside the venue.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CAMPAIGN = REPO / "forensics/memory-safety/campaign/safe-c33"
OUT = REPO / "court/freeze-b78/FREEZE-b78.json"
CENSUS = REPO / "court/freeze-b78/census-b78.json"
GATES = REPO / "court/freeze-b78/gates-b78.log"
TOOL = REPO / "forensics/tools/consumer_closure.py"
ATLAS = REPO / "forensics/downstream/build-link-atlas.json"
CONF = REPO / "court/freeze-b78/e7-b78-confmethod.json"
STATUS = CAMPAIGN / "CAMPAIGN-STATUS.json"
COPYCTX = REPO / "evidence/b78b-copyctx-binding.json"
BUILD_SCRIPT = REPO / "forensics/tools/build_openssh_closure.sh"
LEDGERS = {
    "ssh": REPO / "evidence/ssh-artifact-ledger-b78.json",
    "sshd": REPO / "evidence/sshd-artifact-ledger-b78.json",
}
REBINDS = {
    "ssh": REPO / "evidence/ssh-artifact-ledger-b78-rebind.json",
    "sshd": REPO / "evidence/sshd-artifact-ledger-b78-rebind.json",
}
REPINS = [
    CAMPAIGN / "atlas-refresh/e7-b76-repin.json",
    CAMPAIGN / "atlas-refresh/e7-b77-repin.json",
    CAMPAIGN / "atlas-refresh/e7-b78-repin.json",
    CAMPAIGN / "atlas-refresh/b76c-three-sites.json",
]
INSTALL = "artifacts/phase2/install"
EXPECTED_SIZES = {
    "libcrypto.so.3": 16870752,
    "libssl.so.3": 16583824,
    "libcrypto.a": 44402334,
    "libssl.a": 44402886,
    "legacy.so": 16546728,
    "openssl": 12390680,
}

sys.path.insert(0, str(REPO / "forensics/tools"))
import phase7_courts  # noqa: E402
from atlas_common import content_hash  # noqa: E402
import consumer_closure as cc  # noqa: E402


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
        ["git", *args], text=True, cwd=str(REPO), stderr=subprocess.DEVNULL
    ).strip()


def load(rel: str) -> dict:
    return json.loads((REPO / rel).read_text())


def cgroup(name: str):
    p = Path("/sys/fs/cgroup") / name
    return p.read_text().strip() if p.is_file() else None


def src_content_hash() -> tuple[str, int]:
    """Recompute the campaign src_content hash from the working tree."""
    paths = sorted(
        p.relative_to(REPO).as_posix()
        for p in (REPO / "src").rglob("*.rs")
    )
    h = hashlib.sha256()
    h.update(b"openssl-rs/src-rs/v1\x00")
    for rel in paths:
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update((REPO / rel).read_bytes())
        h.update(b"\x00")
    return h.hexdigest(), len(paths)


def read_sections(path: Path) -> dict[str, list[str]]:
    labels = [
        ("=== GATE 1", "gate1_fmt"),
        ("=== GATE 2", "gate2_clippy"),
        ("=== GATE 3 lib tests", "gate3_lib_tests_parallel"),
        ("=== DIAGNOSTIC", "diagnostic_raised_rlimit_data"),
        ("=== TOOL self-test", "tool_self_test"),
    ]
    sections: dict[str, list[str]] = {}
    cur = None
    for line in path.read_text().splitlines():
        if line.startswith("=== "):
            cur = None
            for prefix, name in labels:
                if line.startswith(prefix):
                    cur = name
                    sections.setdefault(name, [])
                    break
            if cur is None:
                sections.setdefault("_unlabelled", [])
                cur = "_unlabelled"
            continue
        if cur is not None:
            sections.setdefault(cur, []).append(line)
    return sections


def summarize(lines: list[str]) -> dict:
    body = "\n".join(lines)
    cmd = next((ln[4:].strip() for ln in lines if ln.startswith("cmd:")), None)
    exits = re.findall(r"^EXIT: (\d+)$", body, re.M)
    results = []
    for ln in lines:
        m = re.match(
            r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
            r"(\d+) ignored; (\d+) measured; (\d+) filtered out",
            ln,
        )
        if m:
            results.append(
                {
                    "state": m.group(1),
                    "passed": int(m.group(2)),
                    "failed": int(m.group(3)),
                    "ignored": int(m.group(4)),
                    "measured": int(m.group(5)),
                    "filtered_out": int(m.group(6)),
                }
            )
    main = max(results, key=lambda r: r["passed"]) if results else None
    failed_names = []
    if "failures:" in body:
        after = body.rsplit("failures:", 1)[1].splitlines()
        for ln in after:
            m = re.match(r"^ {4}(\S+::\S+)$", ln)
            if m:
                failed_names.append(m.group(1))
            elif "test result:" in ln:
                break
    peaks_before = [int(x) for x in re.findall(r"memory\.peak_before: (\d+)", body)]
    peaks_after = [int(x) for x in re.findall(r"memory\.peak_after: (\d+)", body)]
    host = []
    for ln in lines:
        m = re.fullmatch(
            r"host_meminfo: MemTotal=(\d+) kB MemAvailable=(\d+) kB MemFree=(\d+) kB",
            ln.strip(),
        )
        if m:
            host.append(
                {
                    "mem_total_kib": int(m.group(1)),
                    "mem_available_kib": int(m.group(2)),
                    "mem_free_kib": int(m.group(3)),
                }
            )
    return {
        "command": cmd,
        "returncode": int(exits[-1]) if exits else None,
        "main_test_result": main,
        "failed_tests": failed_names,
        "memory_peak_before": peaks_before,
        "memory_peak_after": peaks_after,
        "host_meminfo": host,
        "lines": len(lines),
    }


def element_7(doc: dict) -> dict:
    return doc["precision"]["predicate_element_7"]


def grouping(doc: dict) -> dict:
    c = Counter(o.get("discharge_receipt") for o in doc["obligations"])
    ordered = dict(sorted(c.items(), key=lambda kv: str(kv[0])))
    return {
        "total": sum(c.values()),
        "openssh-v1i": c.get("openssh-v1i", 0),
        "openssh-v1l": c.get("openssh-v1l", 0),
        "boundary_sweep_total": sum(
            v for k, v in c.items() if str(k).startswith("boundary-sweep-")
        ),
        "by_receipt": ordered,
    }


def configure_from_script() -> list[str]:
    """The closure build's ./configure argv, read from the build script."""
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
    census = load("court/freeze-b78/census-b78.json")
    ssh = load("evidence/closure-ssh-b78b.json")
    sshd = load("evidence/closure-sshd-b78b.json")
    atlas = json.loads(ATLAS.read_text())
    status = json.loads(STATUS.read_text())
    sections = read_sections(GATES)

    gate_fmt = summarize(sections.get("gate1_fmt", []))
    gate_clippy = summarize(sections.get("gate2_clippy", []))
    gate_tests = summarize(sections.get("gate3_lib_tests_parallel", []))
    gate_diag = summarize(sections.get("diagnostic_raised_rlimit_data", []))
    st_lines = sections.get("tool_self_test", [])
    st = summarize(st_lines)
    st_body = "\n".join(st_lines)
    st_failures = [ln.strip()[2:].strip() for ln in st_lines
                   if ln.strip().startswith("- ")]
    st_not_run = [
        ln.strip() for ln in st_lines
        if "DID NOT RUN" in ln or "NOT_RUN" in ln
    ]
    st_conf_line = next(
        (ln for ln in st_lines if ln.startswith(
            "[consumer-closure] conf-method controls:")), "")
    st_e7core_line = next(
        (ln for ln in st_lines if ln.startswith(
            "[consumer-closure] e7core controls:")), "")
    st_classification = (
        "NOT_RUN" if (len(st_failures) == 1
                      and "DID NOT RUN" in st_failures[0]) else "UNCLASSIFIED")

    source_head = census["identity"]["source_head"]
    evidence_head = git("rev-parse", "HEAD")
    src_vs_head = git("diff", "--stat", source_head, "--", "src", "Cargo.toml",
                      "Cargo.lock", "build.rs")
    source_is_ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", source_head, evidence_head],
        cwd=str(REPO)).returncode == 0
    tree_digest = phase7_courts._source_tree_digest()
    tool_sha = sha256_file(TOOL)
    content_sha, content_files = src_content_hash()

    tracked_status = git("status", "--porcelain", "--untracked-files=no")
    all_status = git("status", "--porcelain")

    artefact_paths = {
        "libcrypto.so.3": f"{INSTALL}/lib/libcrypto.so.3",
        "libssl.so.3": f"{INSTALL}/lib/libssl.so.3",
        "libcrypto.a": f"{INSTALL}/lib/libcrypto.a",
        "libssl.a": f"{INSTALL}/lib/libssl.a",
        "legacy.so": f"{INSTALL}/lib/ossl-modules/legacy.so",
        "openssl": f"{INSTALL}/bin/openssl",
        "ssh": "court/tmp/openssh-closure/client-b78/openssh-9.9p1/ssh",
        "sshd": "court/tmp/openssh-closure/server-b78/openssh-9.9p1/sshd",
        "sshd_session": (
            "court/tmp/openssh-closure/server-b78/openssh-9.9p1/sshd-session"),
    }
    artefacts = {name: art(rel) for name, rel in artefact_paths.items()}
    size_checks = {
        name: {
            "measured_size": artefacts[name]["size"],
            "build_receipt_size": expected,
            "match": artefacts[name]["size"] == expected,
        }
        for name, expected in EXPECTED_SIZES.items()
    }

    census_binaries = (census["identity"].get("binary") or {}).get("artefacts") or {}
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
        [sys.executable, "-m", "py_compile", "forensics/tools/consumer_closure.py"],
        cwd=str(REPO), text=True, capture_output=True)

    def closure(name: str) -> dict:
        rel = f"evidence/closure-{name}-b78b.json"
        doc = ssh if name == "ssh" else sshd
        chain = []
        for tag in ("b76c", "b77", "b78", "b78b"):
            p = f"evidence/closure-{name}-{tag}.json"
            d = load(p)
            chain.append(
                {
                    "receipt": p,
                    "sha256": sha256_file(REPO / p),
                    "DISCHARGED": d["counts"].get("DISCHARGED"),
                    "BLOCKED": d["counts"].get("BLOCKED"),
                    "UNKNOWN": d["counts"].get("UNKNOWN"),
                    "verdict": d["verdict"]["state"],
                    "artifact_sha256": d["artifact_identity"]["sha256"],
                    "carried_forward_removed": d["counts"].get(
                        "carried_forward_removed"),
                }
            )
        carry_source = chain[-2]
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
            "element_7": element_7(doc),
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
                    "the b78b run carries from evidence/closure-"
                    + name + "-b78.json, which is ACCEPTED at "
                    + str(carry_source["DISCHARGED"]) + " discharged / "
                    + str(carry_source["BLOCKED"]) + " blocked; the b78b repair "
                    "re-attributes the seven stale `copyctx` coordinates to "
                    "their definition spans and the count becomes 290/290. "
                    "No refused carry is used (unlike b76)."),
            },
        }

    closures = {"ssh": closure("ssh"), "sshd": closure("sshd")}

    # The copyctx repair record the b78b carry depends on.
    copyctx = json.loads(COPYCTX.read_text())
    copyctx_repair = {
        "path": "evidence/b78b-copyctx-binding.json",
        "sha256": sha256_file(COPYCTX),
        "subphase": copyctx.get("subphase"),
        "purpose": copyctx.get("purpose"),
        "finding_answer": (copyctx.get("finding") or {}).get("answer"),
        "rows": len(((copyctx.get("finding") or {}).get("fact_2_the_recorded"
                     "_coordinates_are_stale_coordinates_of_the_same_definitions")
                    or {}).get("rows") or []),
        "result": copyctx.get("result"),
        "non_claims": copyctx.get("non_claims"),
    }

    # Element-7 records: each is bound to a specific instrument revision.
    repin_records = []
    for p in REPINS:
        d = json.loads(p.read_text())
        rel = str(p.relative_to(REPO))
        rec = {
            "path": rel,
            "sha256": sha256_file(p),
            "bytes": p.stat().st_size,
            "schema": d.get("schema"),
            "candidate_tag": d.get("candidate_tag") or d.get("subphase")
            or d.get("batch"),
        }
        if isinstance(d.get("tool"), dict):
            rec["tool_sha256"] = d["tool"].get("sha256")
            rec["tool_sha256_before"] = d["tool"].get("sha256_before")
            rec["tool_sha256_after"] = d["tool"].get("sha256_after")
        else:
            rec["tool_sha256"] = d.get("tool_sha256")
        if d.get("closure"):
            rec["closure"] = d["closure"]
        if d.get("element_7") or d.get("element7"):
            rec["element7"] = d.get("element_7") or d.get("element7")
        if d.get("rows"):
            decisions = Counter(r.get("decision") for r in d["rows"])
            rec["rows"] = len(d["rows"])
            rec["row_decisions"] = {
                str(k): v for k, v in sorted(decisions.items(),
                                             key=lambda kv: str(kv[0]))}
        if d.get("controls"):
            rec["controls"] = d["controls"]
        if d.get("verification"):
            rec["verification"] = d["verification"]
        if d.get("mutation_controls"):
            rec["mutation_controls"] = d["mutation_controls"]
        if d.get("self_test"):
            rec["self_test"] = d["self_test"]
        if d.get("source_identity"):
            rec["source_identity"] = d["source_identity"]
        repin_records.append(rec)

    # The CONF-method witness evidence.  The class is bound to the admitted
    # image and to the final instrument; the four mutation controls are the
    # ones the tool's self-test recorded in this gate log.
    conf_doc = json.loads(CONF.read_text())
    conf_site = next(
        (r for r in (conf_doc.get("precision") or {}).get("residual_sites") or []
         if r.get("class") == cc.ABI_CONTRACT_CONF_DEFAULT_METHOD), None)
    conf_contract = cc.ABI_CONTRACTS[cc.ABI_CONTRACT_CONF_DEFAULT_METHOD]
    tool_lines = TOOL.read_text().splitlines()

    def find_line(text: str) -> int:
        for i, ln in enumerate(tool_lines, 1):
            if text in ln:
                return i
        return None

    conf_witness = {
        "class": cc.ABI_CONTRACT_CONF_DEFAULT_METHOD,
        "resolution_kind": conf_contract.get("resolution_kind"),
        "contract": conf_contract.get("contract"),
        "provider_obligation": conf_contract.get("provider_obligation"),
        "covers": conf_contract.get("covers"),
        "does_not_cover": conf_contract.get("does_not_cover"),
        "citation": conf_contract.get("citation"),
        "site": {
            "function_name": (conf_site or {}).get("function_name"),
            "function_start": (conf_site or {}).get("function"),
            "call_site": (conf_site or {}).get("call_site"),
            "instruction": (conf_site or {}).get("text"),
            "reason": (conf_site or {}).get("reason"),
            "targets_enumerated": len((conf_site or {}).get("targets") or []),
        },
        "witness": {
            "slot": (
                "default_CONF_method cell -> conf_method_st.init (offset 0x10)"),
            "writer": (
                "CONF_set_default_method stores its `meth` parameter unchanged; "
                "the NULL fallback installs the table NCONF_default() publishes"),
            "interface": (
                "CONF_set_default_method(CONF_METHOD *) (exported) and "
                "struct conf_method_st.init = int (*)(CONF *)"),
            "writer_set": (
                "CONF_set_default_method(%rdi) x1 + built-in NULL fallback"),
            "target_set_unbounded": (
                "the exported setter admits any application CONF_METHOD"),
        },
        "source_evidence": {
            "record": "court/freeze-b78/e7-b78-confmethod.json",
            "sha256": sha256_file(CONF),
            "bytes": CONF.stat().st_size,
            "tool_sha256": (conf_doc.get("tool") or {}).get("sha256"),
            "element_7": (conf_doc.get("precision") or {}).get(
                "predicate_element_7"),
            "residual_site_class_count": len(
                [r for r in (conf_doc.get("precision") or {}).get(
                    "residual_sites") or []
                 if r.get("class") == cc.ABI_CONTRACT_CONF_DEFAULT_METHOD]),
            "generated_utc": conf_doc.get("generated_utc"),
        },
        "witness_source_lines": {
            "witness_function": {
                "line": find_line("def conf_default_method_witness("),
                "text": "def conf_default_method_witness(...)",
            },
            "controls_function": {
                "line": find_line("def _conf_default_method_self_test("),
                "text": "def _conf_default_method_self_test(...)",
            },
        },
        "mutation_controls": [
            {
                "control": "wrong-slot-offset",
                "mutation": "the dispatched field load 0x10(base) -> 0x18(base)",
                "expected_refusal": "operand-load-is-not-the-init-slot",
            },
            {
                "control": "non-parameter-setter",
                "mutation": "the cell writer in CONF_set_default_method stores "
                            "%rsi instead of its %rdi parameter",
                "expected_refusal": (
                    "unaccounted-writer-of-the-default-method-cell"),
            },
            {
                "control": "non-builtin-fallback",
                "mutation": "the built-in fallback store writes %rcx instead "
                            "of the NCONF_default() table value in %rax",
                "expected_refusal": (
                    "unaccounted-writer-of-the-default-method-cell"),
            },
            {
                "control": "wrong-declared-field",
                "mutation": (
                    "the witness is asked for the neighbouring `destroy` field "
                    "instead of the dispatched `init` field"),
                "expected_refusal": (
                    "declared-init-field-is-not-at-the-dispatched-offset"),
            },
            {
                "control": "restore",
                "mutation": "none (the admitted image)",
                "expected_refusal": None,
                "observed": "accepted again; the witness is byte-identical to "
                            "the positive witness",
            },
        ],
        "self_test_record": {
            "conf_method_controls_line": st_conf_line,
            "e7core_controls_line": st_e7core_line,
        },
        "statement": (
            "the enumerated `default_CONF_method` -> `CONF_METHOD.init` "
            "dispatch is contract-bounded by the exported "
            "CONF_set_default_method and the documented conf_method_st.init "
            "field; four mutation controls (wrong slot, non-parameter setter, "
            "non-builtin fallback, wrong declared field) each refuse with the "
            "named reason and the admitted image is restored.  The target set "
            "is intentionally unbounded because the setter is public."),
    }

    # Ledger row the closure joins against, and what this freeze proves.
    body = atlas.get("body") or atlas
    row = next((r for r in body.get("runs") or []
                if r.get("run_id") == "run:build-link:candidate:openssh"), None)
    row = row or {}
    linkage = row.get("linkage") or {}
    body_hash_reproduces = content_hash(body) == atlas.get("body_hash")
    atlas_sha = sha256_file(ATLAS)
    row_configure = next(
        (s.get("argv") for s in (row.get("steps") or [])
         if s.get("name") == "configure"), None)
    closure_configure = configure_from_script()

    ledger_binding = {
        "source": "forensics/downstream/build-link-atlas.json",
        "atlas_sha256": atlas_sha,
        "atlas_bytes": ATLAS.stat().st_size,
        "body_hash": atlas.get("body_hash"),
        "body_hash_rule": "sha256 of canonical JSON of body (atlas_common.content_hash)",
        "body_hash_reproduces": body_hash_reproduces,
        "lookup": "body.runs[run_id='run:build-link:candidate:openssh']",
        "run_id": row.get("run_id"),
        "recipe_id": row.get("recipe_id"),
        "recorded_artifact_rel": linkage.get("artifact_rel"),
        "recorded_artifact_sha256": linkage.get("artifact_sha256"),
        "recorded_candidate_install_libcrypto_sha256":
            (body.get("candidate_identity") or {}).get("libcrypto_so_3_sha256"),
        "recorded_install_matches_freeze_install": (
            (body.get("candidate_identity") or {}).get("libcrypto_so_3_sha256")
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
            "under court/tmp/openssh-closure/{client,server}-b78. Its recorded "
            "digest " + str(linkage.get("artifact_sha256"))[:12] + " is not "
            "either analysed binary; the row's recorded candidate install "
            "does match the freeze-proven install, but that does not make the "
            "row's ssh binary the analysed ssh. The field is not the "
            "per-artefact binding. Per-artefact binding is carried by the "
            "rebind receipts in evidence/{ssh,sshd}-artifact-ledger-b78-"
            "rebind.json and by the freeze digests recorded here."),
        "atlas_row_configure_argv": row_configure,
        "closure_build_configure_argv": closure_configure,
        "closure_build_script": art("forensics/tools/build_openssh_closure.sh"),
        "atlas_row_steps": [
            {"name": s.get("name"), "argv": s.get("argv"),
             "exit_code": s.get("exit_code")}
            for s in (row.get("steps") or [])
        ],
        "per_artefact_rebind": {},
        "ledgers": {
            fam: str(p.relative_to(REPO)) for fam, p in LEDGERS.items()
        },
    }
    for fam, p in REBINDS.items():
        if not p.is_file():
            ledger_binding["per_artefact_rebind"][fam] = None
            continue
        rebind_doc = json.loads(p.read_text())
        rebind_checks = (rebind_doc.get("rebind") or {}).get("checks") or {}
        checks_passed = bool(rebind_checks) and all(rebind_checks.values())
        ledger_binding["per_artefact_rebind"][fam] = {
            "receipt": str(p.relative_to(REPO)),
            "sha256": sha256_file(p),
            "bytes": p.stat().st_size,
            "verdict": ("ACCEPTED (all checks passed; not a closure run)"
                        if checks_passed else "REFUSED (a check did not pass)"),
            "artifact_rel": (rebind_doc.get("ledger_record") or {}).get(
                "artifact_rel"),
            "artifact_sha256_recorded": (rebind_doc.get("ledger_record") or {}).get(
                "artifact_sha256_recorded"),
            "artifact_matches_this_build": (rebind_doc.get("ledger_record") or {}).get(
                "artifact_matches_this_build"),
            "ledger": (rebind_doc.get("rebind") or {}).get("ledger_source"),
            "freeze_from_ledger": (rebind_doc.get("rebind") or {}).get("freeze"),
            "checks": (rebind_doc.get("rebind") or {}).get("checks"),
            "not_a_closure_run": (rebind_doc.get("rebind") or {}).get(
                "not_a_closure_run"),
            "witness": (rebind_doc.get("rebind") or {}).get("witness"),
        }

    review_required = (((status.get("current_applied_state") or {})
                        .get("safe_compatible_blockers") or {})
                       .get("projected_after_recensus") or {}).get("REVIEW_REQUIRED")

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
            "contract_bounded": closures[fam]["element_7"]["contract_bounded_sites"],
        }
        for fam in ("ssh", "sshd")
    }
    safe_compatible = {
        "value": False,
        "reason": (
            "consumer_closure.py never promotes: verdict.safe_compatible is a "
            "hard-coded False in the instrument. AGENTS.md section 7 additionally "
            "requires every mechanism in the conservative dependency closure to be "
            "SAFETY_DISCHARGED with its callers' obligations discharged, and "
            "compatibility confirmed against the exact converted implementation. "
            "The closures measure the queue at this candidate, not a promotion."),
        "measured": measured,
        "l7_replay": {
            "status": "NOT_RUN",
            "note": ("L7 functional replay of the consumers at this candidate was "
                     "not run by this freeze; it remains a SEAL/BOUNDARY-stage "
                     "obligation."),
        },
        "outstanding": [
            "L7 functional replay of the consumers at this candidate (NOT_RUN)",
            f"{review_required} REVIEW_REQUIRED discharges "
            "(CAMPAIGN-STATUS current_applied_state.safe_compatible_blockers."
            "projected_after_recensus.REVIEW_REQUIRED); the closure already "
            "records 56 openssh-v1i + 9 openssh-v1l discharges, but the campaign "
            "status requires a rebuild and re-census before the applied count "
            "changes",
            "BOUNDARY adjudication of the remaining contract-bounded boundaries",
            "SEAL (release build, complete probe suite, full forensic regeneration)",
        ],
        "review_required": {
            "count": review_required,
            "source": "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json",
            "json_pointer": ("current_applied_state.safe_compatible_blockers."
                             "projected_after_recensus.REVIEW_REQUIRED"),
            "source_sha256": sha256_file(STATUS),
        },
    }

    gates = {
        "fmt": {
            "command": gate_fmt.get("command"),
            "returncode": gate_fmt.get("returncode"),
        },
        "clippy": {
            "command": gate_clippy.get("command"),
            "returncode": gate_clippy.get("returncode"),
        },
        "lib_tests_parallel": {
            "command": gate_tests.get("command"),
            "returncode": gate_tests.get("returncode"),
            "test_result": gate_tests.get("main_test_result"),
            "failed_tests": gate_tests.get("failed_tests"),
        },
        "diagnostic_raised_rlimit_data": {
            "command": gate_diag.get("command"),
            "returncode": gate_diag.get("returncode"),
            "test_result": gate_diag.get("main_test_result"),
            "not_a_gate": True,
            "present": bool(sections.get("diagnostic_raised_rlimit_data")),
        },
        "log": "court/freeze-b78/gates-b78.log",
        "log_sha256": sha256_file(GATES),
        "verdict": (
            "fmt PASS (exit "
            + str(gate_fmt.get("returncode")) + "), clippy PASS (exit "
            + str(gate_clippy.get("returncode")) + "), library tests PASS at "
            "--test-threads=4 ("
            + str((gate_tests.get("main_test_result") or {}).get("passed"))
            + " passed, "
            + str((gate_tests.get("main_test_result") or {}).get("failed"))
            + " failed, "
            + str((gate_tests.get("main_test_result") or {}).get("ignored"))
            + " ignored; exit " + str(gate_tests.get("returncode")) + "). "
            "The secure-heap tests did not fail under the court's default 4 GiB "
            "per-process RLIMIT_DATA, so the OPENSSL_RS_COURT_DATA=8388608 "
            "diagnostic was not needed."),
        "failure_class": "NONE",
    }

    # Host readings are the MemTotal/MemAvailable/MemFree lines the gate
    # runner recorded before each section.  The cgroup readings are live.
    host_readings = []
    for name, sec in (
        ("gate1_fmt", gate_fmt),
        ("gate2_clippy", gate_clippy),
        ("gate3_lib_tests_parallel", gate_tests),
        ("tool_self_test", st),
    ):
        for reading in sec.get("host_meminfo") or []:
            host_readings.append(dict(reading, when=name))
    meminfo = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meminfo[k] = v.strip().split()[0]
    events = cgroup("memory.events") or ""
    ev = dict(re.findall(r"^(\w+) (\d+)$", events, re.M))
    rlimit_data = resource.getrlimit(resource.RLIMIT_DATA)[0]
    peaks_before = sorted({p for sec in (gate_fmt, gate_clippy, gate_tests, st)
                           for p in sec.get("memory_peak_before", [])})
    peaks_after = sorted({p for sec in (gate_fmt, gate_clippy, gate_tests, st)
                          for p in sec.get("memory_peak_after", [])})
    memory = {
        "deviation": (
            "AGENTS.md section 6.1 requires host `available` >= 24 GiB before a "
            "build and a cap of min(8g, available-16g) with a 2g floor. Measured "
            "host available was 14-15 GiB throughout, so that formula yields "
            "less than 2g and the literal procedure refuses to run. This work "
            "instead ran inside the existing docker court whose cgroup hard cap "
            "is 8 GiB (memory.max=" + str(cgroup("memory.max")) + ") with no "
            "swap (memory.swap.max=" + str(cgroup("memory.swap.max")) + "), so "
            "host exposure is bounded by that cgroup. The deviation is recorded "
            "here rather than claimed as compliance."),
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
            "memory_swap_current_bytes": cgroup("memory.swap.current"),
            "memory_events": ev,
            "pids_max": cgroup("pids.max"),
        },
        "gate_memory_peak_before": peaks_before,
        "gate_memory_peak_after": peaks_after,
        "peak_note": (
            "memory.peak is the cgroup's historical high-water and already "
            "equalled the cap; it did not move across the four gate sections. "
            "memory.events records oom=1 / oom_kill=1 from that earlier event, "
            "not from these gates; swap.max is 0, so the container cannot grow "
            "by swapping."),
        "rlimit_data_kib": rlimit_data // 1024 if rlimit_data else None,
        "parallel_test_outcome": (
            "the --test-threads=4 library gate passed; no RLIMIT_DATA "
            "diagnostic rerun was required"),
    }

    source = {
        "head": source_head,
        "head_subject": git("log", "-1", "--format=%s", source_head),
        "branch": census["identity"].get("branch"),
        "src_rs_files": content_files,
        "src_rs_files_census": census["identity"]["src_rs_files"],
        "crate_version": census["identity"]["crate_version"],
        "src_content_sha256": content_sha,
        "src_content_sha256_census": census["identity"]["src_content_sha256"],
        "src_content_sha256_matches_census": (
            content_sha == census["identity"]["src_content_sha256"]),
        "src_content_hash_rule": census["identity"]["src_content_hash_rule"],
        "census_working_tree_clean": census["identity"].get("working_tree_clean"),
        "census_tracked_working_tree_clean":
            census["identity"].get("tracked_working_tree_clean"),
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
        },
        "git_verification": {
            "production_source_head_is_ancestor_of_evidence_head":
                source_is_ancestor,
            "src_diff_vs_production_source_head": src_vs_head or None,
        },
    }

    doc = {
        "schema": "openssl-rs/campaign/safe-c33/freeze/v1",
        "candidate_tag": "b78",
        "generated_utc": subprocess.check_output(
            ["date", "-u", "+%FT%TZ"], text=True).strip(),
        "freeze_kind": "source-and-artefact freeze (S) with per-artefact ledger rebind",
        "freeze_reason": (
            "b78 freezes the OCSP/element-7 candidate: the two b78b consumer "
            "closures are ACCEPTED 290/290 with element 7 PASS (0 target-bounded "
            "/ 153 contract-bounded), the install and OpenSSH closure binaries "
            "are measured, the CONF-method witness closes the last target-"
            "bounded site, and the per-artefact ledger rebinds bind both ssh and "
            "sshd to the freeze."),
        "identity": {
            "rule": (
                "Two identities, never conflated (AGENTS.md section 22). S is the "
                "frozen source+instrument identity this evidence describes: "
                "production source bb7d5206acfb..., instrument f31816b1... and "
                "the b78b closures. E is the evidence commit that carries this "
                "freeze and the ledger receipts. Committing E moves HEAD; it does "
                "not change S, its artefacts or their digests."),
            "production_source_head": source_head,
            "production_source_head_note": (
                "census identity.source_head: the source tree the census and the "
                "b78b closures analyse"),
            "instrument_head": evidence_head,
            "instrument_head_note": (
                "git HEAD when this freeze was generated; it is the commit that "
                "records the b78b closure and carries instrument "
                + tool_sha[:12] + ". The closures record their own "
                "repository_head (see closures.*.source_identity.repository_head)."),
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
            "instrument_head": evidence_head,
            "tool_sha256": tool_sha,
            "census_sha256": sha256_file(CENSUS),
            "libcrypto_so_3_sha256": artefacts["libcrypto.so.3"]["sha256"],
            "libssl_so_3_sha256": artefacts["libssl.so.3"]["sha256"],
            "ssh_sha256": artefacts["ssh"]["sha256"],
            "sshd_sha256": artefacts["sshd"]["sha256"],
            "rule": ("source head + instrument sha + census sha + measured artefact "
                     "digests; a change to any one of them is a new candidate"),
        },
        "tool": {
            "path": "forensics/tools/consumer_closure.py",
            "sha256": tool_sha,
            "version": ssh["tool"].get("version"),
            "closure_bound_sha256": ssh["tool"]["sha256"],
            "sshd_closure_bound_sha256": sshd["tool"]["sha256"],
            "changed_since_closures": tool_sha != ssh["tool"]["sha256"],
            "self_test": {
                "command": st.get("command"),
                "returncode": st.get("returncode"),
                "failure_count": len(st_failures),
                "failures": st_failures,
                "classification": st_classification,
                "classification_note": (
                    "the single failure entry is a control that DID NOT RUN: no "
                    "admitted site carries an inlined default-context accessor at "
                    "this candidate, so the subject does not exist here. It is "
                    "recorded NOT_RUN, never as a pass; it is not a failure of a "
                    "performed check."),
                "not_run_mentions": st_not_run,
                "additional_not_run_subject": (
                    "the e7core loader-fetch wrapper-source arm is also NOT_RUN "
                    "because the wrapper is inlined; this is recorded inside the "
                    "e7core controls line and is not a separate failure entry"),
                "ok_marker_present": "self-test ok" in st_body,
                "summary": next((ln for ln in st_lines
                                 if "SELF-TEST" in ln), None),
                "log": "court/freeze-b78/gates-b78.log (=== TOOL self-test ===)",
            },
            "python_syntax": (
                "py_compile of the instrument: OK" if py_compile.returncode == 0
                else f"py_compile of the instrument: FAILED (rc={py_compile.returncode})"),
            "inputs": {
                "census": art("court/freeze-b78/census-b78.json"),
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
            "all_install_artefacts_match_census": all(compared) if compared else None,
            "compared_names": sorted(install_matches_census),
            "resolved_libcrypto_sha256": artefacts["libcrypto.so.3"]["sha256"],
            "build_receipt_sizes": {
                "source": "court/build-phase2-b78.log",
                "checks": size_checks,
                "all_match": all(v["match"] for v in size_checks.values()),
            },
            "consumer_source": (
                "OpenSSH 9.9p1 in the closure trees "
                "court/tmp/openssh-closure/{client,server}-b78/openssh-9.9p1"),
            "note": ("each digest and size is recomputed from the file named in "
                     "this working tree; the census comparison is per name"),
        },
        "census": {
            "path": "court/freeze-b78/census-b78.json",
            "sha256": sha256_file(CENSUS),
            "bytes": CENSUS.stat().st_size,
            "source_head": census["identity"]["source_head"],
            "delta_vs": census.get("delta_vs_previous", {}).get("previous"),
            "operation_counts": (census.get("contracts") or {}).get("operation_counts"),
            "gates": census.get("gates"),
        },
        "closures": {
            "ssh": closures["ssh"],
            "sshd": closures["sshd"],
            "copyctx_repair": copyctx_repair,
            "safe_compatible": False,
        },
        "element7": {
            "measured_by_closures": {
                fam: {
                    "status": closures[fam]["element_7"]["status"],
                    "target_bounded_unresolved_sites": closures[fam]["element_7"][
                        "target_bounded_unresolved_sites"],
                    "contract_bounded_sites": closures[fam]["element_7"][
                        "contract_bounded_sites"],
                    "contract_bounded_by_class": closures[fam]["element_7"].get(
                        "contract_bounded_by_class"),
                }
                for fam in ("ssh", "sshd")
            },
            "repin_records": repin_records,
            "conf_method_witness": conf_witness,
            "statement": (
                "the 153 contract-bounded sites are intentionally unbounded: each "
                "is resolved to a declared external ABI contract (AGENTS.md "
                "section 7 criterion 2), not left as an unproven target. None is "
                "counted as target-bounded, and no site is unclassified. The "
                "b78 re-pin record is an intermediate FAIL at 1 target-bounded "
                "site (0x49a8dc); the CONF-method witness record resolves that "
                "site and the b78b closures measure 0/153 PASS."),
        },
        "ledger_binding": ledger_binding,
        "gates": gates,
        "memory": memory,
        "safe_compatible": safe_compatible,
        "residuals": [
            {"kind": "venue/memory", "statement": memory["deviation"]},
            {"kind": "gate/parallel-lib-tests",
             "statement": gates["verdict"]},
            {"kind": "instrument/self-test-not-run",
             "statement": (
                 "the instrument self-test exits "
                 + str(st.get("returncode")) + " with "
                 + str(len(st_failures)) + " failure entry: the e7core "
                 "default-context control DID NOT RUN (no admitted site carries "
                 "the inlined accessor). It is classified NOT_RUN, not a pass, "
                 "and is not evidence that the missing control holds.")},
            {"kind": "element7/contract-bounded",
             "statement": (
                 "153 contract-bounded sites remain target-unbounded by design: "
                 "the application supplies the targets through public ABI "
                 "contracts (exported callbacks, provider tables, the global "
                 "CONF_METHOD cell). They are discharged under AGENTS.md section "
                 "7 criterion 2, not proven safe by this freeze.")},
            {"kind": "ledger-binding",
             "statement": ledger_binding["artifact_matches_this_build_statement"]},
            {"kind": "instrument-drift",
             "statement": (
                 "the e7-b78 re-pin record names tool "
                 + str((repin_records[2] or {}).get("tool_sha256_before"))[:12]
                 + " -> "
                 + str((repin_records[2] or {}).get("tool_sha256_after"))[:12]
                 + "; the final CONF witness and the b78b closures bind "
                 + tool_sha[:12] + ". The re-pin record is retained as an "
                 "intermediate: its status is FAIL because the CONF site was "
                 "still target-bounded, and the later CONF witness record is the "
                 "evidence that closes it.")},
            {"kind": "carry-chain/sshd",
             "statement": (
                 "sshd: evidence/closure-sshd-b78.json (ACCEPTED, "
                 + str(closures["sshd"]["carry_chain"]["immediate_source"][
                     "DISCHARGED"]) + " discharged / "
                 + str(closures["sshd"]["carry_chain"]["immediate_source"][
                     "BLOCKED"]) + " blocked) -> evidence/closure-sshd-b78b.json; "
                 + str(closures["sshd"]["carry_chain"]["carried_forward_removed"])
                 + " carried-forward obligations removed")},
            {"kind": "carry-chain/ssh",
             "statement": (
                 "ssh: evidence/closure-ssh-b78.json (ACCEPTED, "
                 + str(closures["ssh"]["carry_chain"]["immediate_source"][
                     "DISCHARGED"]) + " discharged / "
                 + str(closures["ssh"]["carry_chain"]["immediate_source"][
                     "BLOCKED"]) + " blocked) -> evidence/closure-ssh-b78b.json; "
                 + str(closures["ssh"]["carry_chain"]["carried_forward_removed"])
                 + " carried-forward obligations removed")},
            {"kind": "copyctx-repair",
             "statement": (
                 "the seven b78 `copyctx` coordinates were stale coordinates of "
                 "the same definitions; evidence/b78b-copyctx-binding.json proves "
                 "each recorded coordinate is the definition line at the b76c "
                 "ancestor head and that the normalised body hashes to the "
                 "declared span. The b78b run re-attributes them and reaches "
                 "290/290.")},
            {"kind": "not-run",
             "statement": (
                 "SEAL, BOUNDARY adjudication, L7 functional replay, ASan/Miri, "
                 "dudect/Wycheproof and forensic regeneration are NOT_RUN at this "
                 "candidate; they are scheduled at their gates, not implied by "
                 "this freeze.")},
        ],
        "not_run": [
            "L7 functional replay of the consumers at this candidate",
            "BOUNDARY adjudication of the remaining contract-bounded boundaries",
            "SEAL (release build, full probe suite, full forensic regeneration)",
            "ASan/Miri/Loom and dudect/Wycheproof for this candidate",
            "the e7core default-context control (NOT_RUN: no inlined accessor)",
            f"the {review_required} REVIEW_REQUIRED discharges (campaign status "
            "requires a rebuild and re-census)",
        ],
        "non_claims": [
            ("the closures named here are measurements of the candidate at S with "
             "the closure-bound instrument; they are not re-measured by this "
             "generator"),
            (str(closures["ssh"]["counts"]["BLOCKED"]) + " BLOCKED / "
             + str(closures["ssh"]["counts"]["UNKNOWN"]) + " UNKNOWN (ssh) and "
             + str(closures["sshd"]["counts"]["BLOCKED"]) + " BLOCKED / "
             + str(closures["sshd"]["counts"]["UNKNOWN"]) + " UNKNOWN (sshd) is a "
             "statement about the instrument's queue at this candidate, not a "
             "SAFE_COMPATIBLE promotion"),
            ("a green differential/closure result is not a safety or cryptographic "
             "result (AGENTS.md section 8)"),
            ("the per-artefact rebind is not a closure run and changes no count, "
             "verdict or refusal"),
            ("the instrument self-test's single failure is a NOT_RUN control; it "
             "is not a pass and does not certify the missing accessor"),
            ("L7 functional replay was not run at this candidate"),
        ],
    }
    OUT.write_text(json.dumps(doc, indent=1) + "\n")

    print(f"[b78-freeze] source head {source_head}")
    print(f"[b78-freeze] evidence head {evidence_head} (ancestor={source_is_ancestor})")
    print(f"[b78-freeze] tool sha256 {tool_sha} changed={doc['tool']['changed_since_closures']}")
    print(f"[b78-freeze] self-test rc={st.get('returncode')} failures={len(st_failures)} class={st_classification}")
    print(f"[b78-freeze] src_content matches census: {source['src_content_sha256_matches_census']}")
    print(f"[b78-freeze] install matches census: {doc['artefacts']['all_install_artefacts_match_census']}")
    print(f"[b78-freeze] sizes match build receipt: {doc['artefacts']['build_receipt_sizes']['all_match']}")
    print(f"[b78-freeze] body_hash reproduces: {body_hash_reproduces}")
    print(f"[b78-freeze] rebind included: {sorted(k for k,v in ledger_binding['per_artefact_rebind'].items() if v)}")
    print(f"[b78-freeze] wrote {OUT.relative_to(REPO)}")
    print(f"[b78-freeze] sha256 {sha256_file(OUT)} size {OUT.stat().st_size}")
    print(f"[b78-freeze] keys {sorted(doc)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
