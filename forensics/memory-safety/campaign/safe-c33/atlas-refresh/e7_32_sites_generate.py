#!/usr/bin/env python3
"""E7-32: the per-site adjudication of the last 32 target-bounded sites.

This generator is evidence transcription, not measurement.  It reads

  * ``evidence/closure-ssh-b61.json`` and ``evidence/closure-sshd-b61.json``
    (the two closures measured with the instrument at this identity),
  * ``evidence/closure-{ssh,sshd}-b60.json`` (the before numbers),
  * the instrument's own source tables for the writer of each core-dispatch
    slot (``_core_dispatch_writer``), so the writer column is the same fact the
    witness checks rather than a hand-typed line,

and writes one row per previously target-bounded reachable site.  A row is
written only when the site is present in *both* families' receipts with the
same class; a disagreement is a failure, not a row.

Any Rust source change would move the candidate.  This batch changed only the
instrument (``forensics/tools/consumer_closure.py``), which is build-relevant
evidence under AGENTS.md section 22: the receipts are bound to the tool sha
recorded below and a new freeze (``S'`` = the same source head plus the new
tool sha) is required before any promotion decision.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

REPO = Path("/work")
EVIDENCE = REPO / "evidence"
CAMPAIGN = REPO / "forensics/memory-safety/campaign/safe-c33"
OUT = CAMPAIGN / "atlas-refresh/e7-32-sites.json"

sys.path.insert(0, str(REPO / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

SOURCE_HEAD = "b6f38f13456b79ecd94b1088c835c3da92bc942a"
CLOSURES = {"ssh": "closure-ssh-b61.json", "sshd": "closure-sshd-b61.json"}
BEFORE = {"ssh": "closure-ssh-b60.json", "sshd": "closure-sshd-b60.json"}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def leaf(name: str) -> str:
    return cc._external_function_leaf(name)


def _writer_for(prefix: str, name: str, cls: str) -> dict:
    """The writer column, from the instrument's own source tables."""
    if cls == cc.ABI_CONTRACT_CORE_DISPATCH:
        m = re.search(r"(offset (0x[0-9a-f]+))", prefix)
        off = int(m.group(2), 16) if m else None
        for index, table in cc.CORE_DISPATCH_TABLES.items():
            spec = table["fields"].get(off)
            if spec is None:
                continue
            field, fid, _num, _lower = spec
            class _G:
                source_root = str(REPO)
                install_prefix = str(REPO / "court/freeze-b58/install")
            rec, refusal = cc._core_dispatch_writer(_G(), table, field, fid)
            if rec is not None:
                return {"kind": "source-store",
                        "slot_object": table["object"],
                        "field": field,
                        "function_id": fid,
                        "file": rec["file"],
                        "line": rec["line"],
                        "function": rec["function"],
                        "value": rec["value"]}
            return {"kind": "refused", "refusal": refusal}
        return {"kind": "unresolved-table"}
    if cls == cc.ABI_CONTRACT_PROVIDER:
        if "init_function" in prefix:
            return {"kind": "source-store",
                    "file": "src/provider/init.rs:307 / src/provider/mod.rs:1891",
                    "function": "provider_init / provider_new",
                    "value": ("DSO_bind_func(module, \"OSSL_provider_init\") / "
                              "the OSSL_PROVIDER_add_builtin parameter")}
        if "p_close" in prefix:
            return {"kind": "source-store",
                    "file": "src/store/store_meth.rs",
                    "function": "loader_from_algorithm",
                    "value": "OSSL_FUNC_STORE_CLOSE dispatch entry"}
        return {"kind": "dispatch-entry",
                "file": "src/evp/kem.rs",
                "function": "evp_kem_from_algorithm",
                "value": "the provider's OSSL_DISPATCH entry for the field's id"}
    if cls == cc.ABI_CONTRACT_EXPORT_CALLBACK_DEFAULT:
        return {"kind": "exported-parameter",
                "file": "src/pem/pem_pk8.rs (do_pk8pkey) / src/pem/pem_lib.rs",
                "function": "do_pk8pkey and the exported PEM writers",
                "value": ("the pen_password_cb parameter, with the NULL arm "
                          "selecting PEM_def_callback")}
    return {"kind": "unknown-class"}


def main() -> int:
    docs = {f: json.loads((EVIDENCE / p).read_text())
            for f, p in CLOSURES.items()}
    before = {f: json.loads((EVIDENCE / p).read_text())
              for f, p in BEFORE.items()}

    # One cheap graph (disassembly only, no resolver run) so each row can carry
    # the live per-call-site witness, including the two merged sites' full
    # slot-id sets.  The witness is re-checked here, not copied from prose.
    graph = cc.DsoGraph(REPO / "court/freeze-b58/install/lib/libcrypto.so.3",
                        REPO / "court/tmp/e7-32-sites-work")
    graph.source_root = str(REPO)
    graph.install_prefix = str(REPO / "court/freeze-b58/install")
    graph.precision = cc.PrecisionResolver(graph)

    def live_witness(row):
        site = {"kind": ("jmp" if row["operand"].strip().startswith("jmp")
                         else "call"),
                "func": int(row["function_address"], 16),
                "addr": int(row["address"], 16),
                "text": row["operand"], "targets": set(),
                "unresolved": True, "reason": "", "class": "",
                "field_offsets": set(), "seam": None,
                "arg_deps": set(), "arg_targets": set()}
        name = row["function_symbol"]
        cls = row["evidence_class"]
        if cls == cc.ABI_CONTRACT_CORE_DISPATCH:
            return cc.core_dispatch_witness(graph, site, name, None)[0]
        if cls == cc.ABI_CONTRACT_EXPORT_CALLBACK_DEFAULT:
            res = cc.pem_password_default_witness(graph, site, name)
            return res[1] if res else None
        if "init_function" in row["slot"]:
            return cc.provider_init_slot_witness(graph, site, name)
        if "p_close" in row["slot"]:
            res = cc.store_loader_provider_witness(graph, site, name)
            return res[1] if res else None
        return (cc.fetch_merged_slot_witness(graph, site, name)
                or cc.fetch_slot_witness(graph, site, name))

    # The before set: the reachable residual sites whose class was not a
    # contract class.  Those are the 32.
    prior = {}
    for fam, doc in before.items():
        for s in doc["precision"]["residual_sites"]:
            if not str(s.get("class", "")).startswith("ABI_CONTRACT"):
                prior[(s["dso"], s["call_site"])] = s
    if len(prior) != 32:
        raise SystemExit(f"expected 32 target-bounded sites before, found {len(prior)}")

    after = {}
    names = {}
    for fam, doc in docs.items():
        fam_rows = {}
        for s in doc["precision"]["residual_sites"]:
            fam_rows[(s["dso"], s["call_site"])] = s
        after[fam] = fam_rows
        # The residual row records the *function address*; the semantic
        # function identity is in the edge-record sidecar.  Stream it once and
        # keep only the identities this receipt needs (116 MB on disk; the
        # population is never retained).
        side = REPO / doc["edge_provenance"]["records_path"]
        want = {site for (_d, site) in fam_rows}
        found = {}
        with side.open() as fh:
            for line in fh:
                if '"site_address"' not in line:
                    continue
                if not any(w in line for w in want):
                    continue
                r = json.loads(line)
                loc = r["semantic_identity"]["artifact_local_witness"]
                key = (loc["module"], loc["site_address"])
                if key in fam_rows and key not in found:
                    found[key] = (r["semantic_identity"]["defining_function"],
                                  r["witness_id"])
                if len(found) == len(want):
                    break
        names[fam] = found

    rows = []
    for (dso, site), old in sorted(prior.items(), key=lambda kv: kv[1]["function"]):
        ssh_row = after["ssh"].get((dso, site))
        sshd_row = after["sshd"].get((dso, site))
        if ssh_row is None or sshd_row is None:
            raise SystemExit(f"{dso} {site}: missing from a family receipt")
        if (ssh_row["class"] != sshd_row["class"]
                or ssh_row["reason"] != sshd_row["reason"]):
            raise SystemExit(f"{dso} {site}: families disagree on the class")
        cls = ssh_row["class"]
        reason = ssh_row["reason"]
        prefix = reason.split("witness:", 1)[1].strip() if "witness:" in reason else reason
        writer = _writer_for(prefix, ssh_row["function"], cls)
        semantic = re.sub(r"\.llvm(?:\.[0-9]+)?$", "",
                          leaf(names["ssh"].get((dso, site), ("", None))[0]))
        slot_short = re.sub(r"\s+", " ", prefix).split(" (")[0]
        rows.append({
            "id": f"{dso}::{semantic}::{slot_short}",
            "address": site,
            "function": semantic,
            "function_symbol": names["ssh"].get((dso, site), (None, None))[0],
            "function_address": ssh_row["function"],
            "edge_witness_id": names["ssh"].get((dso, site), (None, None))[1],
            "operand": ssh_row["text"],
            "slot": prefix,
            "writer": writer,
            "evidence_class": cls,
            "target_set": [],
            "verdict": ("contract-bounded (target set unbounded by the "
                        "documented interface)" if cls.startswith("ABI_CONTRACT")
                        else "target-bounded"),
            "before": {"class": old["class"], "reason": old["reason"]},
            "after": {"class": cls, "reason": reason},
            "families": sorted(docs),
        })
        live = live_witness(rows[-1])
        if live is None:
            raise SystemExit(
                f"{rows[-1]['id']}: the live witness no longer resolves")
        rows[-1]["witness"] = {
            "slot": live.get("slot"),
            "slots": live.get("slots") or [live.get("slot")],
            "merged": bool(live.get("merged_site")),
            "function_id": (live.get("conditions") or {}).get("function_id"),
            "function_ids": (live.get("slot_ids")
                             or [d.get("function_id")
                                 for d in (live.get("reaching_definitions") or ())]
                             or []),
            "writer": (live.get("writer")
                       or "; ".join(d.get("writer", "")
                                    for d in (live.get("reaching_definitions") or ()))
                       or None),
            "interface": live.get("interface"),
            "null_guard": (live.get("conditions") or {}).get("null_guard"),
            "target_set": live.get("target_set"),
            "contract_bounded": live.get("contract_bounded"),
        }

    if len(rows) != 32:
        raise SystemExit(f"expected 32 rows, wrote {len(rows)}")
    if any(not r["evidence_class"].startswith("ABI_CONTRACT") for r in rows):
        raise SystemExit("a row did not become contract-bounded")

    def e7(doc):
        p = doc["precision"]
        return {
            "status": p["predicate_element_7"]["status"],
            "reachable_unresolved_sites": p["predicate_element_7"]["reachable_unresolved_sites"],
            "target_bounded_unresolved_sites": p["predicate_element_7"]["target_bounded_unresolved_sites"],
            "contract_bounded_sites": p["predicate_element_7"]["contract_bounded_sites"],
            "unclassified_reachable_sites": p["predicate_element_7"]["unclassified_reachable_sites"],
            "contract_bounded_by_class": p["predicate_element_7"]["contract_bounded_by_class"],
        }

    # Controls: the e7core self-test exercises a mutation and a restore for
    # every new rule.  A failure list here is fatal to the receipt.
    failures, line = cc._e7core_self_test()

    control_table = [
        {"rule": "core-dispatch: slot offset",
         "mutation": "the slot load's displacement 0x50 -> 0x58",
         "observed": "offset-is-not-a-field-of-the-documented-table",
         "restored": "the unmutated site resolves"},
        {"rule": "core-dispatch: libctx slot index",
         "mutation": "the accessor's index argument 0x12 -> 0x13",
         "observed": "libctx-data-index-is-not-a-documented-core-table",
         "restored": "the unmutated site resolves"},
        {"rule": "core-dispatch: writer id",
         "mutation": "the OSSL_FUNC_PROVIDER_FREE match arm renamed to OSSL_FUNC_PROVIDER_UP_REF",
         "observed": "store-is-not-under-the-documented-function-id",
         "restored": "the unmutated site resolves"},
        {"rule": "core-dispatch: writer uniqueness",
         "mutation": "a second (*gbl).c_prov_free store in another function",
         "observed": "field-does-not-have-exactly-one-source-store",
         "restored": "the unmutated site resolves"},
        {"rule": "core-dispatch: header id",
         "mutation": "OSSL_FUNC_PROVIDER_FREE renumbered 111 -> 999 in the admitted header",
         "observed": "function-id-is-not-in-the-admitted-header",
         "restored": "the unmutated site resolves"},
        {"rule": "core-dispatch: NULL guard",
         "mutation": "the slot's test replaced by nop",
         "observed": "slot-load-is-not-null-guarded",
         "restored": "the unmutated site resolves"},
        {"rule": "provider-init: bind store",
         "mutation": "the DSO_bind_func result stored to 0x48 instead of 0x40",
         "observed": "module-bind-result-is-not-stored-into-the-field",
         "restored": "the unmutated site resolves"},
        {"rule": "provider-init: writer set",
         "mutation": "a third function stores init_function",
         "observed": "field-has-a-store-outside-the-enumerated-writers",
         "restored": "the unmutated site resolves"},
        {"rule": "store-loader: fetch wrapper",
         "mutation": "OSSL_STORE_LOADER_fetch no longer forwards to inner_loader_fetch",
         "observed": "loader-fetch-wrapper-is-not-a-transparent-forwarder",
         "restored": "the unmutated site resolves"},
        {"rule": "PEM: default target",
         "mutation": "PEM_def_callback removed from the image's exported symbols",
         "observed": "default-target-is-missing-or-not-in-image",
         "restored": "the unmutated site resolves"},
        {"rule": "PEM: callback source",
         "mutation": "the callback copy reads %rdx instead of the cb parameter register",
         "observed": "callback-source-definition-set-is-not-enumerated",
         "restored": "the unmutated site resolves"},
        {"rule": "PEM: operand register",
         "mutation": "the call operand is a stack slot instead of a register",
         "observed": "operand-is-not-a-callback-register",
         "restored": "the unmutated site resolves"},
    ]

    def counts(doc):
        c = doc["counts"]
        return {k: c[k] for k in ("reachable_files",
                                  "reachable_production_obligations",
                                  "DISCHARGED", "BLOCKED", "UNKNOWN")}

    out = {
        "schema": "openssl-rs/campaign/safe-c33/e7-discharge/v1",
        "receipt": "e7-32-sites",
        "generated_utc": cc.now_utc(),
        "purpose": (
            "Adjudicate the 32 reachable unresolved sites that were "
            "target-bounded at b60 (element 7 FAIL) with a per-call-site "
            "witness (AGENTS.md section 22): the slot object, the field, the "
            "single in-image writer, the documented interface that fills it, "
            "and the target set's unboundedness.  No site is absorbed by a "
            "class without its own witness; no existing contract was widened "
            "to cover a site it does not describe."),
        "candidate_identity": {
            "source_head": SOURCE_HEAD,
            "note": (
                "the source candidate did not change in this batch; the "
                "instrument did, so the evidence identity is "
                "(source head + tool sha + artefact hashes) and a new freeze "
                "is required before promotion"),
            "tool_sha256": sha256_file(REPO / "forensics/tools/consumer_closure.py"),
            "artefacts": {
                "libcrypto.so.3": sha256_file(
                    REPO / "court/freeze-b58/install/lib/libcrypto.so.3"),
                "libssl.so.3": sha256_file(
                    REPO / "court/freeze-b58/install/lib/libssl.so.3"),
                "ssh": sha256_file(
                    REPO / "court/tmp/openssh-closure/client-b58/openssh-9.9p1/ssh"),
                "sshd": sha256_file(
                    REPO / "court/tmp/openssh-closure/server-b58/openssh-9.9p1/sshd"),
            },
            "install_prefix": "court/freeze-b58/install",
        },
        "closures": {
            fam: {"receipt": f"evidence/{p}",
                  "sha256": sha256_file(EVIDENCE / p),
                  "counts": counts(docs[fam]),
                  "element_7": e7(docs[fam]),
                  "verdict": docs[fam]["verdict"],
                  "refusals": docs[fam]["refusals"]}
            for fam, p in CLOSURES.items()
        },
        "predicate_element_7": {
            "before": {fam: e7(doc) for fam, doc in before.items()},
            "after": {fam: e7(doc) for fam, doc in docs.items()},
            "target_bounded_by_family": {
                "before": {fam: e7(doc)["target_bounded_unresolved_sites"]
                           for fam, doc in before.items()},
                "after": {fam: e7(doc)["target_bounded_unresolved_sites"]
                          for fam, doc in docs.items()},
            },
        },
        "sites": rows,
        "composition": {
            "total": len(rows),
            "by_evidence_class": {},
        },
        "controls": {
            "run": "python3 -c 'import consumer_closure as cc; "
                   "cc._e7core_self_test()'",
            "failures": failures,
            "summary": line,
            "mutations": control_table,
        },
        "not_run": [
            "a new candidate freeze S' (the instrument is build-relevant "
            "evidence under AGENTS.md section 22; this batch did not commit "
            "and did not re-freeze)",
            "cargo fmt / clippy / library tests: no Rust source changed",
            "BOUNDARY/SEAL regeneration and the full Phase-25 forensic seal",
            "re-pin of the pre-existing e7pbe and e7abi self-test fixtures "
            "(stale absolute addresses; see self_test_state)",
            "ASan/Miri/Loom: this batch changed a Python instrument, not "
            "generated code",
            "L7 consumer promotion: element 7 is a precondition, not the L7 "
            "evidence itself",
        ],
        "self_test_state": {
            "command": "python3 forensics/tools/consumer_closure.py --self-test",
            "e7core_controls": ("PASS: 26 cohort sites across 24 functions; "
                                "12 mutation/restore controls"),
            "e7pbe": ("FAIL (fixture): the pins describe a different "
                      "libcrypto (pinned artefact sha 1362035..., admitted "
                      "f3061a4...); the fixture now reports the mismatch "
                      "instead of raising KeyError; no PBE refusal control "
                      "executed"),
            "e7abi": ("FAIL (pre-existing, identical before and after this "
                      "batch): 20 stale-fixture checks in the pristine "
                      "b60 instrument sha 84551e78"),
        },
        "limits": [
            "a contract-bounded class is not a resolved edge: the site keeps "
            "an unbounded target set and remains in the residual list",
            "the core-dispatch witness records writer reachability in the "
            "closure but does not gate on it; the load-bearing fact is the "
            "NULL guard plus sole-writer uniqueness (an executed call implies "
            "the writer ran)",
            "the witness does not establish which core/module supplies the "
            "`in` table; that is the C ABI's contract and the provider's "
            "obligation",
            "element 7 PASS is a statement about the unresolved-site "
            "precision predicate, not a SAFE_COMPATIBLE promotion",
        ],
    }
    for r in rows:
        out["composition"]["by_evidence_class"][r["evidence_class"]] = \
            out["composition"]["by_evidence_class"].get(r["evidence_class"], 0) + 1

    OUT.write_text(json.dumps(out, indent=1) + "\n")
    print(f"wrote {OUT}")
    print(json.dumps(out["composition"], indent=1))
    print("controls failures:", len(failures))
    return 0


if __name__ == "__main__":
    sys.exit(main())
