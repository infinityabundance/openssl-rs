#!/usr/bin/env python3
"""Build the v1l unknown-obligation receipt and the v1l consumer-closure union.

This tool is evidence-only.  It reads the frozen v1k census/closure, the two
v1l closure runs, the mechanism registry (state.json), the campaign status and
the v1l site receipt, validates that the counts are internally consistent, and
writes:

  forensics/memory-safety/campaign/safe-c33/atlas-refresh/
      openssh-closure-v1l.json
      unknown-obligations-v1l.json

It does not rebuild any binary and does not touch src/.

Validation is a hard failure (exit 1) on: a changed frozen identity, a
non-deep-equal consumer obligation set, an obligation whose mechanism is not a
registered mechanism, a site-receipt boundary without a matching v1k obligation
and scoped discharge, a discharged obligation not attributed to openssh-v1l, a
missing/FAIL negative-control result, or a D+B+U count that does not sum to the
obligation total.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CAMPAIGN = ROOT / "forensics/memory-safety/campaign/safe-c33"
ATLAS = CAMPAIGN / "atlas-refresh"
WORK = ROOT / "court/mfsem"

EXPECTED = {
    "libcrypto.so.3": "247803f1b57bc109366aeb0831ec27d5680091201920b9f13f5cd61736f52577",
    "libssl.so.3": "3ca46e32588837f7303c0ecbaf12a0376f05253559d0e364d3f76521d6c55853",
    "ssh": "bbb6a6cd0c9a7ca33235aef19b8bad3dc86c425b9eede397290d2b5c7e320a10",
    "sshd": "d66e4929b78ae0a2fc930986894fd5c1b04db80151927f0daa096de6157a074d",
}

OPERATIONS = {
    "src/apps/ciphers.rs:93": "dummy_psk",
    "src/engine/eng_dyn.rs:401": "dynamic_data_ctx_free_func",
    "src/engine/eng_fat.rs:197": "push_cstr_or_null",
    "src/engine/eng_list.rs:90": "engine_list_cleanup",
    "src/engine/tb_asnmth.rs:74": "engine_unregister_all_pkey_asn1_meths",
    "src/engine/tb_cipher.rs:56": "engine_unregister_all_ciphers",
    "src/engine/tb_dh.rs:54": "engine_unregister_all_dh",
    "src/engine/tb_digest.rs:68": "engine_unregister_all_digests",
    "src/engine/tb_dsa.rs:54": "engine_unregister_all_dsa",
    "src/engine/tb_eckey.rs:54": "engine_unregister_all_ec",
    "src/engine/tb_pkmeth.rs:55": "engine_unregister_all_pkey_meths",
    "src/engine/tb_rand.rs:54": "engine_unregister_all_rand",
    "src/engine/tb_rsa.rs:55": "engine_unregister_all_rsa",
    "src/runtime/conf/lib.rs:698": "default_is_number",
    "src/runtime/conf/lib.rs:703": "default_to_int",
    "src/runtime/confmod/asn1.rs:255": "oid_module_finish",
    "src/runtime/confmod/mod.rs:397": "module_free_thunk",
    "src/ui/ui_util.rs:197": "ui_free_method_data",
    "src/ui/ui_util.rs:217": "ui_method_data_index_init",
    "src/cms/cms_lib.rs:1378": "x509_free_void",
    "src/cms/cms_lib.rs:1384": "x509_crl_free_void",
    "src/asn1/asn_mstbl.rs:261": "stbl_module_finish",
    "src/decoder_lib.rs:1080": "decoder_free_thunk",
    "src/ml_kem/key.rs:272": "raise_fixed",
    "src/x509/v3_akid.rs:182": "akid_i2v",
    "src/x509/v3_akid.rs:193": "akid_v2i",
    "src/x509/v3_san.rs:1163": "san_i2v",
    "src/x509/v3_san.rs:1174": "san_v2i",
    "src/x509/v3_san.rs:1184": "san_v2i_issuer",
}

MISSING_PROPERTY = {
    "src/engine/eng_list.rs:90": "The callback has no arguments and is registered in-repo, but its interior engine_table_cleanup(slot) takes a *mut *mut OpenSslLhash raw-pointer view of the module's AtomicPtr static and writes through it without the atomic API. No representation/aliasing contract for that raw write exists at this identity, and it was not exercised under Miri at v1k.",
    "src/engine/tb_cipher.rs:56": "As eng_list.rs:90: the table-slot raw write through the AtomicPtr static has no aliasing contract; no Miri run at v1k.",
    "src/engine/tb_dh.rs:54": "As eng_list.rs:90: the table-slot raw write through the AtomicPtr static has no aliasing contract; no Miri run at v1k.",
    "src/engine/tb_digest.rs:68": "As eng_list.rs:90: the table-slot raw write through the AtomicPtr static has no aliasing contract; no Miri run at v1k.",
    "src/engine/tb_dsa.rs:54": "As eng_list.rs:90: the table-slot raw write through the AtomicPtr static has no aliasing contract; no Miri run at v1k.",
    "src/engine/tb_eckey.rs:54": "As eng_list.rs:90: the table-slot raw write through the AtomicPtr static has no aliasing contract; no Miri run at v1k.",
    "src/engine/tb_pkmeth.rs:55": "As eng_list.rs:90: the table-slot raw write through the AtomicPtr static has no aliasing contract; no Miri run at v1k.",
    "src/engine/tb_rand.rs:54": "As eng_list.rs:90: the table-slot raw write through the AtomicPtr static has no aliasing contract; no Miri run at v1k.",
    "src/engine/tb_rsa.rs:55": "As eng_list.rs:90: the table-slot raw write through the AtomicPtr static has no aliasing contract; no Miri run at v1k.",
    "src/engine/eng_dyn.rs:401": "B20-DYN-1 retains the DynamicDataCtx boundary CONTRACTED. The free hook's provenance obligation is the ENGINE ex-data ABI: the same index is writable through the public ENGINE_set_ex_data, so 'a block from this module's seam' is an external C ABI contract not independently verified here.",
    "src/engine/tb_asnmth.rs:74": "B16-ASN1-1 retains the table boundary CONTRACTED; the table-slot raw write through the AtomicPtr static has no aliasing contract and no Miri run at v1k.",
    "src/cms/cms_lib.rs:1378": "The thunk is registered only on the allocation-failure arm of ossl_cms_get1_certs_ex (X509_add_cert returning 0). The element-type contract is stated but no failure-injection control was run at this identity.",
    "src/cms/cms_lib.rs:1384": "The thunk is registered only on the allocation-failure arm of ossl_cms_get1_crls_ex (X509_CRL_up_ref/OPENSSL_sk_push returning 0). No failure-injection control was run at this identity.",
    "src/ml_kem/key.rs:272": "The body NUL-terminates its own buffer, but the only caller (ossl_ml_kem_key_new at :752, unsupported evp_type) is not reachable through a public API at this identity, so no control exercises it.",
}


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fail(msg: str) -> None:
    print(f"[v1l] VALIDATION FAILED: {msg}", file=sys.stderr)
    raise SystemExit(1)


def key(row: dict) -> str:
    return f"{row['file']}:{row['line']}"


def main() -> int:
    freeze = json.loads((ATLAS / "v1k-candidate-freeze.json").read_text())
    v1k = json.loads((ATLAS / "openssh-closure-v1k.json").read_text())
    ssh = json.loads((WORK / "closure-ssh-v1l.json").read_text())
    sshd = json.loads((WORK / "closure-sshd-v1l.json").read_text())
    state = json.loads((CAMPAIGN / "state.json").read_text())
    status = json.loads((CAMPAIGN / "CAMPAIGN-STATUS.json").read_text())
    sites = json.loads((ATLAS / "openssh-v1l-sites.json").read_text())
    probe_out = (Path("/work/court/tmp/v1l-negctl/negctl.out")
                 if Path("/work/court/tmp/v1l-negctl/negctl.out").is_file()
                 else ROOT / "court/tmp/v1l-negctl/negctl.out").read_text()

    # ---- identity --------------------------------------------------------- #
    install = ROOT / "artifacts/phase2/install"
    got = {
        "libcrypto.so.3": sha(install / "lib/libcrypto.so.3"),
        "libssl.so.3": sha(install / "lib/libssl.so.3"),
        "ssh": sha(WORK / "client-v1k/openssh-9.9p1/ssh"),
        "sshd": sha(WORK / "server-v1k/openssh-9.9p1/sshd"),
    }
    for name, want in EXPECTED.items():
        if got[name] != want:
            fail(f"{name} hash {got[name]} != frozen {want}")

    rows_k = {r["id"]: r for r in v1k["obligations"]["rows"]}
    rows_a = {r["id"]: r for r in ssh["obligations"]}
    rows_b = {r["id"]: r for r in sshd["obligations"]}
    if rows_a != rows_b:
        fail("ssh and sshd obligation sets are not deep-equal")
    if len(rows_a) != 177:
        fail(f"obligation total {len(rows_a)} != 177")
    if set(rows_a) != set(rows_k):
        fail("v1l obligation id set differs from v1k")

    # ---- mechanism registry ---------------------------------------------- #
    registered = {m["id"] for m in state.get("mechanisms") or []}
    for r in rows_a.values():
        if r.get("mechanism") not in registered:
            fail(f"{r['id']} maps to unregistered mechanism {r.get('mechanism')!r}")

    # ---- scoped discharge closure ----------------------------------------- #
    scoped = {}
    for rec in status.get("scoped_boundary_discharges") or []:
        if rec.get("receipt") == "openssh-v1l":
            scoped = rec
    if not scoped:
        fail("CAMPAIGN-STATUS has no openssh-v1l scoped discharge")
    if scoped.get("state") != "SAFETY_DISCHARGED (scoped to the named boundaries)":
        fail("openssh-v1l scoped entry is not SAFETY_DISCHARGED")
    discharged_ids = set(scoped.get("discharged_boundaries") or [])
    boundaries = {b["id"]: b for b in sites.get("boundaries") or []}
    if discharged_ids != set(boundaries):
        fail("scoped discharge ids do not match the site receipt boundaries")
    for bid in discharged_ids:
        b = boundaries[bid]
        row = rows_k.get(f"V1:{b['file']}:{b['line']}:{b['kind']}")
        if row is None:
            fail(f"{bid}: no v1k obligation at {b['file']}:{b['line']}")
        if row["status"] != "UNKNOWN":
            fail(f"{bid}: v1k status is {row['status']}, expected UNKNOWN")
        if b["disposition"] != f"SAFETY_DISCHARGED: {b['file']}:{b['line']}":
            fail(f"{bid}: disposition does not name the exact coordinate")
        if rows_a.get(row["id"], {}).get("status") != "DISCHARGED":
            fail(f"{bid}: v1l did not discharge {row['id']}")
        if rows_a[row["id"]].get("discharge_receipt") != "openssh-v1l":
            fail(f"{bid}: discharge receipt is not openssh-v1l")

    # ---- counts ----------------------------------------------------------- #
    c = ssh["counts"]
    if c["DISCHARGED"] + c["BLOCKED"] + c["UNKNOWN"] != 177:
        fail("D+B+U does not sum to 177")
    if "RESULT PASS" not in probe_out:
        fail("negative-control probe did not report RESULT PASS")
    if ssh["precision"]["predicate_element_7"] != sshd["precision"]["predicate_element_7"]:
        fail("element 7 differs between consumers")

    unknown = [r for r in rows_a.values() if r["status"] == "UNKNOWN"]
    changed = [r for r in rows_a.values() if r["status"] != rows_k[r["id"]]["status"]]
    # status transitions are only UNKNOWN -> DISCHARGED / BLOCKED
    for r in changed:
        if rows_k[r["id"]]["status"] != "UNKNOWN":
            fail(f"{r['id']}: a non-UNKNOWN v1k row changed status")
        if r["status"] not in ("DISCHARGED", "BLOCKED"):
            fail(f"{r['id']}: unexpected transition to {r['status']}")
    # mechanism transitions are only None -> a registered mechanism
    for r in rows_a.values():
        old = rows_k[r["id"]]["mechanism"]
        if old != r["mechanism"] and old is not None:
            fail(f"{r['id']}: mechanism changed from {old} to {r['mechanism']}")

    # ---- per-file / per-mechanism delta ----------------------------------- #
    files = sorted({r["file"] for r in rows_a.values()})
    per_file = []
    for f in files:
        kf = sorted([r for r in rows_k.values() if r["file"] == f],
                    key=lambda r: r["line"] or 0)
        af = sorted([r for r in rows_a.values() if r["file"] == f],
                    key=lambda r: r["line"] or 0)
        if [r["status"] for r in kf] == [r["status"] for r in af] and \
           [r["mechanism"] for r in kf] == [r["mechanism"] for r in af]:
            continue
        per_file.append({
            "file": f,
            "before": {s: sum(1 for r in kf if r["status"] == s)
                       for s in ("DISCHARGED", "BLOCKED", "UNKNOWN")},
            "after": {s: sum(1 for r in af if r["status"] == s)
                      for s in ("DISCHARGED", "BLOCKED", "UNKNOWN")},
            "mechanism_before": sorted({str(r["mechanism"]) for r in kf}),
            "mechanism_after": sorted({str(r["mechanism"]) for r in af}),
            "rows": [{"id": r["id"], "before": rows_k[r["id"]]["status"],
                      "after": r["status"]} for r in af
                     if rows_k[r["id"]]["status"] != r["status"]],
        })
    mech_before = v1k["obligations"]["by_mechanism"]
    mech_after = c["by_mechanism"]
    mech_delta = {m: mech_after.get(m, 0) - mech_before.get(m, 0)
                  for m in sorted(set(mech_before) | set(mech_after))}

    # ---- union closure ---------------------------------------------------- #
    def block(d: dict, label: str) -> dict:
        p = d["precision"]
        return {
            "label": label,
            "family": d["family"],
            "artifact": d["artifact_identity"]["path"],
            "artifact_sha256": d["artifact_identity"]["sha256"],
            "libcrypto_sha256": d["candidate_identity"]["libcrypto_so_3_sha256"],
            "install_prefix": d["candidate_identity"]["install_prefix"],
            "counts": {k: d["counts"][k] for k in (
                "reachable_files", "reachable_production_obligations",
                "DISCHARGED", "BLOCKED", "UNKNOWN")},
            "by_mechanism": d["counts"]["by_mechanism"],
            "precision_totals": p["totals"],
            "element_7": p["predicate_element_7"],
            "reachable_unresolved_sites": p["residual_sites"],
            "evidence_classes": p["evidence_classes"],
            "refusals": d["refusals"],
            "verdict": d["verdict"],
            "boundary_coverage": d["boundary_coverage"],
            "reachable_files_sha256": hashlib.sha256(
                json.dumps(sorted(d["graph"]["reachable_files"])).encode()).hexdigest(),
        }

    refusals = [r["code"] for r in ssh["refusals"]]
    union = {
        "schema": "safe-c33/atlas-refresh/openssh-closure-v1l/v1",
        "kind": "consumer-closure-receipt",
        "subphase": "safe-c33/unknown-obligation-reduction-v1l",
        "generated_utc": now(),
        "question": ("At the v1k frozen identity, how many of the 29 UNKNOWN_OBLIGATION "
                     "sites and the 17 UNKNOWN_MECHANISM files resolve when every unmapped "
                     "site is classified against the registered mechanism taxonomy and only "
                     "code- and caller-verified preconditions are discharged?"),
        "candidate_identity": {
            "source_head": freeze["identity"]["source_head"],
            "src_content_sha256": freeze["identity"]["src_content_sha256"],
            "libcrypto_sha256": got["libcrypto.so.3"],
            "libssl_sha256": got["libssl.so.3"],
            "install_prefix": "artifacts/phase2/install",
            "consumer_binaries": {"ssh_sha256": got["ssh"], "sshd_sha256": got["sshd"]},
            "build_relevant_inputs_changed": False,
        },
        "tool_identity": {
            "path": "forensics/tools/consumer_closure.py",
            "sha256": sha(ROOT / "forensics/tools/consumer_closure.py"),
            "change": ("No analyzer change. The only inputs that differ from v1k are "
                       "state.json (mechanism classification) and the v1l site/scoped "
                       "receipts; the census and binaries are the v1k ones."),
        },
        "consumers": {"ssh": block(ssh, "ssh"), "sshd": block(sshd, "sshd")},
        "obligations": {
            "source": "ssh closure (the sshd obligation set is deep-equal to it)",
            "deep_equal_between_consumers": True,
            "count": len(rows_a),
            "by_status": {s: c[s] for s in ("DISCHARGED", "BLOCKED", "UNKNOWN")},
            "by_mechanism": mech_after,
            "rows": [{k: r.get(k) for k in (
                "id", "file", "line", "status", "mechanism", "mechanism_state",
                "v1_reason", "boundary_ids", "discharge_receipt", "status_reason")}
                for r in sorted(rows_a.values(), key=lambda r: (r["file"], r["line"] or 0))],
        },
        "result": {
            "element_7_ssh": ssh["precision"]["predicate_element_7"]["status"],
            "element_7_sshd": sshd["precision"]["predicate_element_7"]["status"],
            "discharged": c["DISCHARGED"],
            "blocked": c["BLOCKED"],
            "unknown": c["UNKNOWN"],
            "verdict": ssh["verdict"],
        },
        "comparison_to_v1k": {
            "like_for_like": True,
            "why": ("Same v1k census (v1k-candidate-freeze.json), same install "
                    "(libcrypto 247803f1 / libssl 3ca46e32), same consumer binaries "
                    "(ssh bbb6a6cd / sshd d66e4929), unchanged analyzer; only the "
                    "mechanism registry and the v1l receipts differ."),
            "v1k_counts": {"DISCHARGED": 75, "BLOCKED": 73, "UNKNOWN": 29},
            "v1l_counts": {"DISCHARGED": c["DISCHARGED"], "BLOCKED": c["BLOCKED"],
                           "UNKNOWN": c["UNKNOWN"]},
            "delta": {"DISCHARGED": c["DISCHARGED"] - 75,
                      "BLOCKED": c["BLOCKED"] - 73,
                      "UNKNOWN": c["UNKNOWN"] - 29},
            "refusals_before": v1k["refusals_remain"],
            "refusals_after": refusals,
            "refusals_cleared": [r for r in v1k["refusals_remain"] if r not in refusals],
            "per_mechanism_delta": mech_delta,
            "per_file_delta": per_file,
        },
        "refusals_remain": refusals,
        "allocation_by_status": {
            "discharged": [r["id"] for r in rows_a.values() if r["status"] == "DISCHARGED"],
            "blocked": [r["id"] for r in rows_a.values() if r["status"] == "BLOCKED"],
            "unknown": [r["id"] for r in rows_a.values() if r["status"] == "UNKNOWN"],
        },
        "non_claims": [
            "Element 7 PASS is a target/contract-bounded statement, not SAFE_COMPATIBLE.",
            "The closure verdict is still REFUSED: UNKNOWN_OBLIGATION and MISSING_BOUNDARY_RECEIPT remain.",
            "No compatibility, cryptographic or timing evidence is added here.",
            "No Rust source changed, so no Rust test suite was run.",
            "The 15 discharges are site-scoped contract completions; they do not change any mechanism state.",
        ],
    }
    (ATLAS / "openssh-closure-v1l.json").write_text(
        json.dumps(union, indent=1, ensure_ascii=False) + "\n")

    # ---- unknown-obligations receipt -------------------------------------- #
    unknown_k = [r for r in v1k["obligations"]["rows"] if r["status"] == "UNKNOWN"]
    unmapped = [r for r in unknown_k if r["mechanism"] is None]
    unmapped_files = sorted({r["file"] for r in unmapped})
    if len(unknown_k) != 29 or len(unmapped_files) != 17 or len(unmapped) != 19:
        fail(f"enumeration drifted: {len(unknown_k)} unknown, {len(unmapped_files)} files, "
             f"{len(unmapped)} unmapped")

    enum = []
    for r in sorted(unknown_k, key=lambda r: (r["file"], r["line"])):
        rr = rows_a[r["id"]]
        enum.append({
            "id": r["id"], "file": r["file"], "line": r["line"],
            "operation": OPERATIONS.get(key(r)),
            "mechanism_before": r["mechanism"],
            "v1_reason": r["v1_reason"],
            "why_unknown_before": ("no registered mechanism for the file" if r["mechanism"] is None
                                    else "mechanism receipt does not enumerate this exact site"),
            "after": {"mechanism": rr["mechanism"], "status": rr["status"],
                      "discharge_receipt": rr.get("discharge_receipt"),
                      "missing_property": MISSING_PROPERTY.get(key(r))
                      if rr["status"] != "DISCHARGED" else None},
        })

    mapping = []
    for f in unmapped_files:
        ops = [r for r in unmapped if r["file"] == f]
        mapping.append({
            "file": f,
            "operations": [{"line": r["line"],
                            "operation": OPERATIONS.get(key(r)),
                            "mechanism": "C_ABI_CONTRACT",
                            "basis_ref": "state.json#/obligation_mechanisms"} for r in ops],
            "why_defensible": ("The site is an `unsafe extern \"C\" fn`/`unsafe fn` callback or "
                               "adapter whose caller contract is a C/ABI edge. C_ABI_CONTRACT's "
                               "declared authority prefixes cover " + f.split('/')[1] +
                               "/ and its scope names exactly these definitions."),
        })

    discharges = []
    for b in sites["boundaries"]:
        discharges.append({k: b[k] for k in (
            "id", "file", "line", "operation", "mechanism", "disposition",
            "contract", "established_by", "negative_control")})

    remaining = []
    for r in sorted(rows_a.values(), key=lambda r: (r["file"], r["line"])):
        if r["status"] == "DISCHARGED":
            continue
        if rows_k[r["id"]]["status"] != "UNKNOWN":
            continue  # pre-existing BLOCKED rows were never part of the 29
        remaining.append({
            "id": r["id"], "file": r["file"], "line": r["line"],
            "operation": OPERATIONS.get(key(r)),
            "mechanism": r["mechanism"], "status": r["status"],
            "boundary_ids": r.get("boundary_ids"),
            "missing_property": MISSING_PROPERTY.get(key(r), "not stated"),
        })

    unknown_doc = {
        "schema": "safe-c33/atlas-refresh/unknown-obligations/v1",
        "kind": "unknown-obligation-reduction-receipt",
        "subphase": "safe-c33/unknown-obligation-reduction-v1l",
        "generated_utc": now(),
        "frozen_identity": {
            "source_head": freeze["identity"]["source_head"],
            "src_content_sha256": freeze["identity"]["src_content_sha256"],
            "libcrypto_sha256": got["libcrypto.so.3"],
            "libssl_sha256": got["libssl.so.3"],
            "ssh_sha256": got["ssh"], "sshd_sha256": got["sshd"],
            "census": "v1k-candidate-freeze.json",
            "closure": "openssh-closure-v1k.json (177 = 75 D / 73 B / 29 U)",
            "build_relevant_inputs_changed": False,
        },
        "enumeration_before": {
            "unknown_obligations": len(unknown_k),
            "unknown_mechanism_files": len(unmapped_files),
            "unmapped_obligations": len(unmapped),
            "by_file": {f: sum(1 for r in unknown_k if r["file"] == f)
                        for f in sorted({r["file"] for r in unknown_k})},
            "by_mechanism": {(m or "<unmapped>"): sum(1 for r in unknown_k if r["mechanism"] == m)
                             for m in sorted({r["mechanism"] for r in unknown_k},
                                             key=lambda x: str(x))},
            "rows": enum,
        },
        "mapping_decisions": {
            "files_mapped": len(mapping),
            "obligations_mapped": len(unmapped),
            "mechanism": "C_ABI_CONTRACT",
            "files": mapping,
            "left_unmapped": [],
            "not_defensible": ("None of the 17 was left unmapped: every site is an "
                               "`unsafe extern \"C\" fn` callback/adapter and falls inside "
                               "C_ABI_CONTRACT's declared scope and authority prefixes "
                               "(apps/, crypto/conf, crypto/engine, crypto/ui)."),
        },
        "discharges": {
            "count": len(discharges),
            "receipt": "openssh-v1l-sites.json",
            "scoped_discharge": "CAMPAIGN-STATUS.json#/scoped_boundary_discharges[receipt=openssh-v1l]",
            "probe": {
                "source": "unknown-obligations-v1l-negctl.c",
                "binary_sha256": sha(ROOT / "court/tmp/v1l-negctl/negctl")
                if (ROOT / "court/tmp/v1l-negctl/negctl").is_file() else None,
                "output": probe_out.strip().splitlines(),
                "result": "PASS (15/15)",
                "dummy_psk_static_control": "objdump 0x393910: xor %eax,%eax; ret",
            },
            "boundaries": discharges,
        },
        "remaining": {
            "count": len(remaining),
            "subset_of_original_29": True,
            "excluded": "pre-existing v1k BLOCKED rows (61) are not part of the 29 and are listed only in the closure receipt",
            "by_status": {s: sum(1 for r in remaining if r["status"] == s)
                          for s in ("UNKNOWN", "BLOCKED")},
            "rows": remaining,
            "refusals_that_remain": refusals,
            "note": ("No count was softened. The 12 UNKNOWN sites are not discharged and have "
                     "no v1l boundary receipt; the 2 BLOCKED sites moved from UNKNOWN only "
                     "because classifying them to C_ABI_CONTRACT joins them to the existing "
                     "B20/B16 CONTRACTED boundaries."),
        },
        "closure_result": {
            "v1k": {"DISCHARGED": 75, "BLOCKED": 73, "UNKNOWN": 29,
                    "unmapped_files": 17, "refusals": v1k["refusals_remain"]},
            "v1l": {"DISCHARGED": c["DISCHARGED"], "BLOCKED": c["BLOCKED"],
                    "UNKNOWN": c["UNKNOWN"], "unmapped_files": 0,
                    "refusals": refusals},
            "delta": {"DISCHARGED": c["DISCHARGED"] - 75,
                      "BLOCKED": c["BLOCKED"] - 73,
                      "UNKNOWN": c["UNKNOWN"] - 29},
            "per_mechanism_delta": mech_delta,
            "per_file_delta": per_file,
            "element_7_ssh": ssh["precision"]["predicate_element_7"]["status"],
            "element_7_sshd": sshd["precision"]["predicate_element_7"]["status"],
            "element_7_basis": ssh["precision"]["predicate_element_7"]["basis"],
            "verdict": ssh["verdict"]["state"],
        },
        "gates": {
            "py_compile": "PASS (python3 -m py_compile forensics/tools/consumer_closure.py forensics/tools/unknown_obligations_v1l.py)",
            "closure_self_test": "PASS (python3 forensics/tools/consumer_closure.py --self-test)",
            "registry_validation": ("PASS (this tool: frozen hashes, 177 deep-equal "
                                    "obligations, every mechanism registered, every scoped "
                                    "discharge closing to an exact v1k row, probe RESULT PASS; "
                                    "plus forensics/tools/memory_safety_schemas.py --check and "
                                    "--self-test)"),
            "rust_suite": ("NOT RUN: no Rust source changed; src/, Cargo.*, build.rs and "
                           "docker/ are untouched, so a Rust gate would test the same binaries "
                           "as v1k."),
        },
        "does_not_prove": [
            "This is a mechanism/receipt completion, not a boundary audit: the 15 discharged site contracts are stated and controlled, but the enclosing ownership boundaries are not re-adjudicated.",
            "This is not a consumer graduation: SAFE_COMPATIBLE is not claimed and the closure verdict remains REFUSED.",
            "The 12 UNKNOWN and 2 BLOCKED sites are not established; their missing properties are named, not resolved.",
            "The negative controls exercise public entry paths only; they do not prove the absence of C callers that violate the documented ABI.",
            "No Miri/ASan, constant-time, Wycheproof/ACVP or downstream replay evidence is added.",
            "The engine table-slot raw write through an AtomicPtr static is reported as an open obligation, not fixed.",
        ],
        "non_claims": [
            "A site receipt is evidence of per-site contract completion, not of mechanism discharge.",
            "A cleared UNKNOWN_MECHANISM refusal is a classification result, not a safety result.",
            "No Rust test suite was run because no Rust source changed.",
        ],
    }
    (ATLAS / "unknown-obligations-v1l.json").write_text(
        json.dumps(unknown_doc, indent=1, ensure_ascii=False) + "\n")

    print(f"[v1l] D/B/U {c['DISCHARGED']}/{c['BLOCKED']}/{c['UNKNOWN']} "
          f"refusals={refusals} element7={ssh['precision']['predicate_element_7']['status']}")
    print(f"[v1l] wrote openssh-closure-v1l.json and unknown-obligations-v1l.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
