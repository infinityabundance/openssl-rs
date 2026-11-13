#!/usr/bin/env python3
"""Independent source-level contract audit for the SECOND slice of openssh-v1i
obligations: the 19 lexicographically-next stable_ids after the five
`src/provider/digest.rs::UNSAFE_FN_DEF::copyctx` rows reviewed in batch 1.

No compilation, no crate execution: pure text/structural checks over the frozen
candidate.  Review-only data lives under court/freeze-b76/review/.

Checks
  B2-SPAN    re-derive the recorded operation-span hash for all 19 records
  B2-ITEM    the recorded start line really holds `fn <item>(`
  B2-COORD   receipt line == inventory line == current definition line; also
             compare the inventory's `actual_definition_line` (batch-1 found
             stale block-level coordinates; this is the recurrence probe)
  B2-SAFETY  does the definition carry a `# Safety` section at the interface?
  B2-DISPATCH every audited item is registered in a dispatch table (the core can
             actually reach it), and the registration file is the same file
  B2-DUPGUARD every dupctx tests `ctx.is_null()` before copying, and every
             in-crate dupctx call site tests the algctx for NULL (the batch-1
             NULL-algctx defect must not have a dupctx twin)
  B2-NULLPARAM every get_params/get_ctx_params/set_ctx_params callee that takes an
             OSSL_PARAM array tolerates NULL structurally (locate/param_is_empty
             test for it), so the receipt's "NULL or array" contract is code
  B2-KFINAL  keccak_final: is `md_size <= outlen` established anywhere, given that
             the write is `md_size` bytes and EVP_DigestFinalXOF passes a
             caller-chosen `size` and ignores a set_params refusal?
  B2-COPYCTX the batch-1 NULL-algctx copyctx defect is still present (recurrence
             witness: if it were fixed, this check flips)
  B2-WITNESS does each row's established_by name a caller that exists in code with
             a coordinate, or is it the generic sentence reused for a function
             that has no such argument?
"""
import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))

# The 19 stable_ids reviewed in batch 2, in ascending (stable_id, id) order.
BATCH2_IDS = [
    "OSSH-V1I-010", "OSSH-V1I-016", "OSSH-V1I-023", "OSSH-V1I-001",
    "OSSH-V1I-007", "OSSH-V1I-026", "OSSH-V1I-009", "OSSH-V1I-015",
    "OSSH-V1I-030", "OSSH-V1I-006", "OSSH-V1I-018", "OSSH-V1I-013",
    "OSSH-V1I-029", "OSSH-V1I-004", "OSSH-V1I-012", "OSSH-V1I-027",
    "OSSH-V1I-003", "OSSH-V1I-020", "OSSH-V1I-025",
]
# stable_id order (the selection rule), i.e. batch2 == sorted v1i rows [19:38]
SELECTION_NOTE = "sorted by (stable_id, id), rows 20..38 of the 56 v1i obligations"

GENERIC_WITNESS = ("caller: src/evp/digest.rs and the provider dispatch in "
                   "src/provider/digest.rs obtain the algctx from NEWCTX/DUPCTX "
                   "and never manufacture one")


def load_lines(path):
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "replace").split("\n")


class Audit:
    def __init__(self, root, inv_path, receipt_path):
        self.root = root
        self.inv = json.load(open(inv_path))
        self.receipt = json.load(open(receipt_path))
        self.checks = []
        b = {x["id"]: x for x in self.receipt["boundaries"]}
        self.rows = [b[i] for i in BATCH2_IDS]
        self.recs = [o for o in self.inv["obligations"] if o["discharge_boundary_id"] in BATCH2_IDS]
        self.recs.sort(key=lambda o: BATCH2_IDS.index(o["discharge_boundary_id"]))

    def add(self, cid, desc, expected, observed, ok, detail=None):
        self.checks.append({"id": cid, "description": desc, "expected": expected,
                            "observed": observed, "pass": bool(ok), "detail": detail})

    def p(self, rel):
        return os.path.join(self.root, rel)

    # ------------------------------------------------------------------ span
    def check_spans(self):
        bad, rows = [], []
        for rec in self.recs:
            sp = rec["recorded_span"]
            s, e = sp["start_line"], sp["end_line"]
            seg = "\n".join(load_lines(self.p(rec["file"]))[s - 1:e])
            got = hashlib.sha256(seg.encode()).hexdigest()
            rows.append({"id": rec["discharge_boundary_id"], "span": f"{s}-{e}",
                         "match": got == sp["sha256"]})
            if got != sp["sha256"]:
                bad.append(rec["discharge_boundary_id"])
        self.add("B2-SPAN", "recorded operation-span content hash re-derived",
                 "19/19 match", f"{19 - len(bad)}/19 match", not bad,
                 {"mismatch": bad, "rows": rows})

    # ------------------------------------------------------------------ item
    def check_item(self):
        bad = []
        for rec in self.recs:
            lines = load_lines(self.p(rec["file"]))
            ln = lines[rec["line"] - 1]
            if f"fn {rec['item']}(" not in ln:
                bad.append({"id": rec["discharge_boundary_id"], "line": rec["line"],
                            "text": ln.strip()[:70]})
        self.add("B2-ITEM", "the recorded line holds `fn <item>(`",
                 "19/19 hold the item", f"{19 - len(bad)}/19", not bad, {"bad": bad})

    # ---------------------------------------------------------------- coords
    def check_coords(self):
        def_ln, stale_receipt, collided = [], [], []
        for rec in self.recs:
            lines = load_lines(self.p(rec["file"]))
            # real definition: the nearest `fn <item>(` at or before the recorded line
            real = None
            for i in range(rec["line"] - 1, -1, -1):
                if f"fn {rec['item']}(" in lines[i]:
                    real = i + 1
                    break
            cc = rec["coordinate_check"]
            row = {"id": rec["discharge_boundary_id"], "item": rec["item"],
                   "recorded": rec["line"], "real_def": real,
                   "inventory_actual": cc["actual_definition_line"],
                   "receipt": next(r["line"] for r in self.rows
                                   if r["id"] == rec["discharge_boundary_id"])}
            def_ln.append(row)
            if row["receipt"] != rec["line"] or rec["line"] != real:
                stale_receipt.append(row)
            if cc["actual_definition_line"] != real:
                collided.append(row)
        self.add("B2-COORD",
                 "receipt line == inventory line == real definition line, and the "
                 "inventory's actual_definition_line is that same line",
                 "0 stale, 0 name-collision",
                 f"stale={len(stale_receipt)} collision={len(collided)}",
                 not stale_receipt and not collided,
                 {"stale": stale_receipt, "name_collision": collided,
                  "rows": def_ln,
                  "note": "actual_definition_line 433/465/479/515 are the digest_impl! "
                          "macro items; recorded sites are hand-written fns"})

    # ---------------------------------------------------------------- safety
    def check_safety(self):
        missing = []
        for rec in self.recs:
            lines = load_lines(self.p(rec["file"]))
            i = rec["line"] - 1
            j, doc = i - 1, []
            while j >= 0 and (lines[j].strip().startswith("///")
                              or lines[j].strip().startswith("#[")):
                doc.append(lines[j])
                j -= 1
            if not any("# Safety" in d for d in doc):
                missing.append({"id": rec["discharge_boundary_id"], "line": rec["line"]})
        self.add("B2-SAFETY", "each audited unsafe definition carries a `# Safety` fn contract",
                 "19/19 contracted", f"{19 - len(missing)}/19 contracted",
                 not missing, {"missing": missing})

    # -------------------------------------------------------------- dispatch
    def check_dispatch(self):
        bad, rows = [], []
        for rec in self.recs:
            mod = None
            lines = load_lines(self.p(rec["file"]))
            # enclosing `mod NAME {` (column-0) above the site
            for i in range(rec["line"] - 1, -1, -1):
                if lines[i].startswith("mod ") or lines[i].startswith("pub(super) mod ") \
                        or lines[i].startswith("pub(crate) mod "):
                    mod = lines[i].split("mod ")[1].split(" ")[0].strip("{")
                    break
            text = "\n".join(lines)
            reg = f"function: {rec['item']} as *mut c_void" in text
            # hand-written rows register the bare name; macro rows use `super::name`
            reg_super = f"function: super::{rec['item']} as *mut c_void" in text
            rows.append({"id": rec["discharge_boundary_id"], "item": rec["item"],
                         "mod": mod, "registered_bare": reg, "registered_super": reg_super})
            if not (reg or reg_super):
                bad.append(rec["discharge_boundary_id"])
        self.add("B2-DISPATCH",
                 "each audited item is registered in a dispatch table (reachable from the core)",
                 "19/19 registered", f"{19 - len(bad)}/19", not bad,
                 {"unregistered": bad, "rows": rows})

    # -------------------------------------------------------------- dupguard
    def check_dupguard(self):
        lines = load_lines(self.p("src/provider/digest.rs"))
        sites, unguarded = [], []
        for i, ln in enumerate(lines):
            if re.search(r'unsafe extern "C" fn dupctx\(', ln):
                sites.append(i + 1)
                window = "\n".join(lines[i:i + 6])
                if "ctx.is_null()" not in window:
                    unguarded.append(i + 1)
        evp = load_lines(self.p("src/evp/digest.rs"))
        call_sites, guarded = [], []
        for i, ln in enumerate(evp):
            if re.search(r"in_dupctx\(in_algctx\)|dup\(in_algctx\)", ln):
                call_sites.append(i + 1)
                guarded.append("is_null()" in "\n".join(evp[max(0, i - 8):i + 1]))
        self.add("B2-DUPGUARD",
                 "every provider dupctx refuses NULL, and every in-crate dupctx call "
                 "site tests the algorithm context for NULL",
                 "0 unguarded definition, 0 unguarded call site",
                 f"defs={sites} unguarded={unguarded} call_sites={call_sites} guards={guarded}",
                 not unguarded and bool(call_sites) and all(guarded),
                 {"definition_sites": sites, "unguarded_definitions": unguarded,
                  "call_sites": call_sites, "call_site_guarded": guarded})

    # ------------------------------------------------------------ null param
    def check_null_param(self):
        rows, bad = [], []
        params = "\n".join(load_lines(self.p("src/params/mod.rs")))
        loc_null = "if p.is_null() || key.is_null()" in params
        digest = load_lines(self.p("src/provider/digest.rs"))
        text = "\n".join(digest)
        is_empty_null = "if params.is_null()" in text
        for rec in self.recs:
            if rec["item"] not in ("get_params", "get_ctx_params", "set_ctx_params"):
                continue
            ok = loc_null  # every parameter access goes through locate or param_is_empty
            rows.append({"id": rec["discharge_boundary_id"], "item": rec["item"],
                         "locate_accepts_null": loc_null})
            if not ok:
                bad.append(rec["discharge_boundary_id"])
        self.add("B2-NULLPARAM",
                 "the OSSL_PARAM entry points the audited rows call tolerate a NULL array",
                 "locate + is_empty both NULL-safe",
                 f"locate_accepts_null={loc_null} param_is_empty_accepts_null={is_empty_null}",
                 loc_null and is_empty_null and not bad,
                 {"rows": rows, "bad": bad})

    # --------------------------------------------------------------- kfinal
    def check_kfinal(self):
        lines = load_lines(self.p("src/provider/digest.rs"))
        start = next(i for i, x in enumerate(lines)
                     if 'unsafe extern "C" fn keccak_final(' in x)
        body = "\n".join(lines[start:start + 24])
        writes_md_size = "ossl_sha3_final(c, out, (*c).md_size)" in body
        has_bound = ("md_size > outlen" in body or "md_size <= outlen" in body
                     or "outlen < " in body)
        evp = load_lines(self.p("src/evp/digest.rs"))
        xof = next(i for i, x in enumerate(evp)
                   if "pub unsafe extern \"C\" fn EVP_DigestFinalXOF(" in x)
        xof_body = "\n".join(evp[xof:xof + 60])
        xof_calls_dfinal_with_caller_size = bool(
            re.search(r"dfinal\(\(\*ctx\)\.algctx, md, &mut outlen, size\)", xof_body))
        xof_ignores_set_params = ">= 0" in xof_body
        no_xof_test = "EVP_MD_xof" not in xof_body
        established = has_bound or not (writes_md_size and xof_calls_dfinal_with_caller_size)
        self.add("B2-KFINAL",
                 "keccak_final's `out` write (md_size bytes) is bounded by outlen; the "
                 "EVP_DigestFinalXOF arm passes a caller-chosen size and ignores a "
                 "set_params refusal, so md_size<=outlen is not established there",
                 "a bound exists, or no caller passes an unchecked smaller size",
                 f"writes_md_size={writes_md_size} bound={has_bound} "
                 f"xof_passes_caller_size={xof_calls_dfinal_with_caller_size} "
                 f"xof_ignores_set_params={xof_ignores_set_params} xof_tests_xof={not no_xof_test}",
                 established,
                 {"keccak_final_line": start + 1, "xof_line": xof + 1,
                  "authority": "providers/implementations/digests/sha3_prov.c:112-129 "
                               "has the identical shape (conserved, not introduced)"})

    # -------------------------------------------------------------- copyctx
    def check_copyctx_recurrence(self):
        evp = load_lines(self.p("src/evp/digest.rs"))
        sites, guarded = [], []
        for i, ln in enumerate(evp):
            if "copyctx((*out).algctx, (*in_).algctx)" in ln:
                sites.append(i + 1)
                guarded.append("algctx.is_null()" in "\n".join(evp[max(0, i - 8):i]))
        self.add("B2-COPYCTX",
                 "the batch-1 NULL-algctx copyctx defect must not recur; if it is repaired "
                 "this check flips PASS",
                 "no unguarded copyctx call site",
                 f"sites={sites} guarded={guarded}",
                 bool(sites) and all(guarded),
                 {"copyctx_sites": sites, "guarded": guarded,
                  "status": "EXPECTED FAIL on this candidate: batch-1 F1 remains open"})

    # -------------------------------------------------------------- finalnull
    def check_final_null(self):
        """Batch-1's F1 state (digest set, algctx NULL after a refused newctx) has a
        second sink: EVP_DigestFinal_ex calls dfinal with (*ctx).algctx without a
        NULL test, and a provider final that dereferences it faults."""
        evp = load_lines(self.p("src/evp/digest.rs"))
        sites, guarded = [], []
        for i, ln in enumerate(evp):
            if re.search(r"dfinal\(\(\*ctx\)\.algctx,", ln):
                sites.append(i + 1)
                guarded.append("algctx.is_null()" in "\n".join(evp[max(0, i - 10):i]))
        # reachability of the F1 state, re-derived here (not inherited from batch 1)
        def line_of(needle, start=1):
            for i in range(start - 1, len(evp)):
                if needle in evp[i]:
                    return i + 1
            return None
        digest_set = line_of("(*ctx).digest = type_")
        newctx = None
        for i in range(digest_set or 0, min((digest_set or 0) + 40, len(evp))):
            if "newctx(provctx)" in evp[i]:
                newctx = i + 1
                break
        algctx_set = line_of("(*ctx).algctx = algctx")
        fail_ret = None
        if newctx:
            for i in range(newctx, min(newctx + 12, len(evp))):
                if "algctx.is_null()" in evp[i]:
                    for j in range(i, min(i + 8, len(evp))):
                        if re.search(r"\breturn 0;", evp[j]):
                            fail_ret = j + 1
                            break
                    break
        reachable = bool(digest_set and newctx and fail_ret and algctx_set
                         and digest_set < newctx < fail_ret < algctx_set)
        # which audited final rows can actually be reached in that state? A method that
        # publishes GETTABLE_CTX_PARAMS makes EVP_MD_CTX_get_size_ex call get_ctx_params,
        # which (for this file's guards) refuses NULL and stops the final with -1.
        prov = load_lines(self.p("src/provider/digest.rs"))
        blake_has_gettable_ctx = any(
            "OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS" in x for x in prov)
        affected = [r["discharge_boundary_id"] for r in self.recs
                    if r["item"] in ("internal_final", "keccak_final")]
        # per-row resolution: a row is PROTECTED from the F1 sink when its dispatch table
        # publishes GETTABLE_CTX_PARAMS, because EVP_MD_CTX_get_size_ex then calls
        # get_ctx_params, whose NULL refusal answers -1 and stops before dfinal.
        per_row = []
        for r in self.recs:
            if r["item"] not in ("internal_final", "keccak_final"):
                continue
            row_ln = self.recs[[x["discharge_boundary_id"] for x in self.recs]
                               .index(r["discharge_boundary_id"])]["line"]
            start = row_ln - 1
            nxt = [i for i in range(start, len(prov)) if "static FUNCTIONS" in prov[i]]
            window = "\n".join(prov[start:(nxt[0] + 45) if nxt else len(prov)])
            protected = "OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS" in window
            per_row.append({"id": r["discharge_boundary_id"], "item": r["item"],
                            "protected": protected})
        affected = [x["id"] for x in per_row if not x["protected"]]
        self.add("B2-FINALNULL",
                 "EVP_DigestFinal_ex does not test (*ctx).algctx before dfinal, and the F1 "
                 "state (digest set, algctx NULL) is reachable; a final that dereferences ctx "
                 "therefore has an unestablished precondition",
                 "every dfinal call site guarded, or the state unreachable",
                 f"dfinal_sites={sites} guarded={guarded} f1_reachable={reachable} "
                 f"affected_final_rows={affected}",
                 bool(sites) and (not reachable or all(guarded)),
                 {"dfinal_sites": sites, "guarded": guarded,
                  "f1_chain": {"digest_set": digest_set, "newctx": newctx,
                               "failed_return": fail_ret, "algctx_set": algctx_set},
                  "affected_final_rows": affected, "final_rows": per_row,
                  "not_affected_reason": {
                      "blake2 final": "blake publishes GETTABLE_CTX_PARAMS; "
                      "get_ctx_params refuses a NULL ctx with 0, so get_size_ex answers -1 "
                      "and dfinal is never reached in the F1 state"}})

    # -------------------------------------------------------------- witness
    def check_join(self):
        """Batch-1's third defect class (a boundary row accepted by a content
        address rather than by a site-covering join) recurs here as a join that
        is non-discriminating: every obligation carries the same bulk id list."""
        sets = {}
        for rec in self.recs:
            key = tuple(rec.get("boundary_ids", []))
            sets.setdefault(key, []).append(rec["discharge_boundary_id"])
        big = max(len(v) for v in sets.values())
        shared = max(len(k) for k in sets) if sets else 0
        self.add("B2-JOIN",
                 "the obligation->receipt join identifies the discharging row; a bulk list "
                 "shared by unrelated obligations is not a content address",
                 "each obligation's boundary_ids is specific to it",
                 f"distinct_lists={len(sets)} max_shared_rows={big} list_len={shared}",
                 len(sets) == len(self.recs),
                 {"note": "all audited obligations share the same %d-id list; the specific "
                          "row is named only by discharge_boundary_id" % shared})

    def check_witness(self):
        generic, row0 = [], []
        has_coord = re.compile(r"\b(src/[\w/]+\.rs|[a-z_0-9]+\.rs):\d+")
        for rec in self.recs:
            est = json.dumps(self.rows[BATCH2_IDS.index(
                rec["discharge_boundary_id"])].get("established_by", []))
            cites_generic = GENERIC_WITNESS in est
            cites_coord = bool(has_coord.search(est))
            no_ctx_arg = rec["item"] in ("get_params",)
            row0.append({"id": rec["discharge_boundary_id"], "item": rec["item"],
                         "generic": cites_generic, "has_coordinate": cites_coord,
                         "fn_takes_no_ctx": no_ctx_arg})
            if (cites_generic and not cites_coord) or (no_ctx_arg and cites_generic):
                generic.append(rec["discharge_boundary_id"])
        self.add("B2-WITNESS",
                 "each row's established_by is a per-call-site witness (names the writing "
                 "code with a coordinate), or at least is not the algctx sentence applied "
                 "to a function that has no algctx argument",
                 "0 generic/false per-call-site witnesses",
                 f"{len(generic)} generic or inapplicable",
                 not generic, {"generic": generic, "rows": row0,
                               "generic_text": GENERIC_WITNESS})

    def run(self):
        self.check_spans()
        self.check_item()
        self.check_coords()
        self.check_safety()
        self.check_dispatch()
        self.check_dupguard()
        self.check_null_param()
        self.check_kfinal()
        self.check_copyctx_recurrence()
        self.check_final_null()
        self.check_join()
        self.check_witness()
        return self.checks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--inventory", default=os.path.join(
        ROOT, "court/freeze-b76/review/review-65-inventory.json"))
    ap.add_argument("--receipt", default=os.path.join(
        ROOT, "forensics/memory-safety/campaign/safe-c33/atlas-refresh/openssh-v1i-sites.json"))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    checks = Audit(a.root, a.inventory, a.receipt).run()
    if a.json:
        print(json.dumps({"checks": checks}, indent=1))
    else:
        for c in checks:
            print(("PASS " if c["pass"] else "FAIL ") + c["id"] + ": " + c["observed"])
    return 0 if all(c["pass"] for c in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
