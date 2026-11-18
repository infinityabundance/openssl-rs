#!/usr/bin/env python3
"""Independent source-level contract audit for the THIRD (final) slice of
openssh-v1i obligations: the 18 lexicographically-highest stable_ids, i.e. the
six src/provider/digest.rs `update`/`squeeze`/`get_ctx_params` rows and the twelve
src/provider/legacyprov.rs rows.

No compilation, no crate execution: pure text/structural checks over the frozen
candidate. Review-only data lives under court/freeze-b76/review/.

Checks
  B3-SPAN    re-derive the recorded operation-span hash for all 18 records
  B3-ITEM    the recorded line really holds `fn <item>(`
  B3-COORD   receipt line == inventory line == real definition line; also
             compare the inventory's `actual_definition_line` (the batch-1/2
             stale-coordinate defect recurrence probe)
  B3-SAFETY  does the definition carry a `# Safety` section at the interface?
  B3-DISPATCH every audited item is registered in a dispatch table
  B3-UPDATE-NULL  EVP_DigestUpdate passes (*ctx).algctx to dupdate with no NULL
             test; the F1 state (digest set, algctx NULL after a refused NEWCTX)
             is reachable, and every update body dereferences ctx
  B3-SQUEEZE-NULL EVP_DigestSqueeze passes (*ctx).algctx to dsqueeze with no NULL
             test, and shake_squeeze dereferences ctx through ossl_sha3_squeeze
  B3-FINAL-NULL  EVP_DigestFinal_ex/FinalXOF pass (*ctx).algctx to dfinal with no
             NULL test; the audited legacy finals have no GETTABLE_CTX_PARAMS
             row, so EVP_MD_CTX_get_size_ex does not stop the call
  B3-COPY-NULL   EVP_MD_CTX_copy_ex's two provider copy arms pass (*out).algctx /
             (*in_).algctx to copyctx untested for NULL
  B3-INIT-ESTABLISHED  the only dinit call site tests the NEWCTX result
  B3-NULLPARAM  the get_params/get_ctx_params paths tolerate a NULL array
  B3-COPYCTX-SELF  copyctx uses overlap-safe ptr::copy (self-copy arm)
  B3-JOIN    the obligation->receipt join must identify the discharging row, not
             a bulk boundary-id list shared by unrelated obligations
  B3-WITNESS each row's established_by must be a per-call-site witness with a
             coordinate and the right dispatch file
  B3-CONTRACT the inventory's contract field and the receipt's criteria must
             agree (recorded as `uncontracted` vs contract=PASS)
  B3-COVERS  closure scoped_discharge_attempts must cover the site
  B3-IDENTITY the receipt must name the reviewed candidate S and S's content
"""
import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))

BATCH3_IDS = [
    "OSSH-V1I-022", "OSSH-V1I-021", "OSSH-V1I-014", "OSSH-V1I-019",
    "OSSH-V1I-028", "OSSH-V1I-005", "OSSH-V1I-082", "OSSH-V1I-088",
    "OSSH-V1I-081", "OSSH-V1I-087", "OSSH-V1I-086", "OSSH-V1I-092",
    "OSSH-V1I-084", "OSSH-V1I-090", "OSSH-V1I-083", "OSSH-V1I-089",
    "OSSH-V1I-085", "OSSH-V1I-091",
]
GENERIC_WITNESS = ("caller: src/evp/digest.rs and the provider dispatch in "
                   "src/provider/digest.rs obtain the algctx from NEWCTX/DUPCTX "
                   "and never manufacture one")
CANDIDATE = "0238c6e4adbc7ed85a42be68b6fb965e139bd93e"
SRC_CONTENT = "66c1e9ae6fcc3292b697e06febc0a20289c6d897779bf79f7f6f8015cef3f532"


def load_lines(path):
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "replace").split("\n")


def find_body(lines, start_line, needle_end=None):
    """Text from a definition line through its brace-matched close (text only)."""
    i = start_line - 1
    depth = 0
    seen = False
    out = []
    for ln in lines[i:]:
        out.append(ln)
        depth += ln.count("{") - ln.count("}")
        if "{" in ln:
            seen = True
        if seen and depth <= 0:
            break
        if len(out) > 400:
            break
    return "\n".join(out)


class Audit:
    def __init__(self, root, inv_path, receipt_path, closure_path):
        self.root = root
        self.inv = json.load(open(inv_path))
        self.receipt = json.load(open(receipt_path))
        self.closure = json.load(open(closure_path))
        self.checks = []
        b = {x["id"]: x for x in self.receipt["boundaries"]}
        self.rows = [b[i] for i in BATCH3_IDS]
        self.recs = [o for o in self.inv["obligations"]
                     if o["discharge_boundary_id"] in BATCH3_IDS]
        self.recs.sort(key=lambda o: BATCH3_IDS.index(o["discharge_boundary_id"]))
        self.digest = load_lines(self.p("src/provider/digest.rs"))
        self.legacy = load_lines(self.p("src/provider/legacyprov.rs"))
        self.evp = load_lines(self.p("src/evp/digest.rs"))

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
        self.add("B3-SPAN", "recorded operation-span content hash re-derived",
                 "18/18 match", f"{18 - len(bad)}/18 match", not bad,
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
        self.add("B3-ITEM", "the recorded line holds `fn <item>(`",
                 "18/18 hold the item", f"{18 - len(bad)}/18", not bad, {"bad": bad})

    # ---------------------------------------------------------------- coords
    def check_coords(self):
        stale_receipt, misbound = [], []
        for rec in self.recs:
            lines = load_lines(self.p(rec["file"]))
            real = None
            for i in range(rec["line"] - 1, -1, -1):
                if f"fn {rec['item']}(" in lines[i]:
                    real = i + 1
                    break
            receipt_line = next(r["line"] for r in self.rows
                                if r["id"] == rec["discharge_boundary_id"])
            actual = rec["coordinate_check"]["actual_definition_line"]
            row = {"id": rec["discharge_boundary_id"], "item": rec["item"],
                   "file": rec["file"], "recorded": rec["line"], "real_def": real,
                   "inventory_actual": actual, "receipt": receipt_line}
            if receipt_line != rec["line"] or rec["line"] != real:
                stale_receipt.append(row)
            if actual != real:
                misbound.append(row)
        self.add("B3-COORD",
                 "receipt line == inventory line == real definition line, and the "
                 "inventory's actual_definition_line is that same line",
                 "0 stale, 0 misbound",
                 f"stale={len(stale_receipt)} misbound={len(misbound)}",
                 not stale_receipt and not misbound,
                 {"stale": stale_receipt, "misbound": misbound,
                  "note": "digest rows point at the macro template line 501; the "
                          "six legacyprov second instantiations point at the first "
                          "instantiation (323/336/349/360/378/387)"})

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
        self.add("B3-SAFETY", "each audited unsafe definition carries a `# Safety` fn contract",
                 "18/18 contracted", f"{18 - len(missing)}/18 contracted",
                 not missing, {"missing": missing})

    # -------------------------------------------------------------- dispatch
    def check_dispatch(self):
        bad, rows = [], []
        for rec in self.recs:
            text = "\n".join(load_lines(self.p(rec["file"])))
            reg = (f"function: {rec['item']} as *mut c_void" in text
                   or f"function: super::{rec['item']} as *mut c_void" in text)
            if rec["item"] == "shake_squeeze":
                # registered through the sha3_xof_row! macro's $squeeze parameter
                reg = reg or ("function: super::$squeeze as *mut c_void" in text
                              and re.search(r"sha3_xof_row!\([^;]*?shake_squeeze",
                                            text, re.S) is not None)
            if not reg:
                bad.append(rec["discharge_boundary_id"])
            rows.append({"id": rec["discharge_boundary_id"], "item": rec["item"],
                         "registered": reg})
        self.add("B3-DISPATCH",
                 "each audited item is registered in a dispatch table",
                 "18/18 registered", f"{18 - len(bad)}/18", not bad,
                 {"unregistered": bad})

    # ------------------------------------------------------- F1 reachability
    def f1_chain(self):
        def line_of(needle):
            for i, x in enumerate(self.evp):
                if needle in x:
                    return i + 1
            return None

        digest_set = line_of("(*ctx).digest = type_")
        newctx = None
        if digest_set:
            for i in range(digest_set, min(digest_set + 40, len(self.evp))):
                if "newctx(provctx)" in self.evp[i]:
                    newctx = i + 1
                    break
        fail = None
        if newctx:
            for i in range(newctx, min(newctx + 12, len(self.evp))):
                if "algctx.is_null()" in self.evp[i]:
                    for j in range(i, min(i + 8, len(self.evp))):
                        if re.search(r"\breturn 0;", self.evp[j]):
                            fail = j + 1
                            break
                    break
        algctx_set = line_of("(*ctx).algctx = algctx")
        reachable = bool(digest_set and newctx and fail and algctx_set
                         and digest_set < newctx < fail < algctx_set)
        return {"digest_set": digest_set, "newctx": newctx, "failed_return": fail,
                "algctx_set": algctx_set, "reachable": reachable}

    def unguarded_calls(self, needle):
        sites, guarded = [], []
        for i, ln in enumerate(self.evp):
            if needle in ln:
                sites.append(i + 1)
                guarded.append("algctx.is_null()" in "\n".join(self.evp[max(0, i - 8):i]))
        return sites, guarded

    # ------------------------------------------------------ update NULL ctx
    def check_update_null(self):
        sites, guarded = self.unguarded_calls("dupdate((*ctx).algctx,")
        f1 = self.f1_chain()
        early = "if count == 0" in "\n".join(self.evp[2480:2500])
        # every update body dereferences ctx on the inl > 0 arm
        body_deref = {
            "src/digest/sha1.rs": "fn SHA1_Update" in open(self.p("src/digest/sha1.rs")).read(),
            "src/digest/sha3.rs": "let xof_state = unsafe { (*ctx).xof_state }" in
                                  open(self.p("src/digest/sha3.rs")).read(),
            "src/digest/md5_sha1.rs": "MD5_Update(ptr::addr_of_mut!((*mctx).md5)" in
                                      open(self.p("src/digest/md5_sha1.rs")).read(),
        }
        ok = bool(sites) and all(guarded)
        self.add("B3-UPDATE-NULL",
                 "EVP_DigestUpdate must not pass a NULL algctx to dupdate; the F1 "
                 "state is reachable and every update body dereferences ctx",
                 "every dupdate site guarded, or the state unreachable",
                 f"dupdate_sites={sites} guarded={guarded} f1_reachable={f1['reachable']} "
                 f"zero_len_early_returns={early}",
                 ok or not f1["reachable"],
                 {"dupdate_sites": sites, "guarded": guarded, "f1_chain": f1,
                  "bodies_deref_ctx": body_deref,
                  "authority": "the C authority has the same state; §17 forbids "
                               "reproducing the fault"})

    # ----------------------------------------------------- squeeze NULL ctx
    def check_squeeze_null(self):
        sites, guarded = self.unguarded_calls("dsqueeze((*ctx).algctx,")
        f1 = self.f1_chain()
        text = "\n".join(self.digest)
        no_null_test = 'fn shake_squeeze' in text and "ctx.is_null()" not in find_body(
            self.digest, 1403)
        deref = "(*ctx).xof_state" in open(self.p("src/digest/sha3.rs")).read()
        self.add("B3-SQUEEZE-NULL",
                 "EVP_DigestSqueeze must not pass a NULL algctx to dsqueeze; "
                 "shake_squeeze has no NULL arm and ossl_sha3_squeeze dereferences ctx",
                 "guard at the call site or in the provider",
                 f"dsqueeze_sites={sites} guarded={guarded} f1_reachable={f1['reachable']} "
                 f"provider_tests_null={not no_null_test} downstream_derefs_ctx={deref}",
                 (bool(sites) and all(guarded)) or not f1["reachable"],
                 {"dsqueeze_sites": sites, "guarded": guarded, "f1_chain": f1})

    # ------------------------------------------------------- final NULL ctx
    def check_final_null(self):
        sites = []
        guarded = []
        for i, ln in enumerate(self.evp):
            if re.search(r"dfinal\(\(\*ctx\)\.algctx,", ln):
                sites.append(i + 1)
                guarded.append("algctx.is_null()" in "\n".join(self.evp[max(0, i - 10):i]))
        f1 = self.f1_chain()
        # the audited final rows are the legacyprov ones; their dispatch tables
        # publish no GETTABLE_CTX_PARAMS, so get_size_ex does not stop the call.
        per_row = []
        for r in self.rows:
            if r["operation"].split("::")[-1] != "internal_final":
                continue
            start = r["line"] - 1
            nxt = [i for i in range(start, len(self.legacy)) if "OSSL_DISPATCH_END" in self.legacy[i]]
            window = "\n".join(self.legacy[start:(nxt[0] + 1) if nxt else len(self.legacy)])
            per_row.append({"id": r["id"], "protected":
                            "OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS" in window})
        self.add("B3-FINAL-NULL",
                 "a provider final reached with algctx NULL must not dereference it; "
                 "no provider-arm caller tests algctx",
                 "every dfinal site guarded, or the state unreachable",
                 f"dfinal_sites={sites} guarded={guarded} f1_reachable={f1['reachable']} "
                 f"final_rows={[x['id'] for x in per_row if not x['protected']]}",
                 (bool(sites) and all(guarded)) or not f1["reachable"],
                 {"dfinal_sites": sites, "guarded": guarded, "f1_chain": f1,
                  "final_rows": per_row})

    # -------------------------------------------------------- copy NULL ctx
    def check_copy_null(self):
        sites, guarded = self.unguarded_calls("copyctx((*out).algctx, (*in_).algctx)")
        bodies_use_ptrcopy = all(
            "ptr::copy(" in find_body(self.legacy, start) for start in (336, 544))
        self.add("B3-COPY-NULL",
                 "EVP_MD_CTX_copy_ex must not pass NULL algorithm contexts to "
                 "copyctx; the self-copy and same-digest arms do not test them",
                 "every copyctx call site guarded, or the state unreachable",
                 f"copyctx_sites={sites} guarded={guarded} "
                 f"provider_uses_overlap_safe_copy={bodies_use_ptrcopy}",
                 bool(sites) and all(guarded),
                 {"copyctx_sites": sites, "guarded": guarded})

    # --------------------------------------------------- init establishment
    def check_init_established(self):
        text = "\n".join(self.evp)
        newctx = "let algctx = unsafe { newctx(provctx) }" in text
        null_test = "if algctx.is_null()" in text
        dinit = "dinit((*ctx).algctx, params)" in text
        # the failed-newctx return must precede the assignment and the dinit call
        def at(needle):
            for i, x in enumerate(self.evp):
                if needle in x:
                    return i + 1
            return 10 ** 9
        ordered = at("let algctx = unsafe { newctx(provctx) }") < at("if algctx.is_null()") \
            < at("(*ctx).algctx = algctx") < at("dinit((*ctx).algctx, params)")
        self.add("B3-INIT-ESTABLISHED",
                 "the only dinit call site establishes a non-NULL algctx: NEWCTX's "
                 "result is tested and a failure returns before the call",
                 "newctx result tested, failure returns, then dinit",
                 f"newctx={newctx} null_test={null_test} ordered={ordered} dinit={dinit}",
                 newctx and null_test and ordered and dinit,
                 {"only_dinit_call_site": "src/evp/digest.rs:2349"})

    # ------------------------------------------------------------ NULL param
    def check_null_param(self):
        prov = open(self.p("src/provider/digest.rs")).read()
        repeated_null = "if params.is_null()" in find_body(self.digest, 260)
        locate_null = "if p.is_null() || key.is_null()" in open(self.p("src/params/mod.rs")).read()
        getctx_null = "c.is_null()" in find_body(self.digest, 1481)
        self.add("B3-NULLPARAM",
                 "the get_params/get_ctx_params paths tolerate a NULL array: the "
                 "decoder scan, OSSL_PARAM_locate_const, and shake_get_ctx_params' ctx arm",
                 "all three NULL-tolerant",
                 f"repeated_scan_null={repeated_null} locate_null={locate_null} "
                 f"shake_get_ctx_ctx_null={getctx_null}",
                 repeated_null and locate_null and getctx_null,
                 {"rows": ["OSSH-V1I-022", "OSSH-V1I-086", "OSSH-V1I-092"]})

    # -------------------------------------------------------- copyctx self
    def check_copyctx_self(self):
        uses = []
        for lines, start in ((self.legacy, 336), (self.legacy, 544)):
            body = find_body(lines, start)
            uses.append({"line": start, "ptr_copy": "ptr::copy(" in body,
                         "copy_nonoverlapping": "ptr::copy_nonoverlapping" in body})
        self.add("B3-COPYCTX-SELF",
                 "copyctx must use overlap-safe ptr::copy: the self-copy arm passes "
                 "the same pointer on both sides",
                 "ptr::copy, never copy_nonoverlapping",
                 str(uses), all(u["ptr_copy"] and not u["copy_nonoverlapping"] for u in uses),
                 {"bodies": uses})

    # ---------------------------------------------------------------- join
    def check_join(self):
        sets = {}
        for rec in self.recs:
            sets.setdefault(tuple(rec.get("boundary_ids", [])), []).append(
                rec["discharge_boundary_id"])
        biggest = max(sets.values(), key=len)
        self.add("B3-JOIN",
                 "the obligation->receipt join must identify the discharging row; a "
                 "bulk list shared by unrelated obligations is not a content address",
                 "18 distinct lists", f"{len(sets)} distinct lists; largest has {len(biggest)} rows",
                 len(sets) == len(self.recs),
                 {"largest_shared_group": biggest,
                  "note": "all six digest rows share one 112-id list; all twelve "
                          "legacyprov rows share one 18-id list"})

    # ------------------------------------------------------------- witness
    def check_witness(self):
        bad = []
        has_coord = re.compile(r"\b(src/[\w/]+\.rs|[a-z_0-9]+\.rs):\d+")
        for rec in self.recs:
            est = json.dumps(next(r for r in self.rows
                                  if r["id"] == rec["discharge_boundary_id"]
                                  ).get("established_by", []))
            generic = GENERIC_WITNESS in est
            coord = bool(has_coord.search(est))
            wrong_file = rec["file"].endswith("legacyprov.rs") and "src/provider/digest.rs" in est
            if (generic and not coord) or wrong_file:
                bad.append({"id": rec["discharge_boundary_id"],
                            "generic": generic, "has_coordinate": coord,
                            "names_wrong_dispatch_file": wrong_file})
        self.add("B3-WITNESS",
                 "each row's established_by must name the writing code with a "
                 "coordinate and the correct dispatch file",
                 "0 generic/inapplicable",
                 f"{len(bad)} generic or wrong-file", not bad,
                 {"bad": bad, "generic_text": GENERIC_WITNESS})

    # ------------------------------------------------------------ contract
    def check_contract(self):
        bad = []
        for rec in self.recs:
            row = next(r for r in self.rows if r["id"] == rec["discharge_boundary_id"])
            inv_contract = rec.get("contract")
            crit = (row.get("criteria") or {}).get("contract")
            if inv_contract == "uncontracted" and crit == "PASS":
                bad.append({"id": rec["discharge_boundary_id"],
                            "inventory_contract": inv_contract,
                            "receipt_criteria_contract": crit})
        self.add("B3-CONTRACT",
                 "the inventory's contract field and the receipt's contract criterion "
                 "must agree",
                 "0 contradictions", f"{len(bad)} contradictions", not bad, {"bad": bad})

    # ------------------------------------------------------------- covers
    def check_covers(self):
        obs = {o.get("discharge_boundary_id"): o for o in self.closure["obligations"]}
        bad = []
        for rec in self.recs:
            o = obs.get(rec["discharge_boundary_id"])
            if not o:
                bad.append({"id": rec["discharge_boundary_id"], "reason": "absent"})
                continue
            a = (o.get("scoped_discharge_attempts") or [{}])[0]
            if a.get("covers_site") is not True or a.get("covers_current_coordinate") is not True:
                bad.append({"id": rec["discharge_boundary_id"],
                            "covers_site": a.get("covers_site"),
                            "covers_current_coordinate": a.get("covers_current_coordinate"),
                            "declared_ranges": a.get("declared_ranges"),
                            "current_coordinate": a.get("current_coordinate"),
                            "status": o.get("status"),
                            "content_address_accepts": a.get("content_address_accepts")})
        self.add("B3-COVERS",
                 "a row carried as DISCHARGED must have a scoped discharge attempt "
                 "that covers the site it claims",
                 "18/18 covers_site",
                 f"{18 - len(bad)}/18 covers_site", not bad, {"bad": bad})

    # ----------------------------------------------------------- identity
    def check_identity(self):
        si = self.receipt.get("source_identity", {})
        s_prime = si.get("s_prime_commit")
        s_content = si.get("s_prime_src_content_sha256")
        blobs = si.get("file_blob_sha256", {})
        audited = {"src/provider/digest.rs", "src/provider/legacyprov.rs"}
        audited_ok = all(
            hashlib.sha256(open(self.p(f), "rb").read()).hexdigest() == h
            for f, h in blobs.items() if f in audited)
        other_bad = sorted(f for f, h in blobs.items() if f not in audited
                           and os.path.exists(self.p(f))
                           and hashlib.sha256(open(self.p(f), "rb").read()).hexdigest() != h)
        self.add("B3-IDENTITY",
                 "the receipt must name the reviewed candidate S and S's src content",
                 f"s_prime={CANDIDATE} content={SRC_CONTENT}",
                 f"s_prime={s_prime} content={s_content} "
                 f"audited_file_blobs_match={audited_ok} other_receipt_files_differ={other_bad}",
                 s_prime == CANDIDATE and s_content == SRC_CONTENT,
                 {"s_prime": s_prime, "s_prime_src_content": s_content,
                  "current_src_content": SRC_CONTENT, "candidate": CANDIDATE,
                  "audited_file_blobs_match_current": audited_ok,
                  "other_receipt_files_differing_at_head": other_bad,
                  "note": "the two audited files do match their recorded blobs, "
                          "so this is an identity-binding defect, not a content drift "
                          "in the reviewed rows"})

    def run(self):
        self.check_spans()
        self.check_item()
        self.check_coords()
        self.check_safety()
        self.check_dispatch()
        self.check_update_null()
        self.check_squeeze_null()
        self.check_final_null()
        self.check_copy_null()
        self.check_init_established()
        self.check_null_param()
        self.check_copyctx_self()
        self.check_join()
        self.check_witness()
        self.check_contract()
        self.check_covers()
        self.check_identity()
        return self.checks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--inventory", default=os.path.join(
        ROOT, "court/freeze-b76/review/review-65-inventory.json"))
    ap.add_argument("--receipt", default=os.path.join(
        ROOT, "forensics/memory-safety/campaign/safe-c33/atlas-refresh/openssh-v1i-sites.json"))
    ap.add_argument("--closure", default=os.path.join(
        ROOT, "evidence/closure-ssh-b76c.json"))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    checks = Audit(a.root, a.inventory, a.receipt, a.closure).run()
    if a.json:
        print(json.dumps({"checks": checks}, indent=1))
    else:
        for c in checks:
            print(("PASS " if c["pass"] else "FAIL ") + c["id"] + ": " + c["observed"])
    return 0 if all(c["pass"] for c in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
