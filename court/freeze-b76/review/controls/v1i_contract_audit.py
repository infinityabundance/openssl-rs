#!/usr/bin/env python3
"""Independent source-level contract audit for the 19 lowest-stable_id openssh-v1i
obligations.  No compilation, no crate execution: pure text/structural checks over the
frozen candidate.

Usage:
  python3 v1i_contract_audit.py [--root DIR] [--inventory FILE] [--receipt FILE]

Exit 0 only when every check passes.  On the frozen candidate several checks are
*expected* to fail: those failures ARE the review findings, and the canary harness
(run_canaries_v1i.py) proves each detector is load-bearing by mutating the defect away
in a private copy and observing the check flip to PASS.

Checks
  SPAN19     re-derive the recorded operation-span hash rule for all 19 records
  COORD19    compare each receipt boundary line with the current definition line
  CLOC19     the receipt's "SAFETY_DISCHARGED: <file>:<line>" witness resolves
  SAFETYFN   `# Safety` section on each of the 19 unsafe definitions
  FAMILY     per-call-site witness: is the receipt's established_by caller real?
  MACROCTX   the in-file digest_impl! copyctx has `# Safety`; the five hand-written
             copyctx definitions do not
  NULLCTX    the failed-init -> algctx==NULL -> copyctx(NULL) reachability chain
"""
import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))
DEFAULT_INV = os.path.join(DEFAULT_ROOT, "court/freeze-b76/review/review-65-inventory.json")
DEFAULT_RECEIPT = os.path.join(
    DEFAULT_ROOT,
    "forensics/memory-safety/campaign/safe-c33/atlas-refresh/openssh-v1i-sites.json",
)

V1I_IDS = [
    "src/cmp/cmp_asn.rs::UNSAFE_FN_DEF::itav_free",
    "src/cmp/cmp_asn.rs::UNSAFE_FN_DEF::rootcakeyupdate_free",
    "src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::asn1_integer_dup_void",
    "src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::asn1_integer_free_void",
    "src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::cmp_ctx_set_md",
    "src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::general_name_free_void",
    "src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::itav_free_void",
    "src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::policy_free_void",
    "src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::utf8_string_free_void",
    "src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::x509_extension_free_void",
    "src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::x509_name_dup_void",
    "src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::x509_name_free_void",
    "src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::x509_req_dup_void",
    "src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::x509_req_free_void",
    "src/provider/digest.rs::UNSAFE_FN_DEF::copyctx",
    "src/provider/digest.rs::UNSAFE_FN_DEF::copyctx",
    "src/provider/digest.rs::UNSAFE_FN_DEF::copyctx",
    "src/provider/digest.rs::UNSAFE_FN_DEF::copyctx",
    "src/provider/digest.rs::UNSAFE_FN_DEF::copyctx",
]

# The five hand-written copyctx rows, by module (the inventory's stable_id is ambiguous
# between them; the recorded span disambiguates).
COPYCTX_LINES = [658, 970, 1165, 1348, 1898]
# Thunks only ever passed as an OPENSSL_sk_pop_free freefunc (never to ctx_set1_dup!).
SKPOP_THUNKS = ["general_name_free_void", "x509_extension_free_void",
                "utf8_string_free_void", "policy_free_void"]


def load_lines(path):
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "replace").split("\n")


class Audit:
    def __init__(self, root, inv_path, receipt_path):
        self.root = root
        self.inv = json.load(open(inv_path))
        self.receipt = json.load(open(receipt_path))
        self.checks = []
        ob = [o for o in self.inv["obligations"] if o["discharge_receipt"] == "openssh-v1i"]
        ob.sort(key=lambda o: o["stable_id"])
        self.records = ob[:19]

    def add(self, cid, desc, expected, observed, ok, detail=None):
        self.checks.append({"id": cid, "description": desc, "expected": expected,
                            "observed": observed, "pass": bool(ok), "detail": detail})

    def p(self, rel):
        return os.path.join(self.root, rel)

    # ---- SPAN19 -------------------------------------------------------------
    def check_spans(self):
        bad, msgs = [], []
        for rec in self.records:
            sp = rec["recorded_span"]
            start, end = sp["start_line"], sp["end_line"]
            # rule recorded in the inventory: sha256 of the exact source lines start..end
            lines = load_lines(self.p(rec["file"]))
            seg = "\n".join(lines[start - 1:end])
            if hashlib.sha256(seg.encode()).hexdigest() != sp["sha256"]:
                bad.append(f'{rec["file"]}:{start}-{end}')
            msgs.append(f'{os.path.basename(rec["file"])}:{start}')
        self.add("SPAN19", "recorded operation-span content hash re-derived",
                 "19/19 match", f"{19 - len(bad)}/19 match", not bad, {"mismatch": bad})

    # ---- COORD19 ------------------------------------------------------------
    def check_coords(self):
        by_key = {}
        for b in self.receipt["boundaries"]:
            by_key.setdefault((b["file"], b["operation"]), []).append(b)
        stale = []
        rows = []
        for rec in self.records:
            item = rec["item"]
            f = rec["file"]
            cands = by_key.get((f, item), [])
            if not cands:
                continue
            rl = cands[0]["line"]
            cur = rec["line"]
            rows.append({"item": item, "receipt_line": rl, "current_line": cur})
            if rl != cur:
                stale.append({"item": item, "receipt_line": rl, "current_line": cur,
                              "delta": cur - rl})
        self.add("COORD19", "receipt boundary line equals the current definition line",
                 "0 stale", f"{len(stale)} stale", not stale, {"stale": stale, "rows": rows})

    # ---- CLOC19 ------------------------------------------------------------
    def check_contract_locations(self):
        bad = []
        for b in self.receipt["boundaries"]:
            disp = b.get("disposition", "")
            m = re.search(r"SAFETY_DISCHARGED:\s*(\S+):(\d+)", disp)
            if not m:
                continue
            rel, line = m.group(1), int(m.group(2))
            path = self.p(rel)
            if not os.path.exists(path):
                bad.append({"id": b["id"], "why": "file missing", "at": f"{rel}:{line}"})
                continue
            src = load_lines(path)[line - 1]
            s = src.strip()
            # The disposition cites a `file:line` witness.  It is a defect when that
            # coordinate cannot be either a site or a contract: a blank line, an
            # import, an attribute, or a lone brace.
            cannot_resolve = (s == "" or s.startswith("use ") or s.startswith("pub(crate) use ")
                              or s.startswith("#[") or s in ("{", "}", "};"))
            if cannot_resolve:
                bad.append({"id": b["id"], "at": f"{rel}:{line}", "text": s[:80]})
        self.add("CLOC19", "receipt's cited file:line witness resolves to a site or a contract",
                 "every cited coordinate holds code or prose", f"{len(bad)} bogus",
                 not bad, {"bogus": bad})

    # ---- SAFETYFN ----------------------------------------------------------
    def check_safety_fn(self):
        missing = []
        for rec in self.records:
            lines = load_lines(self.p(rec["file"]))
            i = rec["line"] - 1
            # walk back over attributes / doc comments to the doc block
            j = i - 1
            doc = []
            while j >= 0 and (lines[j].strip().startswith("///")
                              or lines[j].strip().startswith("#[")
                              or lines[j].strip().startswith("/// ")):
                doc.append(lines[j])
                j -= 1
            has = any("# Safety" in d for d in doc) or any("# Safety" in x for x in lines[i:i + 1])
            if not has:
                missing.append(f'{rec["file"]}:{rec["line"]} {rec["item"]}')
        self.add("SAFETYFN", "each unsafe definition carries a `# Safety` fn contract",
                 "19/19 contracted", f"{19 - len(missing)}/19 contracted",
                 not missing, {"missing": missing})

    # ---- FAMILY ------------------------------------------------------------
    def check_family(self):
        false_witness = []
        rows = []
        for b in self.receipt["boundaries"]:
            if b["operation"] not in SKPOP_THUNKS:
                continue
            est = json.dumps(b.get("established_by", []))
            src = "\n".join(load_lines(self.p(b["file"])))
            # does the thunk appear anywhere as an argument to ctx_set1_dup! ?
            used_by_setter = bool(re.search(
                r"ctx_set1_dup!\([^)]*" + re.escape(b["operation"]), src, re.S))
            claims_setter = "ctx_set1_dup!" in est
            rows.append({"id": b["id"], "op": b["operation"],
                         "claims_ctx_set1_dup": claims_setter,
                         "actually_used_by_ctx_set1_dup": used_by_setter})
            if claims_setter and not used_by_setter:
                false_witness.append(b["id"])
        self.add("FAMILY", "receipt's established_by names a caller that really reaches the thunk",
                 "0 false per-call-site witnesses", f"{len(false_witness)} false",
                 not false_witness, {"false": false_witness, "rows": rows})

    # ---- MACROCTX ----------------------------------------------------------
    def check_macro_ctx(self):
        lines = load_lines(self.p("src/provider/digest.rs"))
        # macro-generated copyctx: locate "# Safety" within 6 lines before the fn
        macro_ok = False
        for i, ln in enumerate(lines):
            if "unsafe extern \"C\" fn copyctx(" in ln and i < 560:
                macro_ok = any("# Safety" in x for x in lines[max(0, i - 6):i])
        missing = []
        for ln_no in COPYCTX_LINES:
            i = ln_no - 1
            got = any("# Safety" in x for x in lines[max(0, i - 4):i])
            if not got:
                missing.append(ln_no)
        self.add("MACROCTX", "hand-written copyctx carries the contract the macro copyctx carries",
                 "0 missing (macro has one)", f"macro_has_safety={macro_ok}, missing={missing}",
                 macro_ok and not missing, {"macro_has_safety": macro_ok, "missing": missing})

    # ---- NULLCTX -----------------------------------------------------------
    def check_null_algctx(self):
        d = load_lines(self.p("src/evp/digest.rs"))
        text = "\n".join(d)

        def line_of(needle, start=1):
            for i in range(start - 1, len(d)):
                if needle in d[i]:
                    return i + 1
            return None

        digest_set = line_of("(*ctx).digest = type_")
        newctx_call = None
        for i in range(digest_set or 0, min((digest_set or 0) + 40, len(d))):
            if "newctx(provctx)" in d[i]:
                newctx_call = i + 1
                break
        algctx_set = line_of("(*ctx).algctx = algctx")
        fail_return = None
        if newctx_call:
            # `let algctx = newctx(provctx); if algctx.is_null() { ...; return 0; }`
            for i in range(newctx_call, min(newctx_call + 12, len(d))):
                if "algctx.is_null()" in d[i]:
                    for j in range(i, min(i + 8, len(d))):
                        if re.search(r"\breturn 0;", d[j]):
                            fail_return = j + 1
                            break
                    break
        # copyctx call sites in copy_ex
        call_sites = []
        for i, ln in enumerate(d):
            if re.search(r"copyctx\(\(\*out\)\.algctx, \(\*in_\)\.algctx\)", ln):
                call_sites.append(i + 1)
        guarded = []
        for cs in call_sites:
            window = "\n".join(d[max(0, cs - 6):cs])
            guarded.append("algctx.is_null()" in window)
        # the crate's own tolerance witness in the re-acquiring arm
        reacquire_guard = line_of("if !in_algctx.is_null()", 3120)
        chain = (digest_set is not None and newctx_call is not None and algctx_set is not None
                 and fail_return is not None and digest_set < newctx_call < fail_return < algctx_set)
        # GATE: every copyctx call site must reject/tolerate a NULL algctx.
        self.add("NULLCTX",
                 "EVP_MD_CTX_copy_ex calls the provider copyctx on both algctx pointers without a "
                 "NULL test, although the same function's re-acquiring arm guards exactly that",
                 "every copyctx call site guarded",
                 f"copyctx_sites={call_sites}, guarded={guarded}, "
                 f"reacquire_null_guard={reacquire_guard}",
                 bool(call_sites) and all(guarded),
                 {"copyctx_call_sites": call_sites, "guarded": guarded,
                  "reacquire_guard_line": reacquire_guard})
        # WITNESS: the NULL is reachable from a failed init, so the gate above is load-bearing.
        self.add("NULREACH",
                 "a failed EVP_DigestInit_ex leaves digest!=NULL with algctx==NULL",
                 "chain digest_set < newctx < failed return < algctx_set",
                 f"digest_set={digest_set}, newctx={newctx_call}, fail_return={fail_return}, "
                 f"algctx_set={algctx_set}",
                 chain,
                 {"digest_set_line": digest_set, "newctx_line": newctx_call,
                  "fail_return_line": fail_return, "algctx_set_line": algctx_set})
        # REACQ: the crate already treats a NULL algctx as a state that must be tolerated.
        self.add("REACQ",
                 "the re-acquiring arm tests in_algctx for NULL before dupctx",
                 "in_algctx.is_null() test present in the re-acquiring arm",
                 f"guard_line={reacquire_guard}", reacquire_guard is not None,
                 {"guard_line": reacquire_guard})

    # ---- CALLERS (per-call-site ownership) --------------------------------
    def _fn_span(self, lines, idx):
        """Nearest enclosing fn: expand up to the last column-0 '}' and down to the next."""
        start = 0
        for i in range(idx, -1, -1):
            if lines[i] == "}":
                start = i + 1
                break
        end = len(lines)
        for i in range(idx, len(lines)):
            if lines[i] == "}":
                end = i
                break
        return start, end

    def check_callers(self):
        problems, rows = [], []
        item_frees = {
            "itav_free": ("src/cmp/cmp_asn.rs", "itav", "itav_new()"),
            "rootcakeyupdate_free": ("src/cmp/cmp_asn.rs", "upd", "rootcakeyupdate_new()"),
        }
        for name, (rel, var, alloc) in item_frees.items():
            lines = load_lines(self.p(rel))
            sites = []
            for i, ln in enumerate(lines):
                if f"unsafe {{ {name}({var}) }}" in ln:
                    s, e = self._fn_span(lines, i)
                    body = "\n".join(lines[s:e])
                    sites.append(i + 1)
                    if alloc not in body:
                        problems.append(f"{name}@{i+1}: argument `{var}` has no {alloc} in its fn")
            rows.append({"item": name, "call_sites": sites})
            if not sites:
                problems.append(f"{name}: no call sites found")

        # callback thunks: every use outside the definition must be a function-pointer
        # argument to a known ownership-transferring API, never a direct call.
        thunk_rel = "src/cmp/cmp_ctx.rs"
        lines = load_lines(self.p(thunk_rel))
        for name in ["x509_name_dup_void", "x509_name_free_void", "asn1_integer_dup_void",
                     "asn1_integer_free_void", "x509_req_dup_void", "x509_req_free_void",
                     "general_name_free_void", "x509_extension_free_void",
                     "utf8_string_free_void", "itav_free_void", "policy_free_void"]:
            sites, bad = [], []
            for i, ln in enumerate(lines):
                if name not in ln:
                    continue
                if f'fn {name}(' in ln:
                    continue  # definition
                sites.append(i + 1)
                ok = (("Some(" + name + ")") in ln
                      or ln.strip() == name or ln.strip() == name + ",")
                if not ok:
                    bad.append(i + 1)
            rows.append({"item": name, "call_sites": sites, "unclassified": bad})
            if bad:
                problems.append(f"{name}: direct/unclassified use at {bad}")

        # helper: ctx_set_md call sites pass an out-pointer to an owned field
        lines = load_lines(self.p(thunk_rel))
        sites, bad = [], []
        for i, ln in enumerate(lines):
            if "cmp_ctx_set_md(" in ln and "fn cmp_ctx_set_md" not in ln \
                    and not ln.strip().startswith("//"):
                sites.append(i + 1)
                if "ptr::addr_of_mut!" not in ln:
                    bad.append(i + 1)
        rows.append({"item": "cmp_ctx_set_md", "call_sites": sites, "unclassified": bad})
        if bad:
            problems.append(f"cmp_ctx_set_md: call site without an owned out-pointer {bad}")

        # copyctx: only dispatch-table registration and the two core call sites
        lines = load_lines(self.p("src/provider/digest.rs"))
        regs = [i + 1 for i, ln in enumerate(lines) if "function: copyctx as *mut c_void" in ln]
        rows.append({"item": "copyctx", "dispatch_registrations": len(regs)})
        if not regs:
            problems.append("copyctx: no dispatch registration found")

        self.add("CALLERS",
                 "every use of an item free / thunk / helper is a form whose ownership is "
                 "established (constructor in the same fn, fn-pointer argument, owned out-pointer)",
                 "0 unclassified call sites", f"{len(problems)} problems",
                 not problems, {"problems": problems, "rows": rows})

    def run(self):
        self.check_spans()
        self.check_coords()
        self.check_contract_locations()
        self.check_safety_fn()
        self.check_family()
        self.check_macro_ctx()
        self.check_null_algctx()
        self.check_callers()
        return self.checks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=DEFAULT_ROOT)
    ap.add_argument("--inventory", default=DEFAULT_INV)
    ap.add_argument("--receipt", default=DEFAULT_RECEIPT)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    checks = Audit(a.root, a.inventory, a.receipt).run()
    if a.json:
        print(json.dumps({"checks": checks}, indent=1))
    else:
        for c in checks:
            print(("PASS " if c["pass"] else "FAIL ") + c["id"] + ": " + c["observed"])
            if not c["pass"] and c["detail"]:
                print("     " + json.dumps(c["detail"])[:600])
    return 0 if all(c["pass"] for c in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
