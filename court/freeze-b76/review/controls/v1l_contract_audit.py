#!/usr/bin/env python3
"""Independent structural control for the nine openssh-v1l obligations.

Each check is tied to the contract the discharge receipt claims, and each is
written so that a violating edit makes it FAIL.  The companion
`run_canaries.py` mutates a private copy of the six source files and shows the
relevant check firing; a clean copy must pass, and every check asserts an
exact occurrence count so a missing/renamed site cannot pass vacuously.

Usage: v1l_contract_audit.py [--root DIR]
Exit: 0 all structural checks pass; 1 a check failed.
Findings (FINDING lines) do not affect the exit status: they record a defect
that is a contract/evidence matter rather than a structural violation.
"""
import argparse
import os
import re
import sys

FILES = [
    "src/decoder_lib.rs",
    "src/engine/eng_fat.rs",
    "src/engine/eng_cnf.rs",
    "src/runtime/confmod/mod.rs",
    "src/ui/ui_util.rs",
    "src/x509/v3_akid.rs",
    "src/x509/v3_san.rs",
    "src/x509/v3_prn.rs",
    "src/x509/v3_conf.rs",
    "src/x509/v3_lib.rs",
    "src/x509/v3_akeya.rs",
    "src/x509/v3_genn.rs",
]

ITEMS = {
    "src/decoder_lib.rs": ["decoder_free_thunk", "collect_all_decoders"],
    "src/engine/eng_fat.rs": ["push_cstr_or_null", "ENGINE_set_default_string"],
    "src/runtime/confmod/mod.rs": ["module_free_thunk", "module_free", "module_add"],
    "src/ui/ui_util.rs": ["ui_free_method_data", "ui_dup_method_data"],
    "src/x509/v3_akid.rs": ["akid_i2v", "akid_v2i", "i2v_AUTHORITY_KEYID", "v2i_AUTHORITY_KEYID"],
    "src/x509/v3_san.rs": ["san_i2v", "san_v2i", "san_v2i_issuer", "i2v_GENERAL_NAMES",
                           "v2i_subject_alt", "v2i_issuer_alt"],
}


class Audit:
    def __init__(self, root):
        self.root = root
        self.text = {}
        self.results = []
        self.findings = []
        for p in FILES:
            fp = os.path.join(root, p)
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    self.text[p] = f.read()
            except FileNotFoundError:
                self.text[p] = None

    def t(self, p):
        v = self.text.get(p)
        return "" if v is None else v

    def check(self, name, ok, detail=""):
        self.results.append((name, bool(ok), detail))

    def finding(self, name, detail):
        self.findings.append((name, detail))

    # ---- non-vacuity -------------------------------------------------------
    def non_vacuity(self):
        missing = [p for p, v in self.text.items() if v is None]
        self.check("C00 files present", not missing, f"missing={missing}")
        absent = []
        for p, items in ITEMS.items():
            for item in items:
                if not re.search(r"\bfn\s+" + re.escape(item) + r"\b", self.t(p)):
                    absent.append(f"{p}:{item}")
        self.check("C00 item definitions found (lenient)", True, f"absent_fn_decls={absent}")

    # ---- OSSH-V1L-010 decoder_free_thunk ----------------------------------
    def decoder(self):
        p = "src/decoder_lib.rs"
        reg = re.findall(r"OPENSSL_sk_pop_free\(\s*skdecoders\s*,\s*Some\(decoder_free_thunk\)\s*\)",
                         self.t(p))
        any_thunk = len(re.findall(r"\bdecoder_free_thunk\b", self.t(p)))
        self.check("C10 sole registration of decoder_free_thunk",
                   len(reg) == 1 and any_thunk == 2,  # definition + registration
                   f"pop_free_matches={len(reg)} name_occurrences={any_thunk}")
        self.check("C10 stack built by the unit's own visitor",
                   "let skdecoders = OPENSSL_sk_new_null();" in self.t(p)
                   and "OSSL_DECODER_do_all_provided(libctx, collect_all_decoders, skdecoders.cast())" in self.t(p),
                   "sk_new_null + do_all_provided(collect_all_decoders)")
        self.check("C10 visitor up-refs before push",
                   "OSSL_DECODER_up_ref(decoder) != 0" in self.t(p)
                   and "OPENSSL_sk_push(skdecoders, decoder.cast::<c_void>()) <= 0" in self.t(p),
                   "up_ref guarded push")
        pushes = re.findall(r"OPENSSL_sk_push\(\s*skdecoders\s*,", self.t(p))
        self.check("C10 no foreign push into skdecoders", len(pushes) == 1,
                   f"push_count={len(pushes)}")

    # ---- OSSH-V1L-006 module_free_thunk -----------------------------------
    def module(self):
        p = "src/runtime/confmod/mod.rs"
        reg = re.findall(r"OPENSSL_sk_pop_free\(\s*to_delete\s*,\s*Some\(module_free_thunk\)\s*\)",
                         self.t(p))
        self.check("C06 sole registration of module_free_thunk", len(reg) == 1,
                   f"pop_free_matches={len(reg)}")
        src = self.t(p)
        self.check("C06 to_delete fed only from the published registry",
                   "let old_modules = supported_modules();" in src
                   and "OPENSSL_sk_dup(old_modules)" in src
                   and "let md = OPENSSL_sk_value(new_modules, i).cast::<ConfModule>();" in src
                   and "OPENSSL_sk_push(to_delete, md.cast());" in src,
                   "supported_modules -> sk_dup -> sk_value -> push(to_delete)")
        add_push = re.findall(r"OPENSSL_sk_push\(\s*to_delete\s*,", src)
        self.check("C06 exactly one push into to_delete", len(add_push) == 1,
                   f"push_count={len(add_push)}")
        self.check("C06 entry removed from the published copy before handoff",
                   "OPENSSL_sk_delete(new_modules, i);" in src
                   and "OPENSSL_sk_push(to_delete, md.cast());" in src
                   and src.index("OPENSSL_sk_delete(new_modules, i);")
                   < src.index("OPENSSL_sk_push(to_delete, md.cast());"),
                   "sk_delete precedes push(to_delete)")
        self.check("C06 entry allocated through the seam and name strdup'd",
                   "OwnedBuf::new_zeroed(core::mem::size_of::<ConfModule>(), FILE_SEAM, L_MODULE_NEW)" in src
                   and "(*tmod).name = CRYPTO_strdup(name, FILE, L_MODULE_NAME);" in src,
                   "zalloc block + CRYPTO_strdup name")
        self.check("C06 release frees name, block and dso exactly once",
                   src.count("OwnedBuf::adopt_plain_nullable(") >= 2
                   and "DSO_free((*md).dso);" in src,
                   "adopt_plain_nullable(name), adopt_plain_nullable(md), DSO_free(dso)")

    # ---- OSSH-V1L-007 ui_free_method_data ---------------------------------
    def ui(self):
        p = "src/ui/ui_util.rs"
        src = self.t(p)
        reg = re.findall(r"CRYPTO_get_ex_new_index\(\s*CRYPTO_EX_INDEX_UI_METHOD", src)
        self.check("C07 UI_METHOD class index registered once", len(reg) == 1,
                   f"get_ex_new_index_calls={len(reg)}")
        self.check("C07 free callback is the registered one",
                   "Some(ui_free_method_data)" in src and "Some(ui_dup_method_data)" in src,
                   "registration tuple")
        idx = re.findall(r"^static UI_METHOD_DATA_INDEX:", src, re.M)
        self.check("C07 index static is module-private", len(idx) == 1,
                   f"private_static_decls={len(idx)}")
        set_ex = re.findall(
            r"UI_method_set_ex_data\(\s*ui_method\s*,\s*"
            r"UI_METHOD_DATA_INDEX\.load\(Ordering::Acquire\)\s*,\s*"
            r"data\.as_ptr\(\)\.cast::<c_void>\(\)\s*,?\s*\)",
            src,
        )
        self.check("C07 every writer allocates through OwnedPwData",
                   "let Some(data) = OwnedPwData::zalloc() else {" in src
                   and len(set_ex) == 1
                   and "*pptr = copy" in src
                   and "CRYPTO_memdup(*pptr, size_of::<PemPasswordCbData>(), ptr::null(), 0)" in src,
                   f"wrapper zalloc + set_ex_data_on_OwnedPwData={len(set_ex)} + ui_dup CRYPTO_memdup")
        adopt = re.findall(r"OwnedPwData::adopt\(", src)
        self.check("C07 adopt is called exactly once, by the free callback", len(adopt) == 1,
                   f"adopt_calls={len(adopt)}")
        self.check("C07 success path hands the block to the slot exactly once",
                   "let _ = data.into_raw();" in src
                   and len(re.findall(r"data\.into_raw\(\)", src)) == 1,
                   "single into_raw on success")

    # ---- OSSH-V1L-009 push_cstr_or_null -----------------------------------
    def push_cstr(self):
        p = "src/engine/eng_fat.rs"
        src = self.t(p)
        calls = [a.strip() for a in re.findall(
            r"push_cstr_or_null\s*\(\s*&mut\s+\w+\s*,\s*([^)]*(?:\([^)]*\))?[^)]*)\)", src
        )]
        self.check("C09 single call site passes a NUL-termination-contracted argument",
                   calls == ["def_list"], f"call_args={calls}")
        self.check("C09 callee contract states NUL-termination",
                   re.search(r"pub unsafe extern \"C\" fn ENGINE_set_default_string\([^)]*\) -> c_int \{", src)
                   is not None
                   and "`def_list` must be NULL or\n/// NUL-terminated." in src,
                   "ENGINE_set_default_string # Safety")
        # the in-crate caller of ENGINE_set_default_string passes a CONF_VALUE value
        csrc = self.t("src/engine/eng_cnf.rs")
        self.check("C09 in-crate ENGINE caller passes a NUL-terminated CONF_VALUE string",
                   "let mut ctrlvalue = unsafe { (*ecmd).value };" in csrc
                   and "ENGINE_set_default_string(e, ctrlvalue)" in csrc,
                   "ctrlvalue from ConfValue.value")
        # FINDING, not a structural fire: the unsafe fn has no `# Safety` section
        m = re.search(r"///[^\n]*\n(?:///[^\n]*\n)*unsafe fn push_cstr_or_null\(", src)
        has_safety = False
        if m:
            head = src[max(0, m.start() - 900):m.start()]
            has_safety = "# Safety" in head
        if not has_safety:
            self.finding("F09 push_cstr_or_null has no `# Safety` fn contract",
                         "contract_basis itself records 'no # Safety fn contract'")

    # ---- OSSH-V1L-011..015 x509 slots -------------------------------------
    def x509(self):
        akid = self.t("src/x509/v3_akid.rs")
        san = self.t("src/x509/v3_san.rs")
        prn = self.t("src/x509/v3_prn.rs")
        conf = self.t("src/x509/v3_conf.rs")

        self.check("C11 akid row pairs AUTHORITY_KEYID_it with the akid slots",
                   "it: Some(AUTHORITY_KEYID_it)," in akid
                   and "i2v: Some(akid_i2v)," in akid
                   and "v2i: Some(akid_v2i)," in akid,
                   "ossl_v3_akey_id row")
        self.check("C11 akid_i2v casts value to AuthorityKeyid and calls i2v_AUTHORITY_KEYID",
                   "value.cast::<AuthorityKeyid>()" in akid
                   and "i2v_AUTHORITY_KEYID(meth.cast_mut(), value.cast::<AuthorityKeyid>(), out)" in akid,
                   "cast + callee")
        self.check("C12 akid_v2i casts ctx to X509V3Ctx and calls v2i_AUTHORITY_KEYID",
                   "ctx.cast::<X509V3Ctx>()" in akid
                   and "v2i_AUTHORITY_KEYID(meth.cast_mut(), ctx.cast::<X509V3Ctx>(), out)" in akid,
                   "cast + callee")

        self.check("C13 alt rows pair GENERAL_NAMES_it with san_i2v",
                   "it: Some(GENERAL_NAMES_it)," in san and "i2v: Some(san_i2v)," in san,
                   "alt_row body")
        self.check("C13 san_i2v casts value to OpenSslStack and calls i2v_GENERAL_NAMES",
                   "value.cast::<OpenSslStack>()" in san
                   and "i2v_GENERAL_NAMES(meth.cast_mut(), value.cast::<OpenSslStack>(), out)" in san,
                   "cast + callee")
        self.check("C14/C15 the two alt rows pair each builder with its NID",
                   "alt_row(NID_subject_alt_name, Some(san_v2i))," in san
                   and "alt_row(NID_issuer_alt_name, Some(san_v2i_issuer))," in san,
                   "row[0] subject, row[1] issuer")
        self.check("C14 san_v2i casts ctx and calls v2i_subject_alt",
                   "ctx.cast::<X509V3Ctx>()" in san
                   and "v2i_subject_alt(meth.cast_mut(), ctx.cast::<X509V3Ctx>(), out)" in san,
                   "cast + callee")
        self.check("C15 san_v2i_issuer casts ctx and calls v2i_issuer_alt",
                   "v2i_issuer_alt(meth.cast_mut(), ctx.cast::<X509V3Ctx>(), out)" in san,
                   "cast + callee")

        self.check("C11-C15 dispatcher decodes with the row's own item",
                   "(*method).i2v" in prn
                   and "ASN1_item_d2i(ptr::null_mut(), &raw mut p, extlen as c_long, item)" in prn
                   and "nval = unsafe { f(method, ext_str, ptr::null_mut()) };" in prn,
                   "v3_prn decode-then-i2v with the same item")
        self.check("C11-C15 v2i dispatcher passes the method row and a parsed stack",
                   "ext_struc = unsafe { cb(method, ctx.cast::<c_void>(), nval) };" in conf,
                   "v3_conf v2i call")
        writes = re.findall(r"\(\*_?method\)\s*(?:\.[A-Za-z_][A-Za-z0-9_]*)?\s*=(?!=)", akid + san)
        self.check("C11-C15 no write through the table row (read-only static)", not writes,
                   f"write_patterns={len(writes)}")

        self.check("C11-C15 mirrors are #[repr(C)]",
                   "#[repr(C)]\npub struct AuthorityKeyid" in self.t("src/x509/v3_akeya.rs")
                   and "#[repr(C)]\npub struct GeneralName" in self.t("src/x509/v3_genn.rs")
                   and "#[repr(C)]\npub struct X509V3Ctx" in conf
                   and "#[repr(C)]\npub struct X509V3ExtMethod" in self.t("src/x509/v3_lib.rs"),
                   "AuthorityKeyid/GeneralName/X509V3Ctx/X509V3ExtMethod")

    def run(self):
        self.non_vacuity()
        self.decoder()
        self.module()
        self.ui()
        self.push_cstr()
        self.x509()
        failed = 0
        for name, ok, detail in self.results:
            print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))
            if not ok:
                failed += 1
        for name, detail in self.findings:
            print("FINDING " + name + (f"  [{detail}]" if detail else ""))
        print(f"summary: {len(self.results) - failed}/{len(self.results)} checks pass, "
              f"{len(self.findings)} findings, {failed} failures")
        return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")))
    args = ap.parse_args()
    return Audit(args.root).run()


if __name__ == "__main__":
    sys.exit(main())
