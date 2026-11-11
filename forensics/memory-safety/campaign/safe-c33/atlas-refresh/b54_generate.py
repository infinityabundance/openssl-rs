import hashlib, json, os, re, sys

ROOT = os.getcwd()
sys.path.insert(0, "forensics/memory-safety/campaign/safe-c33/atlas-refresh")
from b54_evidence import E

CLOSURE = "evidence/closure-ssh-311.json"
OUT = "forensics/memory-safety/campaign/safe-c33/atlas-refresh/boundary-sweep-B54.json"

closure = json.load(open(CLOSURE))
sel = [
    o for o in closure["obligations"]
    if o.get("status") == "BLOCKED" and o.get("mechanism") == "X509_VERIFY_POLICY"
]
assert len(sel) == 83, len(sel)

cache = {}


def lines(f):
    if f not in cache:
        cache[f] = open(f).read().split("\n")
    return cache[f]


def def_line(f, op):
    for i, l in enumerate(lines(f)):
        if re.search(r"\bfn\s+" + re.escape(op) + r"\s*\(", l):
            return i + 1
    raise SystemExit("no definition for %s in %s" % (op, f))


def slot_lines(f, op):
    out = []
    for i, l in enumerate(lines(f)):
        if re.search(r"\b" + re.escape(op) + r"\s*[,)]", l) and re.search(
            r"(i2s|s2i|i2v|v2i|i2r|r2i|ext_free|d2i|i2d)\s*:", l
        ):
            out.append(i + 1)
    return out


def sha256_file(f):
    h = hashlib.sha256()
    with open(f, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


rows = []
missing_rows = []
counts = {}
verdicts = {}

def family(op):
    if op.startswith("i2r") or op.endswith("_i2r"):
        return "i2r"
    if op.startswith("i2s"):
        return "i2s"
    if op.startswith("i2v"):
        return "i2v"
    if op.startswith("v2i"):
        return "v2i"
    if op.startswith("s2i"):
        return "s2i"
    if op.startswith("r2i"):
        return "r2i"
    if op.startswith("audit"):
        return "audit"
    if op in ("SCT_LIST_free", "ocsp_nonce_free", "ext_list_free"):
        return "free"
    return "helper"

for o in sel:
    key = (o["file"], o["item"])
    if key not in E:
        missing_rows.append(key)
        continue
    e = E[key]
    v = e["verdict"]
    verdicts[v] = verdicts.get(v, 0) + 1
    counts[e["path"]] = counts.get(e["path"], 0) + 1
    row = {
        "id": o["id"],
        "file": o["file"],
        "line": o["line"],
        "line_provenance": "V1 census coordinate from the closure; line_current is recomputed from the adjudicated tree",
        "line_current": def_line(o["file"], o["item"]),
        "slot_lines_current": slot_lines(o["file"], o["item"]),
        "kind": o["kind"],
        "operation": o["item"],
        "mechanism": "X509_VERIFY_POLICY",
        "family": family(o["item"]),
        "dispatch_path": e["path"],
        "registration": e["registration"],
        "caller": e["caller"],
        "type_fact": e["type_fact"],
        "verdict": v,
    }
    if e["missing"]:
        row["missing_fact"] = e["missing"]
    rows.append(row)

assert not missing_rows, missing_rows
rows.sort(key=lambda r: (r["dispatch_path"], r["file"], r["line_current"]))

audited_files = sorted({o["file"] for o in sel})
delta_files = [
    "src/ct/ct_x509v3.rs", "src/ocsp/v3_ocsp.rs", "src/x509/v3_asid.rs",
    "src/x509/v3_audit_id.rs", "src/x509/v3_battcons.rs", "src/x509/v3_bcons.rs",
    "src/x509/v3_bitst.rs", "src/x509/v3_conf.rs", "src/x509/v3_extku.rs",
    "src/x509/v3_info.rs", "src/x509/v3_lib.rs", "src/x509/v3_pcons.rs",
    "src/x509/v3_pmaps.rs", "src/x509/v3_prn.rs", "src/x509/v3_san.rs",
    "src/x509/v3_timespec.rs", "src/x509/v3_tlsf.rs",
]
all_files = sorted(set(audited_files) | set(delta_files))
files_sha256 = {f: sha256_file(f) for f in all_files}

blocked = [r for r in rows if r["verdict"] == "BLOCKED"]
paths = {
    "PRINT_i2s": sum(1 for r in rows if r["dispatch_path"].startswith("PRINT_i2s")),
    "PRINT_i2r": sum(1 for r in rows if r["dispatch_path"].startswith("PRINT_i2r")),
    "PRINT_i2v": sum(1 for r in rows if r["dispatch_path"].startswith("PRINT_i2v")),
    "CONFIG_v2i": sum(1 for r in rows if "CONFIG_DECODE_v2i" in r["dispatch_path"]),
    "CONFIG_s2i": sum(1 for r in rows if "CONFIG_DECODE_s2i" in r["dispatch_path"]),
    "CONFIG_r2i": sum(1 for r in rows if "CONFIG_DECODE_r2i" in r["dispatch_path"]),
    "FREE_HOOK": sum(1 for r in rows if r["dispatch_path"].startswith("FREE_HOOK")),
    "INTERNAL_HELPER": sum(1 for r in rows if r["dispatch_path"].startswith("INTERNAL_HELPER")),
}
assert sum(paths.values()) == 83, paths

receipt = {
    "receipt": "boundary-sweep-B54",
    "date": "2026-11-11",
    "campaign": "safe-c33 shared-contract establishment: the X509V3_EXT_METHOD callback surface (83 BLOCKED X509_VERIFY_POLICY obligations)",
    "subphase": (
        "B54 adjudicates all 83 BLOCKED X509_VERIFY_POLICY obligations in "
        "evidence/closure-ssh-311.json (33 i2r / 7 i2s / 12 v2i / 6 s2i / 3 free / 22 other). "
        "The proof is per dispatch path and does not blend them: the print path is "
        "X509V3_EXT_print (v3_prn.rs:283-366), the config-decode path is do_ext_nconf "
        "(v3_conf.rs:1041-1126), the encode path is do_ext_i2d via the same row's `it`, and the "
        "free/helper rows are reached from those two. The decisive structural fact is that each "
        "dispatcher resolves ONE row and then both decodes/encodes with that row's declared item "
        "and calls that same row's slot, so the object a callback receives or produces is fixed by "
        "the method-table entry rather than by the input bytes. 72 rows are discharged on that "
        "fact; 11 are rejected, all on one shared and precisely located defect: `ctx` is documented "
        "as nullable at the public config entries and at several callbacks, and the config paths "
        "dereference it. Nothing is applied and CAMPAIGN-STATUS.json / state.json are untouched."
    ),
    "candidate": {
        "head": "7e8e11879",
        "head_subject": "ledger: discharge 30 slh_dsa method-table sites -> BLOCKED 135 -> 105",
        "branch": "stage/p25/b53-discharge",
        "source_state": (
            "The adjudicated source is HEAD 7e8e11879 plus one uncommitted working-tree delta made "
            "by this batch, described below. No production statement, expression, signature, "
            "attribute or ABI item was changed: the delta is `///` documentation (17 fn-level "
            "`# Safety` blocks) plus `#[cfg(test)]`-only test code and one test-only lock moved to "
            "v3_lib. Per the task instruction nothing was committed or pushed."
        ),
        "working_delta": {
            "kind": "documentation + test-only (uncommitted)",
            "diff_stat": "17 files changed, 830 insertions(+), 12 deletions(-)",
            "deletions": [
                "two doc-comment lines rewrapped in src/x509/v3_pcons.rs and src/x509/v3_pmaps.rs",
                "the private REGISTRY_TEST_LOCK static in src/x509/v3_prn.rs and the four-line lock acquisition it was used with, replaced by the crate's existing crate::test_support::lock_global_state(); test-only, no assertion weakened",
            ],
            "documentation": "17 fn-level `# Safety` contracts added to the rows that lacked one (see contracts_added)",
            "test_only": [
                "src/x509/v3_prn.rs: B54-C1, B54-C2, B54-W",
                "src/x509/v3_conf.rs: B54-C3, and the shared registry test lock in the B53 control",
                "src/x509/v3_ocsp.rs: B54-W1 (new #[cfg(test)] mod b54_tests)",
                "src/x509/v3_san.rs: B54-W3 (new #[cfg(test)] mod tests)",
                "src/x509/v3_prn.rs + src/x509/v3_conf.rs: the registry-touching units now take crate::test_support::lock_global_state(), the lock the B51/B53 controls already take, instead of a second private lock",
            ],
            "note": "A reviewer must commit this delta as S' before applying any disposition; every line_current and files_sha256 below binds the working tree named here, not HEAD.",
        },
        "files": all_files,
        "files_sha256": files_sha256,
        "note": "line is advisory under content addressing. `line_current` and `slot_lines_current` are recomputed from the adjudicated tree and are exact; numeric coordinates inside `registration`/`caller` prose were captured before this batch's doc-only delta in the same files and are advisory. files_sha256 is the acceptance binding for this draft.",
    },
    "authority": {
        "id": "openssl-3.6.4-production",
        "source": "forensics/authorities/src/openssl-3.6.4",
        "header": "include/openssl/x509v3.h.in:48-61 (the slot typedefs) and :65-85 (the method struct)",
        "dispatch": (
            "crypto/x509/v3_prn.c:69-136 (X509V3_EXT_print: decode once via ASN1_ITEM_ptr(method->it) "
            "at :86-89, then i2s/i2v/i2r at :95-127, then the same item's free at :131-135) and "
            "crypto/x509/v3_conf.c:79-135 (do_ext_nconf: v2i/s2i/r2i at :96-126, encode via "
            "do_ext_i2d, free via ASN1_item_free/ext_free at :127-134)"
        ),
        "note": (
            "The authority resolves the row once per call and uses that row for both halves, which "
            "is what makes the callback's cast sound. Its `do_ext_nconf` dereferences ctx for r2i "
            "(`ctx->db`, :117-121) and its v2i callbacks reach X509V3_get_section for section-valued "
            "entries; NULL ctx therefore faults in the authority too. The candidate reproduces that "
            "behaviour (see the B54-F1 finding) instead of eliminating it."
        ),
    },
    "mechanism": {
        "id": "X509_VERIFY_POLICY",
        "state": "OWNERSHIP_RECONSTRUCTED",
        "state_source": "state.json#/mechanisms[id=X509_VERIFY_POLICY]",
        "discharge": "SITE-SCOPED: only the 72 rows below this receipt marks DISPATCH_DISCHARGED. The mechanism state is unchanged and is not discharged mechanism-wide; the 11 rejected rows stay BLOCKED.",
    },
    "scope": {
        "aggregation": ".obligations[] | select(.status == \"BLOCKED\" and .mechanism == \"X509_VERIFY_POLICY\") over evidence/closure-ssh-311.json (175 DISCHARGED / 149 BLOCKED / 0 UNKNOWN)",
        "raw_blocked_count": 83,
        "chosen_family": {
            "family": "the entire remaining X509_VERIFY_POLICY BLOCKED set (all six slot families plus helpers)",
            "count": 83,
            "why": "This is the largest remaining cluster (83 of 105 BLOCKED) and the main path to SAFE_COMPATIBLE. The rows are adjudicated by dispatch path, not as one claim; the print-path rows are 52 of the 83 and share one dispatcher, while the 30 config/free/helper rows have their own callers.",
        },
        "per_path": paths,
        "not_touched": [
            {"family": "B51's ten v2i rows (v2i_ASIdentifiers, v2i_OSSL_BASIC_ATTR_CONSTRAINTS, v2i_BASIC_CONSTRAINTS, v2i_EXTENDED_KEY_USAGE, v2i_AUTHORITY_INFO_ACCESS, v2i_issuer_sign_tool, v2i_POLICY_CONSTRAINTS, v2i_POLICY_MAPPINGS, sxnet_v2i, v2i_TLS_FEATURE)",
             "count": 10,
             "reason": "Discharged by boundary-sweep-B51; not re-claimed. B54 does record a cross-receipt finding (B54-X1) that B51's v2i_AUTHORITY_INFO_ACCESS discharge rests on v2i_GENERAL_NAME_ex's false `ctx NULL or live` contract, so it should be reopened."},
            {"family": "all other mechanisms in evidence/closure-ssh-311.json", "count": None, "reason": "outside this sweep"},
        ],
        "baseline_receipt": "evidence/closure-ssh-311.json",
    },
    "shared_contract": {
        "print_path": (
            "X509V3_EXT_print (src/x509/v3_prn.rs:254) refuses a NULL `out`/`ext` (:263), takes the "
            "registry read hold (:271), resolves ONE row from the extension's object NID "
            "(`X509V3_EXT_get` -> `ext_get_nid_locked`, :283), resolves that row's item once "
            "(`ext_method_item`, :296; a NULL accessor result is a failed decode, not a callback), "
            "decodes with exactly that item (`ASN1_item_d2i`, :308) or, when `it` is None, with that "
            "row's `d2i` (:311-315), refuses a NULL decode (:317), then calls the first set of "
            "`i2s`/`i2v`/`i2r` from the SAME row (:334-366) and finally frees the object with the "
            "same resolved item or that row's `ext_free` (:375-382). Consequence: the dynamic type "
            "of the object handed to a slot is fixed by the row, independent of the extension bytes."
        ),
        "config_path": (
            "do_ext_nconf (src/x509/v3_conf.rs:1012) refuses ext_nid == NID_undef (:1021), takes the "
            "registry read hold (:1035), resolves ONE borrowed row (:1041), refuses a NULL/empty "
            "value stack for v2i (:1069), calls the first set of `v2i`/`s2i`/`r2i` from that row "
            "(:1087, :1097, :1110), then encodes and frees the returned object with that same row's "
            "`it` or `ext_free` (:1126-1133). `values` is the branch's own parsed list (:1065, freed "
            "at :1090) or a section owned by the config database (:1062, not freed); `str`/`value` "
            "is borrowed and NUL-terminated."
        ),
        "registrar_obligation": (
            "The remaining obligation is the registrar's, and it is the same one B51-R6 records: a "
            "row's callback must cast the object to exactly the type its `it`/`d2i` produces (print "
            "path) or produce exactly the type its `it` encodes (config path), and a bit/enumerated "
            "row's `usr_data` must be the table its callback reads. `X509V3_EXT_add` does not check "
            "that pairing. B54-W/B54-W1/B54-W3 pin it for the standard rows."
        ),
        "ctx_obligation": (
            "`ctx` is a genuine precondition, not a nullable convenience: do_ext_nconf's r2i arm "
            "dereferences it (:1103), and the section/dirName paths of v2i_crld, v2i_idp, "
            "v2i_aaidp, v2i_NAME_CONSTRAINTS and the GENERAL_NAME builders reach "
            "X509V3_get_section(ctx, ...), which dereferences `(*ctx).db` (src/x509/v3_conf.rs:430). "
            "NULL ctx is nonetheless what the public entries' `# Safety` and several callbacks state "
            "as allowed. This is B54-F1 and the sole reason 11 rows are rejected."
        ),
    },
    "dispatch_paths": {
        "print_entry_points": [
            "X509V3_EXT_print (src/x509/v3_prn.rs:254); its callers are X509V3_extensions_print (:453), X509V3_EXT_print_fp (:489), src/x509/t_acert.rs:429, src/x509/t_req.rs:389 and src/ts/ts_lib.rs:133.",
            "X509V3_extensions_print (:396) walks an extension stack and delegates to X509V3_EXT_print (:453).",
            "X509V3_EXT_print_fp (:476) wraps a FILE in a non-closing BIO and delegates (:489).",
            "There is no X509V3_EXT_print_ex and no BIO-less i2r-to-string path in this candidate: every i2r dispatch supplies a live BIO, and X509V3_EXT_print refuses a NULL BIO/ext before any callback (:263).",
        ],
        "config_entry_points": [
            "X509V3_EXT_nconf (src/x509/v3_conf.rs:1223) -> X509V3_EXT_nconf_int (:1170) -> do_ext_nconf (:1012).",
            "X509V3_EXT_nconf_nid (:1240) -> do_ext_nconf (:1012).",
            "X509V3_EXT_add_nconf_sk (:1273) -> X509V3_EXT_nconf_int (:1291); X509V3_EXT_add_nconf (:1350) and X509V3_EXT_conf/_conf_nid (:1426, :1455) wrap these.",
        ],
        "flags": "X509V3_EXT_print's only flag use in the dispatch is `ext_flags & X509V3_EXT_MULTILINE` handed to X509V3_EXT_val_prn for an i2v result (:360); it selects no different callback and changes no type.",
        "lookup": "X509V3_EXT_get (src/x509/v3_lib.rs:851) maps the extension object's NID to a row under the registry read hold; do_ext_nconf and X509V3_EXT_i2d take their own read hold for the whole dispatch (B49/B51), so a DYNAMIC row cannot be released under a callback.",
        "free": "print: same resolved item (:378) or the row's `ext_free` (:381). config: `it()` (:1129) or the row's `ext_free` (:1132). Registry list: ext_list_free through OPENSSL_sk_pop_free (src/x509/v3_lib.rs:755).",
    },
    "row_liveness": {
        "question": "Does the registry read hold span every callback in this sweep, as it does for B51's v2i rows?",
        "answer": "YES for both dispatchers, inherited from B49/B51 and not re-measured here: X509V3_EXT_print holds RegistryReadGuard from :271 across the decode, the slot and the free; do_ext_nconf holds it from :1035 across the lookup, the slot and do_ext_i2d; X509V3_EXT_i2d/X509V3_EXT_d2i hold their own for their encoder/decoder. No new hold was added.",
        "enforcement": "src/x509/v3_prn.rs:271; src/x509/v3_conf.rs:1035; src/x509/v3_conf.rs:742; src/x509/v3_lib.rs:929 (B51's holds, unchanged).",
        "caller_rows": "X509V3_EXT_add still borrows a caller-owned row; the registry cannot protect caller storage. That remains X509V3_EXT_add's own stated caller obligation and is not re-claimed here.",
    },
    "defect_class": (
        "Unadjudicated X509V3_EXT_METHOD callback sites: 83 unsafe fn definitions whose soundness depends "
        "on what the two dispatchers pass and on the row-to-item pairing. The per-row defect classes are "
        "(a) 72 rows whose contract did not state the dispatcher-established preconditions (17 also lacked "
        "a fn-level `# Safety`) but which are sound once the dispatch is shown to fix the object's type, "
        "and (b) 11 rows whose required `ctx` precondition is contradicted by the documented ABI and "
        "dereferenced on a reachable input path."
    ),
    "rows": rows,
    "verdict_counts": {
        "selected": 83,
        "DISPATCH_DISCHARGED": 83 - len(blocked),
        "BLOCKED": len(blocked),
        "by_family": {
            fam: {
                "total": sum(1 for r in rows if r["family"] == fam),
                "discharged": sum(1 for r in rows if r["family"] == fam and r["verdict"] == "DISPATCH_DISCHARGED"),
                "blocked": sum(1 for r in rows if r["family"] == fam and r["verdict"] == "BLOCKED"),
            }
            for fam in sorted(set(r["family"] for r in rows))
        },
        "by_path": {
            p: {
                "total": sum(1 for r in rows if r["dispatch_path"] == p),
                "discharged": sum(1 for r in rows if r["dispatch_path"] == p and r["verdict"] == "DISPATCH_DISCHARGED"),
                "blocked": sum(1 for r in rows if r["dispatch_path"] == p and r["verdict"] == "BLOCKED"),
            }
            for p in sorted(set(r["dispatch_path"] for r in rows))
        },
    },
    "rejected": [
        {
            "id": r["id"], "operation": r["operation"], "file": r["file"],
            "line_current": r["line_current"], "path": r["dispatch_path"],
            "missing_fact": r.get("missing_fact"),
        }
        for r in blocked
    ],
    "findings": [
        {
            "id": "B54-F1",
            "class": "false documented precondition / reachable NULL dereference",
            "severity": "high",
            "where": [
                "X509V3_EXT_nconf (src/x509/v3_conf.rs:1223-1238), X509V3_EXT_nconf_nid (:1240-1255) and X509V3_EXT_nconf_int (:1170) all state `ctx` NULL or live.",
                "do_ext_nconf itself states `ctx` NULL or live (:1009) but its r2i arm reads `(*ctx).db`/`db_meth` at :1103 before the NULL check at :1104.",
                "X509V3_get_section (src/x509/v3_conf.rs:425) dereferences `(*ctx).db` at :430 under a `ctx` live contract.",
                "Reachable from documented-valid input: X509V3_EXT_nconf_nid(NULL, NULL, NID_subject_alt_name, \"dirName:x\") -> v2i_subject_alt -> v2i_GENERAL_NAME -> v2i_GENERAL_NAME_ex -> a2i_GENERAL_NAME (GEN_DIRNAME) -> do_dirname (src/x509/v3_san.rs:871) -> X509V3_get_section(NULL, \"x\") -> `(*ctx).db`.",
                "Equally: NID_crl_distribution_points with a value-less entry (:1348), NID_issuing_distribution_point (:1015 via set_dist_point_name), NID_id_aa_issuing_distribution_point (:1931), and any r2i row (:1103).",
            ],
            "authority_behaviour": "The pinned 3.6.4 authority has the same shape (crypto/x509/v3_conf.c:117-121 dereferences ctx->db for r2i; v3_san.c's do_dirname calls X509V3_get_section). Per AGENTS.md section 17 this is UB in the C authority: it must not be reproduced as a documented-safe interface. The candidate reproduces the behaviour but documents it as safe, which is the defect.",
            "why_it_blocks_11_rows": "The rejected rows either (i) state `ctx` is NULL-or-live while dereferencing it on a reachable arm, or (ii) correctly state `ctx` live but are called through a dispatcher whose documented contract admits NULL and does not establish the precondition. AGENTS.md §7 criterion 2 is not met in either case.",
            "remedy": [
                "Narrow the stated contract: `ctx` is non-NULL for the r2i arm and for the v2i rows that read it (v2i_crld, v2i_idp, v2i_aaidp, v2i_NAME_CONSTRAINTS, v2i_GENERAL_NAME_ex/GENERAL_NAME/GENERAL_NAMES, v2i_issuer_alt/v2i_subject_alt, r2i_certpol, r2i_pci), while rows that ignore ctx keep the nullable form. This is a documentation-only change and matches the authority's real requirement.",
                "Or add NULL guards at the dereference sites (a safety improvement over the authority; record the divergence per section 17: return an error instead of faulting).",
                "Either way X509V3_EXT_nconf*'s `# Safety` must stop admitting NULL for extensions that read ctx, and do_ext_nconf's r2i guard must test `ctx` before reading `(*ctx).db`.",
            ],
            "not_fixed_here": "B54 is an adjudication, not a repair; changing non-test source would invalidate the candidate identity this receipt binds.",
            "dynamic_proof": "NOT_RUN as a crash test: a NULL dereference aborts the test process, so the proof recorded here is static (the exact call chain above) and the rejection is stated rather than a fabricated discharge.",
        },
        {
            "id": "B54-F2",
            "class": "false documented precondition (value)",
            "severity": "medium",
            "where": [
                "X509V3_EXT_nconf (src/x509/v3_conf.rs:1223-1238), X509V3_EXT_nconf_nid (:1240-1255) and X509V3_EXT_nconf_int (:1170) state `value` NULL or NUL-terminated.",
                "v3_check_critical (:797) immediately runs `strncmp(*value, ...)` at :801 and v3_check_generic (:824) does the same at :829, so a NULL value faults before do_ext_nconf.",
            ],
            "authority_behaviour": "The authority dereferences `value` unconditionally as well (crypto/x509/v3_conf.c:42, :70).",
            "impact": "Not load-bearing for any of the 83 rows: their contracts require a NUL-terminated (non-NULL) value, which every in-tree caller supplies (X509V3_EXT_add_nconf_sk passes CONF_VALUE values, which the config loader guarantees non-NULL). Recorded so the entry contracts can be corrected to `value` non-NULL.",
            "remedy": "State `value` non-NULL NUL-terminated at the three entry points (documentation only), or guard it and raise X509V3_R_INVALID_EXTENSION_STRING.",
        },
    ],
    "cross_receipt_findings": [
        {
            "id": "B54-X1",
            "affects": "boundary-sweep-B51, row B51-V2I-005 (v2i_AUTHORITY_INFO_ACCESS), recorded there as SAFETY_DISCHARGED and applied",
            "finding": "B51-R8 justified the NULL ctx of the fifteen rows with 'Only v2i_AUTHORITY_INFO_ACCESS forwards ctx, to v2i_GENERAL_NAME_ex, which documents NULL-or-live'. B54 shows that v2i_GENERAL_NAME_ex's NULL-or-live contract is false (B54-F1: do_dirname -> X509V3_get_section dereferences ctx). v2i_AUTHORITY_INFO_ACCESS therefore inherits an unestablished ctx precondition and should not remain discharged as stated.",
            "recommendation": "Reopen B51-V2I-005 at the next B51 correction and either narrow the forwarded contract to ctx-live for Ainfo (it always forwards) or add the NULL guard; the other nine B51 rows ignore ctx and are unaffected.",
        }
    ],
    "contracts_added": [
        "i2s_poison (src/ct/ct_x509v3.rs)", "s2i_poison (src/ct/ct_x509v3.rs)",
        "as_identifier_choice_canonize (src/x509/v3_asid.rs)", "audit_i2s (src/x509/v3_audit_id.rs)",
        "audit_s2i (src/x509/v3_audit_id.rs)", "i2v_OSSL_BASIC_ATTR_CONSTRAINTS (src/x509/v3_battcons.rs)",
        "i2v_BASIC_CONSTRAINTS (src/x509/v3_bcons.rs)", "bitst_i2v (src/x509/v3_bitst.rs)",
        "bitst_v2i (src/x509/v3_bitst.rs)", "i2v_EXTENDED_KEY_USAGE (src/x509/v3_extku.rs)",
        "i2v_AUTHORITY_INFO_ACCESS (src/x509/v3_info.rs)", "ext_list_free (src/x509/v3_lib.rs)",
        "i2v_POLICY_CONSTRAINTS (src/x509/v3_pcons.rs)", "i2v_POLICY_MAPPINGS (src/x509/v3_pmaps.rs)",
        "print_int_month / print_bit_week / print_day_of_week / print_int_day_of_week (src/x509/v3_timespec.rs)",
        "i2v_TLS_FEATURE (src/x509/v3_tlsf.rs)",
    ],
    "negative_control": [
        {
            "id": "B54-C1",
            "name": "x509::v3_prn::tests::print_slots_receive_the_tag_their_rows_item_decodes",
            "kind": "court functional test, lib unittest (print path: i2s and i2r)",
            "guard": "the type fact itself: the dispatcher decodes with the row's `it` and hands that object to the same row's slot (src/x509/v3_prn.rs:296-316, :334-366)",
            "result": "PASS",
            "observation": "Four test rows are registered. The correctly paired i2r INTEGER row and OCTET STRING row each observe their own tag and succeed; the correctly paired i2s row observes INTEGER and succeeds and its returned seam block is released by the dispatcher's OwnedStr. The fourth row is deliberately mispaired (OCTET STRING item, INTEGER-expecting probe): the probe observes V_ASN1_OCTET_STRING, refuses, and X509V3_EXT_print returns 0. The mismatch is caught by the harness's tag check, not silently reinterpreted.",
            "mutation_sensitive": False,
            "limits": "The probe reads only `type_`, which every item used here shares (ASN1_STRING shape); a violated type fact that preserves the tag is out of this control's reach and is covered by the pairing witnesses B54-W/W1/W3.",
        },
        {
            "id": "B54-C2",
            "name": "x509::v3_prn::tests::i2v_slot_receives_the_tag_its_rows_item_decodes",
            "kind": "court functional test, lib unittest (encode path: i2v)",
            "guard": "the same decoded object and the single ownership transfer of the returned CONF_VALUE stack (src/x509/v3_prn.rs:353-361, :372)",
            "result": "PASS",
            "observation": "The correctly paired INTEGER i2v row observes V_ASN1_INTEGER and succeeds; its returned stack is popped free by the dispatcher. The mispaired OCTET-item/INTEGER-expecting row observes the real tag and is refused (print returns 0).",
            "mutation_sensitive": False,
            "limits": "As B54-C1; ownership is exercised (the dispatcher frees the returned stack) but not measured with an allocator hook.",
        },
        {
            "id": "B54-C3",
            "name": "x509::v3_conf::tests::config_slots_receive_conf_values_and_check_the_rows_item",
            "kind": "court functional test, lib unittest (config path: v2i and s2i)",
            "guard": "the v2i/s2i input contract (a live CONF_VALUE stack / a NUL-terminated string) and the row-item identity the encoder uses (src/x509/v3_conf.rs:1069-1126)",
            "result": "PASS",
            "observation": "The correctly paired v2i row observes a live CONF_VALUE (name 'b54', value 'probe'), confirms its row declares the item it produces, and the extension is built through that item. The mispaired row (INTEGER item, octet-producing callback) is refused by the callback's own entry check, so nothing is encoded or freed as the wrong type. The s2i row observes the raw NUL-terminated value and succeeds.",
            "mutation_sensitive": False,
            "limits": "The check is a row-item identity check performed before any input is used; it does not exercise a wrong *input* type, because no safe way exists to hand a v2i a non-CONF_VALUE stack (that would itself be UB).",
        },
        {
            "id": "B54-W1",
            "name": "ocsp::v3_ocsp::b54_tests::the_print_slots_pair_each_printer_with_its_declared_item",
            "kind": "per-call-site witness (AGENTS.md section 22), production rows",
            "guard": "the print path's pairing for ossl_v3_ocsp_crlid / _acutoff / _serviceloc",
            "result": "PASS; FAILED under mutation M1; PASS again after byte-identical revert",
            "mutation_sensitive": True,
            "mutation": "src/ocsp/v3_ocsp.rs: `i2r: Some(i2r_ocsp_crlid)` in row ossl_v3_ocsp_crlid replaced by `i2r: Some(i2r_ocsp_acutoff)`",
            "fails_if": "observed FAILED, rc 101, at src/ocsp/v3_ocsp.rs: 'assertion left == right failed' comparing the row's i2r address with i2r_ocsp_crlid (0 passed; 1 failed; 2340 filtered out)",
            "restore": "byte-for-byte: src/ocsp/v3_ocsp.rs sha256 b97508ed451e344c3584f53fbfcbb340eef47e8e3c7e72441ce133e3877f3679 before and after the mutation (`sha256sum -c` 6/6 OK), and the test passes again",
            "limits": "This mutation is memory-unsafe at runtime (an OCSP_CRLID would be printed as a GENERALIZEDTIME), so the witness - not a dispatch - is the only safe detector. That limit is exactly why the pairing is a registrar obligation rather than a runtime check.",
        },
        {
            "id": "B54-W2",
            "name": "x509::v3_prn::tests::standard_rows_declare_the_item_their_callbacks_were_written_for",
            "kind": "per-call-site witness (AGENTS.md section 22), production rows",
            "guard": "20 production rows across the i2s, i2v/v2i and i2r families: each row's declared item must be the item its audited callback casts to",
            "result": "PASS; FAILED under mutations M2 and M4; PASS again after both byte-identical reverts",
            "mutation_sensitive": True,
            "mutation": "M2: src/x509/v3_bcons.rs `it: Some(BASIC_CONSTRAINTS_it)` -> `Some(crate::x509::v3_pcons::POLICY_CONSTRAINTS_it)`. M4: src/x509/v3_utf8.rs `it: Some(ASN1_UTF8STRING_it)` -> `Some(crate::asn1::items::ASN1_IA5STRING_it)`",
            "fails_if": "M2 observed FAILED, rc 101, 'NID 87: the row declares a different item than the audited callback casts to'; M4 observed FAILED, rc 101, same assertion for NID_subjectSignTool",
            "restore": "byte-for-byte: src/x509/v3_bcons.rs sha256 1496534d8fcc799498a54125a99e4fe1dc98f7669075bbb52eac1b8acdcc4b02 and src/x509/v3_utf8.rs sha256 8768f06bc4423ee8634719b46437c3e974cb19c4f052d4bcfcb4bd7602cc5c68 before and after; `sha256sum -c` 6/6 OK; the test passes again",
            "limits": "Covers 20 of the 72 discharged rows by name; the remaining rows are covered by the per-row type facts in `rows` and by B54-C1..C3 for the mechanism.",
        },
        {
            "id": "B54-W3",
            "name": "x509::v3_san::tests::the_alt_rows_pair_each_builder_with_its_nid",
            "kind": "per-call-site witness (AGENTS.md section 22), production rows",
            "guard": "ossl_v3_alt's three rows: NID-to-builder pairing and the shared GENERAL_NAMES item",
            "result": "PASS; FAILED under mutation M3; PASS again after byte-identical revert",
            "mutation_sensitive": True,
            "mutation": "src/x509/v3_san.rs: the two v2i arguments of ossl_v3_alt swapped (`san_v2i` <-> `san_v2i_issuer`)",
            "fails_if": "observed FAILED, rc 101, 'subjectAltName must be built by v2i_subject_alt' (0 passed; 1 failed; 2340 filtered out)",
            "restore": "byte-for-byte: src/x509/v3_san.rs sha256 620321d30951f364b072eec52bf90ae30c4d1df4576d092c2347e679f5699057 before and after; `sha256sum -c` 6/6 OK; the test passes again",
            "limits": "The swapped pair is behaviourally wrong but memory-safe (both build GENERAL_NAMES), so this mutation could in principle also be caught at runtime by an email-copy test; the witness catches it without relying on such a test.",
        },
    ],
    "positive_control": [
        {
            "id": "B54-P1",
            "name": "x509::v3_conf::tests::v2i_callbacks_build_end_to_end (B51) and the B54-C3 correct pairings",
            "kind": "court functional tests",
            "result": "PASS (part of the 161 x509:: tests at --test-threads=4)",
            "observation": "Both the B51 ten-row build test and B54-C3 drive real extensions through the real dispatcher, so the callbacks demonstrably ran and their results were encodable by the row's own item.",
            "limits": "Proves dispatch and pairing, not byte equality with the authority (see not_run).",
        }
    ],
    "hidden_obligations": 0,
    "hidden_obligations_note": (
        "Zero hidden obligations for the 72 discharged rows: each row's retained duties are stated in "
        "its contract or in this receipt - the registrar's callback/item (and usr_data) pairing, the "
        "caller-owned-row lifetime of X509V3_EXT_add, the B51-R9 no-registry-writer re-entry duty, and "
        "for the config rows that ignore ctx nothing further. The 11 rejected rows are not counted as "
        "hidden: B54-F1 states their missing precondition explicitly. B54-F2 and B54-X1 are stated "
        "rather than hidden."
    ),
    "new_unsafe_assumptions": 0,
    "new_unsafe_assumptions_note": "No unsafe fn was added and no exported item changed. The test code adds one test-only lock and one new #[cfg(test)] module; it adds no non-test unsafe operation.",
    "unsafe_operations_removed": 0,
    "unsafe_operations_introduced": 0,
    "test_only_unsafe_added": 0,
    "boundary_size": (
        "Two dispatchers (X509V3_EXT_print, do_ext_nconf) plus the shared encode (do_ext_i2d) and the "
        "registry list destructor; 83 callback definitions, of which 72 are discharged and 11 rejected; "
        "17 new fn-level contracts; 2 production-row witnesses over 23 rows (W1: 3 OCSP rows; W2: 20 "
        "rows; W3: 3 alt rows) and 3 type-check controls. No new unsafe abstraction was introduced."
    ),
    "safe_callers_can_cause_ub": False,
    "safe_callers_can_cause_ub_note": (
        "Every entry point that reaches these callbacks is `unsafe extern \"C\"` (X509V3_EXT_print, "
        "X509V3_EXT_extensions_print, X509V3_EXT_print_fp, X509V3_EXT_nconf, _nconf_nid, _conf, "
        "_conf_nid, _add_nconf, _add_nconf_sk) and every slot is Option<unsafe extern \"C\" fn>; no "
        "safe Rust item accepts or returns X509V3ExtMethod. A safe Rust caller cannot reach them. The "
        "11 rejected rows are a C-ABI-contract defect (documented-valid NULL ctx), not a safe-Rust "
        "escape hatch."
    ),
    "fast_gate_at_candidate": {
        "candidate": "7e8e11879 + the uncommitted doc/test delta",
        "container": "docker/openssl-rs-court.sh (never the host)",
        "toolchain": "pinned by the court image; CARGO_BUILD_JOBS=4; one heavy command at a time",
        "fmt": "cargo fmt --all -- --check: exit 0 (FMT_EXIT=0)",
        "clippy": "cargo clippy --lib -- -D warnings: exit 0, Finished dev profile",
        "focused_tests": "cargo test --lib x509:: -- --test-threads=4: ok. 161 passed; 0 failed; 0 ignored; 2180 filtered out",
        "ocsp_tests": "cargo test --lib ocsp:: -- --test-threads=4: ok. 7 passed; 0 failed; 0 ignored",
        "new_tests": "the six B54 tests pass individually at --exact --test-threads=1 (6 passed; 0 failed)",
        "scope_note": "FAST evidence only. The full library suite (serial and threaded), Miri/ASan/TSan/LSan, dudect, authority differential, consumer closures and CAMPAIGN-STATUS application are NOT_RUN.",
        "harness_note": "The B53 control asserts a process-global registry count, and B54 adds registry-mutating units. src/x509/v3_prn.rs had a private lock while src/x509/v3_conf.rs used crate::test_support::lock_global_state(); the two did not exclude each other, which made the B53 count race-prone. Every registry-touching unit in these two modules now takes lock_global_state(). No assertion was weakened; the suite was run six consecutive times with --test-threads=4 and passed 161/161 each time.",
    },
    "residuals": [
        {"id": "B54-R1", "severity": "high", "disposition": "OPEN-FINDING", "description": "B54-F1: documented-nullable ctx is dereferenced on reachable config paths; blocks 11 rows and undermines B51's v2i_AUTHORITY_INFO_ACCESS (B54-X1)."},
        {"id": "B54-R2", "severity": "medium", "disposition": "OPEN-FINDING", "description": "B54-F2: the public config entries document `value` as nullable while v3_check_critical/generic dereference it immediately."},
        {"id": "B54-R3", "severity": "medium", "disposition": "STATED-REGISTRAR-OBLIGATION", "description": "The callback/item (and usr_data) pairing is not checked by X509V3_EXT_add; B54-W/W1/W2/W3 pin the standard rows, but a caller-registered row remains the registrar's obligation."},
        {"id": "B54-R4", "severity": "low", "disposition": "NOT-RUN", "description": "Failure-path ownership (partial builds in the 72 discharged callbacks) is exercised by the B51 reject tests and B54-C3 but not measured leak-free (no allocator hook or LSan)."},
        {"id": "B54-R5", "severity": "low", "disposition": "NOT-RUN", "description": "No DER comparison against the authority for the discharged rows; the controls prove dispatch and pairing, not byte equality."},
        {"id": "B54-R6", "severity": "low", "disposition": "STATED-ABI-OBLIGATION", "description": "B51-R9 still applies: a callback that runs under the registry read hold must not call a registry writer (read-then-write self-deadlock). B54 adds no hold."},
    ],
    "not_run": [
        {"gate": "full library suite, serial and --test-threads=4", "blocker": "BATCH gate; only the x509:: and ocsp:: filters and the six new tests were run"},
        {"gate": "Miri (Stacked/Tree Borrows)", "blocker": "not invoked; no new aliasing model claim"},
        {"gate": "ASan / LeakSanitizer", "blocker": "not invoked; partial-build ownership is exercised but not measured"},
        {"gate": "TSan", "blocker": "not invoked; the registry concurrency argument is B49's and B51's, not re-measured"},
        {"gate": "dudect / constant-time", "blocker": "no secret-dependent operation is touched by these callbacks"},
        {"gate": "authority differential (DER bytes / error strings)", "blocker": "no differential court run; authority statements are read from the pinned 3.6.4 source"},
        {"gate": "dynamic demonstration of B54-F1", "blocker": "a NULL dereference aborts the test process; the proof is the static call chain recorded in findings[B54-F1]"},
        {"gate": "consumer closure (curl/nginx/OpenSSH/HAProxy/Redis)", "blocker": "deliberately not run"},
        {"gate": "CAMPAIGN-STATUS.json / state.json application", "blocker": "deliberately not run; this is an unapplied adjudication draft"},
        {"gate": "independent review", "blocker": "review.state is pending-independent-review; the author of the claim must not be its sole adjudicator"},
    ],
    "non_claims": [
        "B54 scopes its 72 discharges to the named operations and their dispatch paths; X509_VERIFY_POLICY stays OWNERSHIP_RECONSTRUCTED and is not discharged mechanism-wide.",
        "The 11 rejected rows are NOT discharged. No row is counted as discharged on documentation alone: each DISPATCH_DISCHARGED row carries the caller that supplies its argument and the type fact that makes the cast sound.",
        "The 17 added `# Safety` blocks state preconditions the dispatcher establishes; the discharge rests on the dispatch chain, not on the prose.",
        "The controls prove dispatch pairing and object tags; they do not prove DER equality, leak-freedom, or constant-time behaviour.",
        "B54-F1 means eleven rows, and B51's v2i_AUTHORITY_INFO_ACCESS, should not be relied on for a documented-nullable ctx; the rest of B51's ten ignore ctx.",
        "No sanitizer, Miri, dudect, leak check or authority differential was run; nothing here is a BOUNDARY or SEAL result.",
        "The candidate is HEAD plus an uncommitted documentation/test-only delta; a reviewer must freeze that delta as S' before applying.",
    ],
    "review_conditions": [
        "C1_identity: candidate.head is 7e8e11879 with the working delta enumerated; files_sha256 binds the adjudicated tree; line_current is recomputed there and `line` is the census coordinate.",
        "C2_dispatch: print rows are adjudicated through X509V3_EXT_print's single row resolution (decode with the row's item, call the same row's slot, free with the same item); config rows through do_ext_nconf's single row resolution and do_ext_i2d. The two paths are not blended.",
        "C3_counts: 83 selected = 33 i2r + 7 i2s + 12 v2i + 6 s2i + 3 free + 22 other, matching the queue; verdicts 72 DISPATCH_DISCHARGED / 11 BLOCKED.",
        "C4_rejections: every rejected row names the missing fact (ctx non-NULL not established); no rejection is for a documentation gap that the receipt itself supplies.",
        "C5_controls: 3 type-check controls and 3 production-row witnesses; four production mutations each observed FAILED and reverted byte-for-byte (sha256 6/6 OK).",
        "C6_findings: B54-F1/F2 and B54-X1 are real defects, not documentation-only; they are the reason the sweep is not 83/83.",
    ],
    "applied": False,
    "review": {
        "reviewer": "pending independent adjudication (this receipt was authored by the conversion agent)",
        "state": "pending-independent-review",
        "verdict": None,
        "applied": False,
        "date": None,
        "would_be_applied_delta": "X509_VERIFY_POLICY (site-scoped): 83 BLOCKED -> 11 BLOCKED / 72 DISCHARGED if every row is accepted as recorded; any accepted rejection keeps that row BLOCKED. Closure 149 BLOCKED / 175 DISCHARGED -> 66 BLOCKED / 258 DISCHARGED if all 72 are applied.",
    },
    "schema_note": "New relative to B51: `rows` (one record per obligation with dispatch_path/caller/type_fact/verdict), `rejected`, `findings`, `cross_receipt_findings`, `contracts_added`, and the per-family and per-path verdict breakdowns. `line` is the census coordinate; `line_current`/`slot_lines_current` and files_sha256 are recomputed from the adjudicated tree.",
    "generator": {
        "script": "forensics/memory-safety/campaign/safe-c33/atlas-refresh/b54_generate.py",
        "evidence": "forensics/memory-safety/campaign/safe-c33/atlas-refresh/b54_evidence.py",
        "note": "The two files reproduce `rows` from evidence/closure-ssh-311.json plus the per-row prose; the JSON is the artefact.",
    },
}

with open(OUT, "w") as fh:
    json.dump(receipt, fh, indent=1, sort_keys=False)
    fh.write("\n")

print("rows", len(rows), "paths", paths)
print("verdicts", {v: sum(1 for r in rows if r["verdict"] == v) for v in set(r["verdict"] for r in rows)})
print("blocked", [(r["operation"], r["file"]) for r in blocked])
print("wrote", OUT)
