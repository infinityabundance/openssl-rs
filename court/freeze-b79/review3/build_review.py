#!/usr/bin/env python3
"""Assemble evidence/b79-review-rebind.json from the measured artefacts."""
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path("/home/user/openssl-rs")
AR = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh"
CAND = "08cb1148b40aa4cebc727e7c0b988505d3094ff0"
OUT = ROOT / "evidence/b79-review-rebind.json"

spans = {r["id"]: r for r in json.loads(
    (ROOT / "court/freeze-b79/review3/spans.json").read_text())}
rdiff = json.loads((ROOT / "court/freeze-b79/review3/receipt-diffs.json").read_text())
by_b = {r["boundary"]: r for r in rdiff["rows"]}

# ---------------------------------------------------------------- authored
CHANGE_COMMIT = {"cmp": "688c27cb8", "rand": "97a1240e7", "ssl": "688c27cb8"}
GROUP = {i: "cmp" for i in ("OSSH-V1I-049", "OSSH-V1I-050", "OSSH-V1I-051",
                            "OSSH-V1I-052", "OSSH-V1I-053", "OSSH-V1I-054",
                            "OSSH-V1I-059", "OSSH-V1I-060", "OSSH-V1I-061",
                            "OSSH-V1I-063", "OSSH-V1I-064", "OSSH-V1I-065",
                            "OSSH-V1I-067", "OSSH-V1I-069")}
GROUP.update({"RAND-CTX-001": "rand", "ssl_conf.rs:616": "ssl"})

CALLERS = {
    "OSSH-V1I-049": ["the six `ctx_set1_dup!` invocations (cmp_ctx.rs:806-840) pass it as `$dup`",
                     "macro body `ctx_set1_dup!`: `unsafe { $dup(val) }` where the public setter's `# Safety` makes `val` NULL or live"],
    "OSSH-V1I-050": ["the same macro passes it as `$free`: `$free((*ctx).$field.cast())`, the field being NULL (fresh zeroed context) or the previous duplicate the context owns",
                     "`destroy_body`/`OSSL_CMP_CTX_free` (cmp_ctx.rs:565-573) release the same members exactly once"],
    "OSSH-V1I-051": ["`OSSL_CMP_CTX_set1_serialNumber` (`ctx_set1_dup!`, cmp_ctx.rs:830-835) passes it as `$dup`"],
    "OSSH-V1I-052": ["the same setter passes it as `$free` on the exclusively owned incumbent member"],
    "OSSH-V1I-053": ["`OSSL_CMP_CTX_set1_p10CSR` (`ctx_set1_dup!`, cmp_ctx.rs:836-841) passes it as `$dup`"],
    "OSSH-V1I-054": ["the same setter passes it as `$free` on the exclusively owned incumbent member"],
    "OSSH-V1I-059": ["`OPENSSL_sk_pop_free((*ctx).subject_alt_names, Some(general_name_free_void))` (cmp_ctx.rs:565); elements are pushed only by the push0 setter, which takes ownership"],
    "OSSH-V1I-060": ["`OPENSSL_sk_pop_free((*ctx).req_extensions, Some(x509_extension_free_void))` (cmp_ctx.rs:566, 1253)"],
    "OSSH-V1I-061": ["`OPENSSL_sk_pop_free((*ctx).status_string, Some(utf8_string_free_void))` (cmp_ctx.rs:573, 881)"],
    "OSSH-V1I-063": ["`itavs_free` (cmp_ctx.rs:460-463): `OPENSSL_sk_pop_free(sk, Some(itav_free_void))`, reached from destroy_body and from `OSSL_CMP_CTX_reset_geninfo_ITAVs`"],
    "OSSH-V1I-064": ["`OPENSSL_sk_pop_free((*ctx).policies, Some(policy_free_void))` (cmp_ctx.rs:567); the stack is created by the push0 setter, which takes ownership"],
    "OSSH-V1I-065": ["cmp_ctx.rs:628, 637 (a fresh zeroed context's NULL slots) and :1638, :1643 (`ptr::addr_of_mut!` on the context's own member slots)"],
    "OSSH-V1I-067": ["cmp_asn.rs:2105, 2173, 2385, 3128, 3137, 3147 — every call is a failure arm of an in-crate constructor that still owns the `itav_new()` block"],
    "OSSH-V1I-069": ["cmp_asn.rs:2242, 2252, 2263, 2273 — failure arms after `rootcakeyupdate_new()`/a failed `X509_dup`; the deliberate NULL pass at :2273 is within the contract"],
    "RAND-CTX-001": ["`context_init` (src/context/mod.rs) installs it as slot 5 through the `OSSL_LIB_CTX_DRBG_INDEX` constructor table; no Rust caller",
                     "the returned block is published once and released by `ossl_rand_ctx_free`"],
    "ssl_conf.rs:616": ["`cmd_MinProtocol` (ssl_conf.rs:975-978) and `cmd_MaxProtocol` (:1007-1010), both `unsafe extern \"C\"` rows of the `SSL_CONF` command table",
                        "reached only through `SSL_CONF_cmd`, which refuses NULL `cctx`/`value` before the indirect call"],
}

ANSWERS = {
    "cmp-thunk": {
        "a_safe_rust_ub": "No. Each thunk is a private `unsafe extern \"C\" fn` with no `pub`; every occurrence is a fn-pointer argument in a macro expansion or an `OPENSSL_sk_pop_free` freefunc, and each direct call site passes a value the same frame owns.",
        "b_unsafe_covered": "Yes. The span holds one unsafe call; its precondition is stated by the fn-level `# Safety` added at 688c27cb8 (provenance, whole-value extent, exclusive release, NULL no-op) and by the inline SAFETY; the caller side is the macro's exclusive-storage replacement or the stack the context owns.",
        "c_hidden_obligation": "None new. The retained external obligation is the b76 one: a C caller that hands a stack it still owns through a set0 setter violates that setter's `# Safety`. Recorded, not hidden.",
        "d_load_bearing_control": "The span resolver plus the CALLERS witness: C4 fires for every row (corrupting one row's hash blocks exactly that row) and the b76 harness canaries K11 (direct thunk call) and K12 (stray item free) fire at this candidate.",
    },
    "cmp-065": {
        "a_safe_rust_ub": "No. Private `unsafe fn`; four in-crate call sites, all passing `ptr::addr_of_mut!` on the context's own member slots.",
        "b_unsafe_covered": "Yes. The contract now states the exact slot discipline and the failure-atomicity of `*pmd`; the b76 caveat about an arbitrary NID is discharged by the contract itself (an unknown NID makes `OBJ_nid2sn` answer NULL and the fetch refuses without a dereference).",
        "c_hidden_obligation": "None found; the incumbent release followed by the new store is single-owner and the failure arm leaves `*pmd` untouched.",
        "d_load_bearing_control": "C4 (per-row break canary) fires; the call-site coordinates in `established_by` are re-bound here to 628/637/1638/1643.",
    },
    "rand": {
        "a_safe_rust_ub": "No. `pub(crate) unsafe extern \"C\"` reached only from `context_init`'s constructor table; no safe-Rust path exists.",
        "b_unsafe_covered": "Yes. Every unsafe operation in the span carries its own contract: the initialiser is called with NULL settings under `OPENSSL_INIT_BASE_ONLY` (no caller memory read); `CRYPTO_strdup`/`OwnedStr::adopt` own their fresh seam block; the two stores target this frame's unpublished block.",
        "c_hidden_obligation": "None new. `_libctx` is never read, so the function has no caller precondition; it stays `unsafe` because it hands out raw ownership.",
        "d_load_bearing_control": "C4 fires; the span hash, the body snapshot and the structured unsafe-operation lines are re-bound together so the row cannot cite a body it no longer contains.",
    },
    "ssl": {
        "a_safe_rust_ub": "No. Private `unsafe fn`; the only callers are the two `unsafe extern \"C\"` command-table rows, reached through `SSL_CONF_cmd`, which refuses NULL `cctx`/`value` first.",
        "b_unsafe_covered": "Yes. The `# Safety` section states the `cctx`/`value`/`bound` obligations and the early return when both `ctx` and `ssl` are NULL; the added `unsafe { }` wraps the same callee with the same arguments.",
        "c_hidden_obligation": "None found. Acceptance does not imply a write: the bound is written only for the matching version arms, so a rejected name leaves it untouched.",
        "d_load_bearing_control": "C4 fires; the in-file control `conf_cmd_min_max_protocol_bounds_are_range_checked` is NOT_RUN here (no compile) and belongs to the next BATCH gate.",
    },
}


def src_lines(commit, file):
    raw = subprocess.run(["git", "-C", str(ROOT), "show", f"{commit}:{file}"],
                         capture_output=True, check=True).stdout.decode()
    return raw.splitlines()


def doc_block(lines, start_line):
    i = start_line - 2
    out = []
    while i >= 0 and (lines[i].lstrip().startswith("///")
                      or lines[i].lstrip().startswith("#[doc")):
        out.append(lines[i].strip())
        i -= 1
    return list(reversed(out))


rows = []
for bid in ("OSSH-V1I-049", "OSSH-V1I-050", "OSSH-V1I-051", "OSSH-V1I-052",
            "OSSH-V1I-053", "OSSH-V1I-054", "OSSH-V1I-059", "OSSH-V1I-060",
            "OSSH-V1I-061", "OSSH-V1I-063", "OSSH-V1I-064", "OSSH-V1I-065",
            "OSSH-V1I-067", "OSSH-V1I-069", "RAND-CTX-001", "ssl_conf.rs:616"):
    s = spans[bid]
    g = GROUP[bid]
    d = by_b[bid]
    lines = src_lines(CAND, s["file"])
    doc = doc_block(lines, s["new_span"]["start_line"])
    has_safety = any("# Safety" in x or "Safety" in x for x in doc)
    answers = ANSWERS["cmp-thunk"] if g == "cmp" else (
        ANSWERS["cmp-065"] if bid == "OSSH-V1I-065" else ANSWERS[g])
    rows.append({
        "boundary": bid,
        "receipt": d["receipt"],
        "file": s["file"],
        "operation": s["operation"],
        "kind": "UNSAFE_FN_DEF",
        "prior": {"coordinate": d["old"]["line"],
                  "span_lines": [d["old"]["span_start_line"], d["old"]["span_end_line"]],
                  "span_sha256": d["old"]["span_sha256"],
                  "verdict": d["prior_verdict"], "review": d["prior_review"]},
        "current": {"coordinate": d["new"]["line"],
                    "def_line": s["new_span"]["def_line"],
                    "span_lines": [s["new_span"]["start_line"],
                                   s["new_span"]["end_line"]],
                    "span_sha256": s["new_span"]["sha256"],
                    "qualified_identity": s["new_span"]["qualified_identity"],
                    "resolution": s["new_span"]["resolution"]},
        "delta": {"introduced_by": CHANGE_COMMIT[g],
                  "classification": s["classification"], "statement": s["delta"],
                  "old_span_text": s["old_lines"],
                  "new_span_text": s["new_lines"]},
        "contract": {"safety_section_present": has_safety,
                     "doc_block_quote": doc[:14],
                     "note": ("the fn-level `# Safety` sits above the span and is "
                              "therefore not part of the span hash"
                              if g != "rand" else
                              "no `# Safety` section: `_libctx` is never read and the "
                              "function has no caller-visible precondition; it stays "
                              "`unsafe` because it hands out raw ownership")},
        "body_quote": s["new_lines"],
        "callers": CALLERS[bid],
        "answers": answers,
        "verdict": "ACCEPT",
        "verdict_basis": ("re-established at this candidate: the in-span delta is "
                          f"{s['classification']} ({s['delta']}); the body, contract "
                          "and every use site were re-read and the four questions "
                          "re-answered at " + CAND[:9]),
        "residuals": ([
            "the external C-ABI obligation at the set0/push0 boundary is retained, unchanged from b76",
        ] if bid in ("OSSH-V1I-059", "OSSH-V1I-060", "OSSH-V1I-061",
                     "OSSH-V1I-063", "OSSH-V1I-064") else
            ["no `# Safety` section, justified by the absent caller precondition "
             "(`_libctx` unused); `missing_safety_doc` does not apply to a "
             "`pub(crate)` item"] if g == "rand" else
            ["the in-file control for this site is NOT_RUN at this candidate (no compile)"]
            if g == "ssl" else []),
    })

controls = [
    {"id": "C0-candidate", "purpose": "bind every hash to the review candidate",
     "observed": f"branch stage/p25/b75-ocsp, HEAD {CAND}; span resolver = "
                 "consumer_closure.resolve_operation_span at source_commit=CAND",
     "pass": True},
    {"id": "C1-stale-reproduction",
     "purpose": "the tool's own adjudicator must still refuse all sixteen at the "
                "unmodified receipts",
     "observed": "16/16 BLOCKED (span-hash-mismatch), matching the b79b closures",
     "pass": True},
    {"id": "C2-content-acceptance",
     "purpose": "after the re-bind the same adjudicator must discharge all sixteen",
     "observed": "16/16 DISCHARGED; covers_current=True and covers_site=True with "
                 "binding=same-resolved-definition for every row",
     "pass": True},
    {"id": "C3-per-row-break-canary",
     "purpose": "corrupt exactly one row's span_sha256 in a private receipt copy",
     "observed": "16/16 FIRED: the corrupted row is BLOCKED and the other fifteen "
                 "still discharge",
     "pass": True},
    {"id": "C4-doc-only-invariant",
     "purpose": "revert the one changed line in a provided-text span",
     "observed": "14/14 doc-only rows reproduce their recorded prior hash; the two "
                 "annotation-only rows are excluded by construction",
     "pass": True},
    {"id": "C5-caller-witness",
     "purpose": "the CALLERS/FAMILY detectors must be load-bearing at this candidate",
     "observed": "CALLERS problems=[] on the tree; K11 break-direct-thunk-call, "
                 "K12 break-stray-item-free, K7 real-call-site-witness and K9 "
                 "break-span-hash all FIRED. K1/K2 are baseline assertions about the "
                 "b76 defect state and are not applicable here.",
     "pass": True},
    {"id": "C6-no-collateral",
     "purpose": "no row outside the sixteen changed",
     "observed": "with the sixteen rows removed, each receipt is field-for-field "
                 f"identical to its HEAD copy; collateral={rdiff['collateral']}",
     "pass": rdiff["collateral"] == []},
]

review = {
    "schema": "openssl-rs/safe-c33/b79-review-rebind/v1",
    "kind": "independent-review-and-receipt-rebind",
    "subphase": "safe-c33/b79 review-3: re-establish and re-bind the sixteen rows the "
                "b79b closures left BLOCKED",
    "generated_utc": "2026-11-14T00:00:00Z",
    "reviewer": {
        "role": "independent reviewer and receipt re-binder",
        "independence": "not the author of 688c27cb8, 97a1240e7, 5595a1f5e or the "
                        "b76/b78 receipts; the verdicts below rest on outputs of the "
                        "closure tool read at this candidate",
    },
    "venue": {
        "free_g_available_gib": 29,
        "memory_cap": "16 GiB / 16 vCPU, user-authorized AGENTS.md 6.1 deviation",
        "compilation": "none (source-level review; no cargo, no binary)",
        "work_done": "span resolution, adjudication and canaries only",
    },
    "candidate_identity": {
        "source_head": CAND,
        "branch": "stage/p25/b75-ocsp",
        "files_sha256": {f: hashlib.sha256(subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{CAND}:{f}"],
            capture_output=True, check=True).stdout).hexdigest()
            for f in ("src/cmp/cmp_ctx.rs", "src/cmp/cmp_asn.rs",
                      "src/rand/rand_lib.rs", "src/ssl/ssl_conf.rs")},
        "closure_tool_sha256": hashlib.sha256(
            (ROOT / "forensics/tools/consumer_closure.py").read_bytes()).hexdigest(),
        "span_schema": "safe-c33/operation-span-sha256/v1",
    },
    "method": {
        "task1": "located each operation at the candidate by (file, qualified "
                 "operation) with the tool's own resolver; quoted the brace-matched "
                 "span and the fn-level contract",
        "task2": "resolved the prior span at the commit whose bytes the recorded "
                 "hash belongs to (bb7d5206 for the v1i rows, 04acfb7e for B69, "
                 "b6f38f1 for the sslconf row), confirmed it reproduces the "
                 "recorded hash, then diffed it against the candidate span and "
                 "classified the delta hunk-locally",
        "task3": "answered the four questions from source at this candidate and "
                 "re-ran the closure adjudicator plus per-row canaries",
        "task4": "updated only the sixteen rows (plus one additive receipt-level "
                 "block per receipt) and re-ran the adjudicator and canaries",
    },
    "prior_state": {
        "closures": ["evidence/closure-ssh-b79b.json",
                     "evidence/closure-sshd-b79b.json"],
        "tally": "290 obligations, 274 DISCHARGED / 16 BLOCKED / 0 UNKNOWN, element 7 PASS",
        "cause": "every one of the sixteen was a span-hash mismatch: 688c27cb8 "
                 "changed the inline SAFETY comment inside fourteen cmp spans (and "
                 "added the fn-level `# Safety` above them, outside the hash), "
                 "97a1240e7 wrapped the rand initialiser call in an explicit unsafe "
                 "block, and the ssl span took the same wrapper change.",
        "premise_correction": "the task brief attributed the cmp span drift to "
                              "97a1240e7; git log -- src/cmp/cmp_ctx.rs over "
                              "bb7d5206..HEAD shows 688c27cb8 as the only commit "
                              "touching that file, and -S confirms it introduced "
                              "both the twelve `# Safety` doc lines and the twelve "
                              "rewritten inline SAFETY comments.",
    },
    "rows": rows,
    "controls": controls,
    "receipt_diffs": {
        "note": "old/new coordinate and hash per row; the file sha256s are the "
                "re-bound receipts",
        "rows": [{"receipt": r["receipt"], "boundary": r["boundary"],
                  "old": r["old"], "new": r["new"],
                  "classification": r["classification"],
                  "disposition_update": r.get("disposition_update"),
                  "prose_coordinate_updates": r.get("prose_coordinate_updates")}
                 for r in rdiff["rows"]],
        "files": {
            "forensics/memory-safety/campaign/safe-c33/atlas-refresh/openssh-v1i-sites.json":
                {"before_sha256": "6c6449a7bb2ba2b8c32a15cf8d5f0eab618672fa160ae54beb092fdec980649a",
                 "after_sha256": hashlib.sha256((AR / "openssh-v1i-sites.json").read_bytes()).hexdigest()},
            "forensics/memory-safety/campaign/safe-c33/atlas-refresh/boundary-sweep-B69.json":
                {"before_sha256": "deac3e3bca329398300e17771ee93bdcbef762bcdf908720b5f94ce71e9580f9",
                 "after_sha256": hashlib.sha256((AR / "boundary-sweep-B69.json").read_bytes()).hexdigest()},
            "forensics/memory-safety/campaign/safe-c33/atlas-refresh/sslconf-exclusivity-2026-11-10-sites.json":
                {"before_sha256": "a6c2f00d6c66ae60a4968ae384db6f214b07edf51e21dac95fc6eae54a5c239c",
                 "after_sha256": hashlib.sha256((AR / "sslconf-exclusivity-2026-11-10-sites.json").read_bytes()).hexdigest()},
        },
    },
    "residuals": [
        {"id": "R1-no-compile", "state": "NOT_RUN",
         "statement": "no cargo invocation at this candidate (source-level venue). "
                      "fmt/clippy/test and the in-file controls "
                      "(`zero_state_sweep_ossl_cmp_ctx`, "
                      "`conf_cmd_min_max_protocol_bounds_are_range_checked`, "
                      "`ssl_set_version_bound_is_an_unsafe_fn`) are NOT_RUN and "
                      "belong to the next BATCH gate."},
        {"id": "R2-closures-not-regenerated", "state": "NOT_RUN",
         "statement": "the 274/16 closures were not re-run; moving the sixteen rows "
                      "to DISCHARGED (290/290) requires a fresh closure at this "
                      "candidate. The C2 control is a synthetic-plane reproduction, "
                      "not a closure."},
        {"id": "R3-evidence-text", "state": "OPEN",
         "statement": "OSSH-V1I-059's first `established_by` bullet says "
                      "`ctx_set1_dup!` passes the member; the actual use is the "
                      "`OPENSSL_sk_pop_free` freefunc plus the push0 setter. That "
                      "prose predates this review (b76 era) and is not load-bearing "
                      "for the verdict, which rests on the enumerated use sites; it "
                      "is recorded, not silently repaired."},
        {"id": "R4-rand-safety-section", "state": "JUSTIFIED",
         "statement": "RAND-CTX-001 has no `# Safety` section because it has no "
                      "caller-visible precondition (`_libctx` is unused); the fn is "
                      "`unsafe` because it returns raw ownership. `missing_safety_doc` "
                      "does not apply to a `pub(crate)` item."},
        {"id": "R5-retained-external", "state": "RETAINED",
         "statement": "the set0/push0 C-ABI ownership obligations on the pop_free "
                      "freefuncs are unchanged and remain the caller's, exactly as "
                      "the b76 accept recorded."},
        {"id": "R6-freeze-binding", "state": "BOUND",
         "statement": "these verdicts are bound to the exact source head and receipt "
                      "bytes named above; any further edit to the four source files "
                      "or the three receipts invalidates them."},
    ],
    "does_not_prove": [
        "It does not establish SAFE_COMPATIBLE for openssh or any consumer family; "
        "a site receipt is not a family graduation.",
        "It does not establish that the other 274 obligations still discharge at this "
        "candidate; only the sixteen rows were re-established.",
        "It does not establish the absence of UB at runtime: no sanitizer, Miri or "
        "binary-level check ran.",
        "It does not validate the prose evidence fields of the three receipts beyond "
        "the coordinates it names.",
        "It does not establish constant-time behaviour or any cryptographic property "
        "of these operations.",
        "It does not establish that the in-file negative controls fire at this "
        "candidate (no compile).",
    ],
}

OUT.write_text(json.dumps(review, indent=1, ensure_ascii=True) + "\n")
print("wrote", OUT.relative_to(ROOT))
print("sha256", hashlib.sha256(OUT.read_bytes()).hexdigest())
print("rows", len(rows), "controls", len(controls),
      "pass", all(c["pass"] for c in controls))
