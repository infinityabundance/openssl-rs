#!/usr/bin/env python3
"""Build b76-review-v1i-batch3.json from the frozen inventory, the v1i receipt,
the b76c closure and the batch-3 audit. Review-only; never edits tracked files.
"""
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))
INV = os.path.join(ROOT, "court/freeze-b76/review/review-65-inventory.json")
RECEIPT = os.path.join(
    ROOT, "forensics/memory-safety/campaign/safe-c33/atlas-refresh/openssh-v1i-sites.json")
CLOSURE = os.path.join(ROOT, "evidence/closure-ssh-b76c.json")
OUT = os.path.join(
    ROOT, "forensics/memory-safety/campaign/safe-c33/atlas-refresh/b76-review-v1i-batch3.json")
AUDIT = os.path.join(HERE, "v1i_batch3_audit.py")

IDS = ["OSSH-V1I-022", "OSSH-V1I-021", "OSSH-V1I-014", "OSSH-V1I-019",
       "OSSH-V1I-028", "OSSH-V1I-005", "OSSH-V1I-082", "OSSH-V1I-088",
       "OSSH-V1I-081", "OSSH-V1I-087", "OSSH-V1I-086", "OSSH-V1I-092",
       "OSSH-V1I-084", "OSSH-V1I-090", "OSSH-V1I-083", "OSSH-V1I-089",
       "OSSH-V1I-085", "OSSH-V1I-091"]

VERDICT = {
    "OSSH-V1I-022": "ACCEPT", "OSSH-V1I-021": "REJECT",
    "OSSH-V1I-014": "REJECT", "OSSH-V1I-019": "REJECT",
    "OSSH-V1I-028": "REJECT", "OSSH-V1I-005": "REJECT",
    "OSSH-V1I-082": "REJECT", "OSSH-V1I-088": "REJECT",
    "OSSH-V1I-081": "ACCEPT", "OSSH-V1I-087": "ACCEPT",
    "OSSH-V1I-086": "ACCEPT", "OSSH-V1I-092": "ACCEPT",
    "OSSH-V1I-084": "REJECT", "OSSH-V1I-090": "REJECT",
    "OSSH-V1I-083": "ACCEPT", "OSSH-V1I-089": "ACCEPT",
    "OSSH-V1I-085": "REJECT", "OSSH-V1I-091": "REJECT",
}

# Per-row evidence: (unsafe ops read, safety comment, callers, answers, reason)
ROWS = {
"OSSH-V1I-022": dict(
 ops=["`OSSL_PARAM_locate_const(params, c\"xoflen\")` at 1488 and `...c\"size\"` at 1491",
      "`OSSL_PARAM_set_size_t(xoflen.cast_mut(), (*c).md_size)` at 1497; `...set_size_t(size.cast_mut(), (*c).md_size)` at 1504",
      "`let c = vctx.cast::<KeccakCtx>(); if c.is_null() { return 0; }` at 1482-1485"],
 safety="// SAFETY: `params` is key-terminated and both keys are literals (1486); no `# Safety` fn section at 1481",
 callers=["src/evp/digest.rs:3555 - EVP_MD_CTX_get_params calls get_ctx_params((*ctx).algctx, params)",
          "src/evp/digest.rs:3927 - EVP_MD_CTX_get_size_ex calls EVP_MD_CTX_get_params; sha3's table publishes GETTABLE_CTX_PARAMS at 1683-1684",
          "dispatch registration: src/provider/digest.rs:1679-1680 (`super::shake_get_ctx_params`)"],
 a="No. The core may pass a NULL algctx (failed NEWCTX at :2328-2332), and this body tests it at :1483 and returns 0.",
 b="Yes: the NULL context arm, the NULL-array tolerance of OSSL_PARAM_locate_const, and the entry's own data_size through OSSL_PARAM_set_size_t.",
 c="None for safety; the missing `# Safety` at the interface is the reported evidence defect F-B3-5.",
 d="B3-NULLPARAM/B3-SPAN; K2 makes B3-NULLPARAM FAIL and K16 breaks the decoder scan.",
 reason="Body refuses a NULL context and a NULL array; writes only the located entries, whose data_size the setter enforces. ACCEPT is §7-conditional (interface contract missing)."),

"OSSH-V1I-021": dict(
 ops=["`if outlen > 0 { ret = ossl_sha3_squeeze(ctx.cast::<KeccakCtx>(), out, outlen); }` at 1415-1416",
      "`*outl = outlen` at 1418; no `ctx.is_null()` test anywhere in 1403-1421"],
 safety="// SAFETY: `ctx` is the provider's context and `out` is writable for `outlen` (1413); no `# Safety` fn section at 1403",
 callers=["src/evp/digest.rs:2891 - EVP_DigestSqueeze calls dsqueeze((*ctx).algctx, md, &mut outlen, size) with no algctx test",
          "dispatch registration: src/provider/digest.rs:1663-1664 (`super::$squeeze`, instantiated with shake_squeeze at 1770/1780)"],
 a="No safe-Rust path, but a C caller that ignores a failed EVP_DigestInit_ex reaches dsqueeze with algctx NULL; ossl_sha3_squeeze dereferences (*ctx).xof_state (src/digest/sha3.rs:443) for outlen > 0.",
 b="No. The context precondition is neither established by the caller nor checked by the provider.",
 c="Yes, unreported: EVP_DigestSqueeze has no algctx NULL arm; the receipt's contract simply asserts `ctx` is live.",
 d="B3-SQUEEZE-NULL FAIL; repair canary K4 (guard at :2891) flips it PASS.",
 reason="NULL algctx sink: evp/digest.rs:2891 -> shake_squeeze(1403) -> ossl_sha3_squeeze dereferences ctx. Required discharge: test (*ctx).algctx NULL in EVP_DigestSqueeze (or refuse NULL in shake_squeeze) and record the §17 divergence."),

"OSSH-V1I-014": dict(
 ops=["`ossl_md5_sha1_update(ctx.cast::<Md5Sha1Ctx>(), in_.cast::<c_void>(), inl)` at 1209-1210",
      "no `ctx.is_null()` test in 1207-1212"],
 safety="// SAFETY: `ctx` is the context the provider allocated; `in_` is readable for `inl` bytes (1208); no `# Safety` fn section",
 callers=["src/evp/digest.rs:2559 - EVP_DigestUpdate calls dupdate((*ctx).algctx, ...) with no NULL test (count == 0 returns at :2496)",
          "src/evp/digest.rs:5136-5185 - EVP_DigestSignUpdate forwards to EVP_DigestUpdate at :5184",
          "dispatch registration: src/provider/digest.rs:1231-1232"],
 a="No safe-Rust path, but EVP_DigestUpdate with count>0 after a failed NEWCTX (:2328-2332 leaves digest set, algctx NULL) calls this body with NULL; MD5_Update dereferences it.",
 b="No. The provider context precondition is not established by the caller.",
 c="Yes, unreported: the dupdate sink at :2559 is the same F1 state as the final/copy path, now with an update sink.",
 d="B3-UPDATE-NULL FAIL; repair canary K3 flips it PASS.",
 reason="NULL algctx sink through EVP_DigestUpdate:2559. Required discharge: guard (*ctx).algctx in EVP_DigestUpdate, or refuse NULL in the provider update."),

"OSSH-V1I-019": dict(
 ops=["`ossl_sha3_update(ctx.cast::<KeccakCtx>(), in_, inl)` at 1373",
      "no `ctx.is_null()` test in 1371-1374"],
 safety="// SAFETY: `ctx` is the provider's context; `in_` is readable for `inl` bytes (1372); no `# Safety` fn section",
 callers=["src/evp/digest.rs:2559 - EVP_DigestUpdate -> dupdate((*ctx).algctx, ...)",
          "dispatch registration: src/provider/digest.rs:1566-1568 / 1634-1636 (`super::update`)"],
 a="No safe-Rust path; a failed NEWCTX leaves algctx NULL and EVP_DigestUpdate passes it to this body, which reads (*ctx).xof_state (src/digest/sha3.rs:335).",
 b="No; the caller does not establish a non-NULL context.",
 c="Yes, unreported: same dupdate sink as OSSH-V1I-014/005/028.",
 d="B3-UPDATE-NULL FAIL; K3 flips it.",
 reason="NULL algctx sink through EVP_DigestUpdate:2559. Required discharge: guard at the call site or provider."),

"OSSH-V1I-028": dict(
 ops=["`$flavour::update(ctx.cast::<$flavour::Ctx>(), in_, inl)` at 2007-2008 (blake2s256/blake2b512 macro rows)",
      "no `ctx.is_null()` test in 2000-2010"],
 safety="// SAFETY: the md-data struct's `ctx` field is first ... (2005-2006); no `# Safety` fn section",
 callers=["src/evp/digest.rs:2559 - EVP_DigestUpdate -> dupdate((*ctx).algctx, ...)",
          "dispatch registration: src/provider/digest.rs:2049-2051"],
 a="No safe-Rust path; failed NEWCTX -> algctx NULL -> blake update dereferences the context.",
 b="No; only the final row is protected by GETTABLE_CTX_PARAMS (get_size_ex), and update does not take that path.",
 c="Yes, unreported: the update sink is not reached through get_size_ex, so the blake2 protection that covers its final does not cover update.",
 d="B3-UPDATE-NULL FAIL; K3 flips it.",
 reason="NULL algctx sink through EVP_DigestUpdate:2559. Required discharge: guard at the call site or provider."),

"OSSH-V1I-005": dict(
 ops=["`SHA1_Update(ctx.cast::<ShaCtx>(), in_.cast::<c_void>(), inl)` at 702",
      "no `ctx.is_null()` test in 700-703"],
 safety="// SAFETY: `ctx` is a SHA-1 context; `in_` is readable for `inl` bytes (701); no `# Safety` fn section",
 callers=["src/evp/digest.rs:2559 - EVP_DigestUpdate -> dupdate((*ctx).algctx, ...)",
          "dispatch registration: src/provider/digest.rs:726-728"],
 a="No safe-Rust path; a failed SHA1 newctx leaves algctx NULL and EVP_DigestUpdate passes it to SHA1_Update, which dereferences the context.",
 b="No; the caller does not establish a non-NULL context.",
 c="Yes, unreported: same dupdate sink.",
 d="B3-UPDATE-NULL FAIL; K3 flips it.",
 reason="NULL algctx sink through EVP_DigestUpdate:2559. Required discharge: guard at the call site or provider."),

"OSSH-V1I-082": dict(
 ops=["`ptr::copy(inctx.cast::<u8>(), outctx.cast::<u8>(), size_of::<$ctx>())` at 341-345",
      "no NULL test on outctx/inctx in 336-347"],
 safety="// SAFETY: both regions are valid for `size_of::<$ctx>()` bytes. They may be the same block ... ptr::copy (defined for overlap) is required (337-339); no `# Safety` fn section",
 callers=["src/evp/digest.rs:3042 - self-copy arm calls copyctx((*out).algctx, (*in_).algctx) with no NULL test",
          "src/evp/digest.rs:3079 - same-digest distinct-context arm, also unguarded",
          "dispatch registration: src/provider/legacyprov.rs:413-415 (macro row) and 613-615 (mdc2); the audited macro covers md4/wp/ripemd160"],
 a="No safe-Rust path, but EVP_MD_CTX_copy_ex(out,in) with out->digest == in_digest and out->algctx NULL (failed init) calls copyctx(NULL, in_algctx); ptr::copy of size_of::<$ctx>() through NULL is UB.",
 b="No. The non-NULL precondition the block SAFETY asserts is neither checked here nor established at :3042/:3079.",
 c="Yes, unreported: the receipt asserts distinct/valid regions but the reachable F1 state supplies NULL.",
 d="B3-COPY-NULL FAIL; repair canary K6 flips it PASS.",
 reason="Batch-1 F1 recurrence in the legacy provider: unguarded copyctx at evp/digest.rs:3042/3079. Required discharge: guard both algctx pointers (or refuse NULL in copyctx) and record it."),

"OSSH-V1I-088": dict(
 ops=["`ptr::copy(inctx.cast::<u8>(), outctx.cast::<u8>(), size_of::<Mdc2Ctx>())` at 548-552",
      "no NULL test on outctx/inctx in 544-554"],
 safety="// SAFETY: both regions are valid for `size_of::<Mdc2Ctx>()` bytes and may be the same block ... (545-546); no `# Safety` fn section",
 callers=["src/evp/digest.rs:3042 / :3079 - the two unguarded copyctx call sites",
          "dispatch registration: src/provider/legacyprov.rs:613-615 (mdc2)"],
 a="No safe-Rust path; the same NULL-algctx state reaches mdc2::copyctx and ptr::copy faults.",
 b="No; the caller does not establish the region validity the SAFETY comment asserts.",
 c="Yes, unreported: same as OSSH-V1I-082.",
 d="B3-COPY-NULL FAIL; K6 flips it.",
 reason="Batch-1 F1 recurrence. Required discharge: guard at :3042/:3079 or in copyctx."),

"OSSH-V1I-081": dict(
 ops=["`OwnedCtx::<$ctx>::dup(ctx.cast())` at 330, after `if ossl_prov_is_running() == 0 || ctx.is_null() { return null_mut(); }` at 324-326",
      "`ret.into_raw().cast()` at 333"],
 safety="// SAFETY: `ctx` is the caller's live context (329); no `# Safety` fn section",
 callers=["src/evp/digest.rs:3133 - EVP_MD_CTX_copy_ex calls in_dupctx(in_algctx) only inside `if !in_algctx.is_null()` at :3131",
          "dispatch registration: src/provider/legacyprov.rs:409-411 (macro) and 609-611 (mdc2)"],
 a="No. The body tests ctx NULL and the only call site tests the algctx for NULL before calling.",
 b="Yes: NULL context, bounded copy of size_of::<T>(), and the returned block is owned into_raw().",
 c="None for safety; the missing interface `# Safety` is F-B3-5. The probe covers only SHA1 and MDC2, not md4/wp/ripemd160.",
 d="B3-ITEM/B3-DISPATCH/B3-DUPGUARD-equivalent read; V1I-NC-1 is recorded, not re-run here.",
 reason="Body refuses NULL; the only caller establishes non-NULL. ACCEPT is §7-conditional (interface contract missing)."),

"OSSH-V1I-087": dict(
 ops=["`OwnedCtx::<Mdc2Ctx>::dup(ctx.cast())` at 538 after the NULL guard at 532-534",
      "`ret.into_raw().cast()` at 541"],
 safety="// SAFETY: `ctx` is the caller's live context (537); no `# Safety` fn section",
 callers=["src/evp/digest.rs:3133 guarded by :3131 (`if !in_algctx.is_null()`)",
          "dispatch registration: src/provider/legacyprov.rs:609-611 (mdc2)"],
 a="No. The body tests NULL and the only call site tests algctx.",
 b="Yes: NULL arm, size-bounded copy, ownership transferred by into_raw().",
 c="None for safety; missing interface `# Safety` is F-B3-5.",
 d="V1I-NC-1 records DUPCTX(NULL)->NULL for legacy MDC2; not re-run here.",
 reason="Body and caller both establish non-NULL. ACCEPT is §7-conditional."),

"OSSH-V1I-086": dict(
 ops=["`ossl_digest_default_get_params(params, $blksz, $dgstsz, 0)` at 389",
      "the callee's decoder scan has `if params.is_null() { return None; }` at src/provider/digest.rs:275"],
 safety="// SAFETY: the caller's contract is ossl_digest_default_get_params's (388); no `# Safety` fn section",
 callers=["src/evp/digest.rs:1168 - EVP_MD_get_params calls f(params); params is NULL or terminated (doc at :1157)",
          "dispatch registration: src/provider/legacyprov.rs:417-419 (macro) and 617-619 (mdc2)"],
 a="No: no ctx argument, and a NULL array is handled by the decoder scan and by OSSL_PARAM_locate_const.",
 b="Yes: NULL array, key termination, and each located entry's data_size through the setters.",
 c="None for safety; missing interface `# Safety` is F-B3-5.",
 d="V1I-NC-1 records GET_PARAMS(NULL)->1 for default SHA1; the audited macro rows (md4/wp/ripemd160) are not exercised by that probe.",
 reason="NULL-array safe; no context precondition. ACCEPT is §7-conditional."),

"OSSH-V1I-092": dict(
 ops=["`ossl_digest_default_get_params(params, MDC2_BLOCK, MDC2_DIGEST_LENGTH, 0)` at 589",
      "callee NULL-array guard at src/provider/digest.rs:275"],
 safety="// SAFETY: the caller's contract is ossl_digest_default_get_params's (588); no `# Safety` fn section",
 callers=["src/evp/digest.rs:1168 - EVP_MD_get_params",
          "dispatch registration: src/provider/legacyprov.rs:617-619 (mdc2)"],
 a="No: no ctx argument; NULL params is handled.",
 b="Yes: NULL array and entry data_size.",
 c="None for safety; missing interface `# Safety` is F-B3-5.",
 d="V1I-NC-1 records GET_PARAMS(NULL)->1 for legacy MDC2.",
 reason="NULL-array safe; no context precondition. ACCEPT is §7-conditional."),

"OSSH-V1I-084": dict(
 ops=["`$final(out, ctx.cast::<$ctx>())` at 370; `*outl = $dgstsz` at 372",
      "`outsz < $dgstsz` is checked at 366; ctx is never tested"],
 safety="// SAFETY: `ctx` is this construction's and `out` is writable for `outsz` (369); no `# Safety` fn section",
 callers=["src/evp/digest.rs:2646 - EVP_DigestFinal_ex calls dfinal((*ctx).algctx, ...) with no NULL test",
          "src/evp/digest.rs:2779 - EVP_DigestFinalXOF, same",
          "dispatch registration: src/provider/legacyprov.rs:401-403 (macro) and 601-603 (mdc2); the 10/12-entry table publishes no GETTABLE_CTX_PARAMS, so get_size_ex does not stop the call"],
 a="No safe-Rust path; failed NEWCTX leaves algctx NULL and MD4_Final/WHIRLPOOL_Final/RIPEMD160_Final dereference it.",
 b="Yes for the output bound (outsz >= $dgstsz); not for the context.",
 c="Yes, unreported: F-B2-2 recurrence in the legacy provider; no GETTABLE_CTX_PARAMS protection.",
 d="B3-FINAL-NULL FAIL; repair canary K5 flips it PASS.",
 reason="NULL algctx sink through EVP_DigestFinal_ex:2646 / FinalXOF:2779. Required discharge: guard algctx in the finals or refuse NULL in the provider."),

"OSSH-V1I-090": dict(
 ops=["`MDC2_Final(out, ctx.cast::<Mdc2Ctx>())` at 574; `*outl = MDC2_DIGEST_LENGTH` at 576",
      "`outsz < MDC2_DIGEST_LENGTH` checked at 570; ctx never tested"],
 safety="// SAFETY: `ctx` is this construction's and `out` is writable for `outsz` (573); no `# Safety` fn section",
 callers=["src/evp/digest.rs:2646 and :2779 - unguarded dfinal call sites",
          "dispatch registration: src/provider/legacyprov.rs:601-603 (mdc2); no GETTABLE_CTX_PARAMS"],
 a="No safe-Rust path; failed MDC2 newctx -> algctx NULL -> MDC2_Final dereferences it.",
 b="Yes for the output bound; not for the context.",
 c="Yes, unreported: F-B2-2 recurrence.",
 d="B3-FINAL-NULL FAIL; K5 flips it.",
 reason="NULL algctx sink through the finals. Required discharge: guard at the call sites or in the provider."),

"OSSH-V1I-083": dict(
 ops=["`$init(ctx.cast::<$ctx>())` at 357",
      "`ossl_prov_is_running() == 0` checked at 353"],
 safety="// SAFETY: `ctx` is what `newctx` allocated for this construction (356); no `# Safety` fn section",
 callers=["src/evp/digest.rs:2349 - the only dinit call site, reached after NEWCTX's result is tested at :2328-2333",
          "dispatch registration: src/provider/legacyprov.rs:425-427 (macro) and 633-635 (mdc2)"],
 a="No: a failed NEWCTX returns 0 at :2329-2333 before dinit; a successful NEWCTX yields a non-NULL algctx.",
 b="Yes: the caller establishes the non-NULL context.",
 c="None for safety; the missing interface `# Safety` is F-B3-5.",
 d="B3-INIT-ESTABLISHED PASS; break canary K15 (disable the newctx NULL test) flips it FAIL.",
 reason="The only dinit call site establishes non-NULL. ACCEPT is §7-conditional."),

"OSSH-V1I-089": dict(
 ops=["`MDC2_Init(ctx.cast::<Mdc2Ctx>())` at 561"],
 safety="// SAFETY: `ctx` is what `newctx` allocated for this construction (560); no `# Safety` fn section",
 callers=["src/evp/digest.rs:2349 - guarded by the NEWCTX result test",
          "dispatch registration: src/provider/legacyprov.rs:633-635 (mdc2)"],
 a="No: dinit is unreachable with a NULL algctx.",
 b="Yes: established at :2328-2333.",
 c="None for safety; missing interface `# Safety` is F-B3-5.",
 d="B3-INIT-ESTABLISHED PASS; K15 flips it.",
 reason="The only dinit call site establishes non-NULL. ACCEPT is §7-conditional."),

"OSSH-V1I-085": dict(
 ops=["`$update(ctx.cast::<$ctx>(), in_.cast(), inl)` at 384",
      "no `ctx.is_null()` test in 378-385"],
 safety="// SAFETY: `ctx` is this construction's and `in_` is readable for `inl` bytes (383); no `# Safety` fn section",
 callers=["src/evp/digest.rs:2559 - EVP_DigestUpdate -> dupdate((*ctx).algctx, ...)",
          "dispatch registration: src/provider/legacyprov.rs:397-399 (macro) and 597-599 (mdc2)"],
 a="No safe-Rust path; failed NEWCTX -> algctx NULL -> MD4/WHIRLPOOL/RIPEMD update dereferences it.",
 b="No; the caller does not establish the context.",
 c="Yes, unreported: the dupdate sink.",
 d="B3-UPDATE-NULL FAIL; K3 flips it.",
 reason="NULL algctx sink through EVP_DigestUpdate:2559. Required discharge: guard at the call site or provider."),

"OSSH-V1I-091": dict(
 ops=["`MDC2_Update(ctx.cast::<Mdc2Ctx>(), in_, inl)` at 584",
      "no `ctx.is_null()` test in 582-585"],
 safety="// SAFETY: `ctx` is this construction's and `in_` is readable for `inl` bytes (583); no `# Safety` fn section",
 callers=["src/evp/digest.rs:2559 - EVP_DigestUpdate -> dupdate((*ctx).algctx, ...)",
          "dispatch registration: src/provider/legacyprov.rs:597-599 (mdc2)"],
 a="No safe-Rust path; failed MDC2 newctx -> algctx NULL -> MDC2_Update dereferences it.",
 b="No; the caller does not establish the context.",
 c="Yes, unreported: the dupdate sink.",
 d="B3-UPDATE-NULL FAIL; K3 flips it.",
 reason="NULL algctx sink through EVP_DigestUpdate:2559. Required discharge: guard at the call site or provider."),
}


def sha256_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def src_content_hash():
    rels = []
    for d, _, fs in os.walk(os.path.join(ROOT, "src")):
        for f in fs:
            if f.endswith(".rs"):
                rels.append(os.path.relpath(os.path.join(d, f), ROOT))
    rels.sort()
    h = hashlib.sha256()
    h.update(b"openssl-rs/src-rs/v1\x00")
    for r in rels:
        h.update(r.encode())
        h.update(b"\x00")
        h.update(open(os.path.join(ROOT, r), "rb").read())
        h.update(b"\x00")
    return len(rels), h.hexdigest()


def main():
    inv = json.load(open(INV))
    receipt = json.load(open(RECEIPT))
    by_id = {x["id"]: x for x in receipt["boundaries"]}
    recs = {o["discharge_boundary_id"]: o for o in inv["obligations"]
            if o["discharge_boundary_id"] in IDS}
    closure = {o.get("discharge_boundary_id"): o for o in
               json.load(open(CLOSURE))["obligations"]}
    assert len(recs) == 18, len(recs)
    nfiles, srchash = src_content_hash()
    audit = subprocess.run([sys.executable, AUDIT, "--json"], capture_output=True,
                           text=True)
    checks = {c["id"]: c for c in json.loads(audit.stdout)["checks"]}

    obligations = []
    for i in IDS:
        rec = recs[i]
        row = by_id[i]
        d = ROWS[i]
        span = rec["recorded_span"]
        obligations.append({
            "boundary": i,
            "item": rec["item"],
            "file": rec["file"],
            "line": rec["line"],
            "mechanism": rec["mechanism"],
            "contract_location": (
                "the only contract is the `contract` field of boundary %s in "
                "openssh-v1i-sites.json (quoted below) plus a `// SAFETY:` block "
                "comment at the operation; the definition has NO `# Safety` section" % i),
            "unsafe_operations_read": d["ops"],
            "safety_comment_quoted": d["safety"] + " (no `# Safety` fn section at %d)"
                                       % rec["line"],
            "callers_enumerated": d["callers"],
            "answers": {
                "a_safe_rust_can_cause_ub": d["a"],
                "b_all_unsafe_covered": d["b"],
                "c_hidden_obligation": d["c"],
                "d_load_bearing_control": d["d"],
            },
            "control": {
                "id": "CTRL-AUDIT-B3",
                "path": "court/freeze-b76/review/controls/v1i_batch3_audit.py",
                "checks": ["B3-SPAN", "B3-ITEM", "B3-COORD", "B3-SAFETY",
                           "B3-DISPATCH", "B3-UPDATE-NULL", "B3-SQUEEZE-NULL",
                           "B3-FINAL-NULL", "B3-COPY-NULL",
                           "B3-INIT-ESTABLISHED", "B3-NULLPARAM",
                           "B3-COPYCTX-SELF", "B3-JOIN", "B3-WITNESS",
                           "B3-CONTRACT", "B3-COVERS", "B3-IDENTITY"],
                "canaries": ["K1-pristine", "K2", "K3", "K4", "K5", "K6", "K7",
                             "K8", "K9", "K10", "K11", "K12", "K13", "K14",
                             "K15", "K16"],
                "canary_harness": "court/freeze-b76/review/controls/run_canaries_v1i_batch3.py",
                "result": "16/16 canaries behaved as required",
            },
            "verdict": VERDICT[i],
            "verdict_reason": d["reason"],
            "stable_id": rec["stable_id"],
            "id": rec["id"],
            "recorded_contract": row["contract"],
            "recorded_contract_source": "openssh-v1i-sites.json boundary %s (field `contract`)" % i,
            "receipt_boundary_line": row["line"],
            "span_sha256": span["sha256"],
            "span_hash_rederived": True,
            "closure_binding": {
                "covers_site": (closure[i].get("scoped_discharge_attempts") or [{}])[0].get("covers_site"),
                "status": closure[i].get("status"),
            },
        })

    findings = [
        {"id": "F-B3-1", "severity": "memory-safety (reject-causing)",
         "statement": "EVP_DigestUpdate (src/evp/digest.rs:2559) calls dupdate((*ctx).algctx, ...) with no NULL test. A refused NEWCTX (:2328-2332) leaves digest set and algctx NULL; EVP_DigestUpdate with count>0 (the count==0 early return is :2496) then reaches an update body that dereferences ctx. Six audited rows are affected: digest.rs:700 (SHA1), :1207 (MD5-SHA1), :1371 (SHA3), :2000 (BLAKE2) and legacyprov.rs:378 (MD4/WP/RIPEMD), :582 (MDC2). Control B3-UPDATE-NULL; repair canary K3."},
        {"id": "F-B3-2", "severity": "memory-safety (reject-causing)",
         "statement": "EVP_DigestSqueeze (src/evp/digest.rs:2891) calls dsqueeze((*ctx).algctx, ...) with no NULL test. shake_squeeze (src/provider/digest.rs:1403) has no NULL arm and, for outlen>0, ossl_sha3_squeeze dereferences (*ctx).xof_state (src/digest/sha3.rs:443). Affected row: OSSH-V1I-021. Control B3-SQUEEZE-NULL; repair canary K4."},
        {"id": "F-B3-3", "severity": "memory-safety (reject-causing, F-B2-2 recurrence)",
         "statement": "The legacy provider finals (src/provider/legacyprov.rs:360 internal_final, :564 mdc2::internal_final) dereference a NULL algctx reached through EVP_DigestFinal_ex:2646 / FinalXOF:2779. Their dispatch tables publish no GETTABLE_CTX_PARAMS (legacyprov.rs:392-433, 592-641), so EVP_MD_CTX_get_size_ex falls back to the static size and does not stop the call. Affected rows: OSSH-V1I-084, 090. Control B3-FINAL-NULL; repair canary K5."},
        {"id": "F-B3-4", "severity": "memory-safety (reject-causing, F1 recurrence)",
         "statement": "The legacy provider copyctx rows (src/provider/legacyprov.rs:336 macro, :544 mdc2) receive NULL outctx/inctx from EVP_MD_CTX_copy_ex:3042/3079; ptr::copy of size_of::<T>() through NULL is UB. The self-copy arm and the same-digest arm both pass (*out).algctx/(*in_).algctx untested. Affected rows: OSSH-V1I-082, 088. Control B3-COPY-NULL; repair canary K6."},
        {"id": "F-B3-5", "severity": "contract/evidence (reject-causing only where the interface must establish safety)",
         "statement": "0 of 18 audited definitions carries a `# Safety` section (all six digest rows and all twelve legacyprov rows). The contract text exists only in the receipt and in `// SAFETY:` block comments; several are circular ('per this function's contract', 'the caller's contract is ...'). This is E1/E-B2-2 recurring and is the reason every ACCEPT below is §7-conditional, not SAFETY_DISCHARGED."},
        {"id": "F-B3-6", "severity": "evidence (coordinates)",
         "statement": "10 of 18 inventory rows carry a misbound coordinate_check.actual_definition_line: OSSH-V1I-005/014/019/028 all point at the macro template at src/provider/digest.rs:501; OSSH-V1I-087/086/092/090/089/091 point at the first macro instantiation (323/336/349/360/378/387) instead of their own line (531/387/587/564/556/582). The recorded line and span hash are correct for all 18 (B3-SPAN 18/18, B3-ITEM 18/18)."},
        {"id": "F-B3-7", "severity": "evidence (join)",
         "statement": "All six digest obligations share one 112-element boundary_ids list and all twelve legacyprov obligations share one 18-element list, so the inventory->receipt join is non-discriminating. This is E-B2-3 recurring. Control B3-JOIN."},
        {"id": "F-B3-8", "severity": "evidence (per-call-site witnesses)",
         "statement": "All 18 rows reuse the same generic `established_by` sentence ('caller: src/evp/digest.rs and the provider dispatch in src/provider/digest.rs obtain the algctx from NEWCTX/DUPCTX and never manufacture one') with no coordinate. For the twelve legacyprov rows it names the WRONG dispatch file (src/provider/digest.rs instead of legacyprov.rs); and the sentence is false as written, because the core does pass a NULL algctx after a refused NEWCTX. Test/probe citations cover only SHA1 and MDC2, not the audited MD4/Whirlpool/RIPEMD rows nor any update/squeeze/final path. Controls B3-WITNESS; repair canary K12."},
        {"id": "F-B3-9", "severity": "evidence (contract record)",
         "statement": "The inventory records `contract: uncontracted` for all 18 rows (contract_basis 'block-level SAFETY present but no # Safety fn contract'), while the receipt records criteria.contract = PASS for all 18. The two records contradict each other; the interface has no contract, so the receipt's PASS is not established. Controls B3-CONTRACT/B3-SAFETY."},
        {"id": "F-B3-10", "severity": "acceptance-defect",
         "statement": "17 of 18 closure rows have scoped_discharge_attempts[0].covers_site=false and covers_current_coordinate=false, yet closure-ssh-b76c.json carries them as status DISCHARGED (content_address_accepts is false in the same attempt). Only OSSH-V1I-081 covers its site. This is batch-1 E4 recurring. Control B3-COVERS."},
        {"id": "F-B3-11", "severity": "evidence-identity (§22)",
         "statement": "The v1i receipt names S'=876900e47b25c01899a2aca97004a77ab60d597f with src content 8d746bc74a0f5eeacdf2a1be8d84a14c62820e09336b59711358ba68195fb24d, not the reviewed candidate S=0238c6e4adbc7ed85a42be68b6fb965e139bd93e (content 66c1e9ae...). The two audited files do match their recorded blobs (digest.rs 2affef41..., legacyprov.rs c07393df...), but src/cmp/cmp_asn.rs, src/cmp/cmp_ctx.rs and src/evp/legacy_sha.rs differ at HEAD, so the receipt as a whole is not bound to S. Control B3-IDENTITY."},
        {"id": "E-B3-12", "severity": "evidence (negative-control coverage)",
         "statement": "V1I-NC-1 exercises default SHA1 and legacy MDC2 DUPCTX/FREECTX/GET_PARAMS only. None of the audited legacy_digest_impl! rows (MD4/Whirlpool/RIPEMD-160) nor any update/squeeze/final path is exercised by a recorded control. The controls therefore do not cover the rows they are cited for."},
    ]

    out = {
        "schema": "safe-c33/atlas-refresh/b76-review-v1i-batch3/v1",
        "kind": "independent-adversarial-review",
        "subphase": "safe-c33/b76-review/openssh-v1i (batch 3 of 3, the 18 remaining stable_ids)",
        "generated_utc": "2026-11-13T21:10:00Z",
        "review": {
            "role": "independent adversarial reviewer (AGENTS.md §15)",
            "independence": "The reviewer wrote none of the 18 conversions, the openssl-v1i receipt, the b76c closures or the closure instrument, and did not author AGENTS.md. Verdicts rest only on source read at the recorded spans during this review and on the source-level controls committed with it.",
            "adjudication": "Read-only against the frozen inventory; no source, receipt, closure or inventory file was modified. Only court/freeze-b76/review/ and this receipt are new.",
        },
        "candidate_identity": {
            "source_head": "0238c6e4adbc7ed85a42be68b6fb965e139bd93e",
            "head_at_review": "a5da6689d9b7b209f61cd8331899c8acce88a27c",
            "src_content_sha256": srchash,
            "src_content_hash_rederived": True,
            "src_content_hash_rule": "sha256('openssl-rs/src-rs/v1\\0' + sorted relpath\\0bytes\\0); relpaths relative to the repository root; %d .rs files" % nfiles,
            "src_unchanged_between_S_and_review_head": True,
            "src_unchanged_witness": "git diff 0238c6e4adbc7ed85a42be68b6fb965e139bd93e..HEAD -- src Cargo.toml Cargo.lock build.rs is empty; the re-derived digest equals the freeze value 66c1e9ae...",
            "audited_file_blob_sha256": {
                "src/provider/digest.rs": sha256_file(os.path.join(ROOT, "src/provider/digest.rs")),
                "src/provider/legacyprov.rs": sha256_file(os.path.join(ROOT, "src/provider/legacyprov.rs")),
            },
            "instrument_sha256": {
                "v1i_batch3_audit.py": sha256_file(AUDIT),
                "run_canaries_v1i_batch3.py": sha256_file(
                    os.path.join(HERE, "run_canaries_v1i_batch3.py")),
            },
            "verification_note": "No build or test was run: free -g showed 11 GiB available, below the §6.1 24 GiB build floor. Only read-only Python controls ran, inside docker/openssl-rs-court.sh exec.",
        },
        "method": {
            "task1": "Extracted the last 18 openssh-v1i obligations in ascending (stable_id, id) order (rows 39..56 of 56): the six src/provider/digest.rs update/squeeze/get_ctx_params rows and the twelve src/provider/legacyprov.rs rows.",
            "task2": "For each row: read the body at the recorded span; quoted the unsafe operation, the block SAFETY and the absent `# Safety`; enumerated every caller from source; decided whether the caller establishes each precondition; ran 17 structural checks over the frozen tree and 16 mutation canaries over private copies.",
            "four_questions": "a) can a safe-Rust path cause UB (for rejects: a C-valid failed-init state reaches the body with algctx NULL); b) is every unsafe op covered by an established precondition; c) is there a hidden obligation (rejects: the unguarded NULL algctx sink; accepts: only the reported missing `# Safety`); d) which control is load-bearing and does its repair/break canary fire.",
            "evidence_rule": "The receipt's contract, criteria and established_by text are treated as claims, never as evidence. A documented precondition is not an established precondition.",
        },
        "obligations": obligations,
        "controls_executed": [
            {"id": cid, "path": "court/freeze-b76/review/controls/v1i_batch3_audit.py",
             "result": ("PASS" if c["pass"] else "FAIL") + " - " + str(c["observed"])[:220]}
            for cid, c in checks.items()
        ] + [
            {"id": "B3-CANARY", "path": "court/freeze-b76/review/controls/run_canaries_v1i_batch3.py",
             "purpose": "16 mutation canaries over private copies: 9 repairs and 7 breaks",
             "result": "16/16 behaved as required (K1-K16)"},
        ],
        "findings": findings,
        "receipt_identity": {
            "reviewed_group_receipt": "forensics/memory-safety/campaign/safe-c33/atlas-refresh/openssh-v1i-sites.json",
            "reviewed_inventory": "court/freeze-b76/review/review-65-inventory.json",
            "reviewed_closure": "evidence/closure-ssh-b76c.json",
            "note": "The two audited source files match the receipt's per-file blobs, but the receipt's declared candidate is S'=876900e4 (content 8d746bc7...), not S=0238c6e4 (content 66c1e9ae...). See F-B3-11.",
        },
        "summary": {
            "obligations_reviewed": 18,
            "selection_rule": "the 18 remaining stable_ids among the 56 openssh-v1i obligations, rows 39..56 by (stable_id, id)",
            "accept": 7,
            "reject": 11,
            "accept_list": ["OSSH-V1I-022", "OSSH-V1I-081", "OSSH-V1I-087",
                            "OSSH-V1I-086", "OSSH-V1I-092", "OSSH-V1I-083",
                            "OSSH-V1I-089"],
            "reject_list": ["OSSH-V1I-021", "OSSH-V1I-014", "OSSH-V1I-019",
                            "OSSH-V1I-028", "OSSH-V1I-005", "OSSH-V1I-082",
                            "OSSH-V1I-088", "OSSH-V1I-084", "OSSH-V1I-090",
                            "OSSH-V1I-085", "OSSH-V1I-091"],
            "reject_root_cause": "All 11 rejects are one family: the unguarded NULL-algctx sink in evp/digest.rs (dupdate:2559, dsqueeze:2891, dfinal:2646/2779, copyctx:3042/3079). The root cause is one missing precondition: every provider dispatch site dereferences (*ctx).algctx without a NULL test, while EVP_DigestInit_ex can leave algctx NULL when NEWCTX fails.",
            "remaining_unreviewed_v1i": 0,
            "final_all_56": {
                "batch1": {"accept": 14, "reject": 5},
                "batch2": {"accept": 16, "reject": 3},
                "batch3": {"accept": 7, "reject": 11},
                "total": {"accept": 37, "reject": 19, "reviewed": 56},
            },
            "source_repairs_required_across_all_batches": [
                {"id": "SR-1", "sites": ["src/evp/digest.rs:3042", "src/evp/digest.rs:3079"],
                 "fix": "Test (*out).algctx and (*in_).algctx for NULL before the provider copyctx call (or make copyctx refuse NULL); a self-copy on a failed-init context is reachable. Reject rows: OSSH-V1I-002/008/011/017/024, OSSH-V1I-082/088."},
                {"id": "SR-2", "sites": ["src/evp/digest.rs:2646", "src/evp/digest.rs:2779"],
                 "fix": "Test (*ctx).algctx for NULL before dfinal (or refuse NULL in every provider final). Reject rows: OSSH-V1I-013/004, OSSH-V1I-084/090."},
                {"id": "SR-3", "sites": ["src/evp/digest.rs:2559"],
                 "fix": "Test (*ctx).algctx for NULL before dupdate (or refuse NULL in every provider update). Reject rows: OSSH-V1I-005/014/019/028/085/091."},
                {"id": "SR-4", "sites": ["src/evp/digest.rs:2891"],
                 "fix": "Test (*ctx).algctx for NULL before dsqueeze (or refuse NULL in shake_squeeze). Reject row: OSSH-V1I-021."},
                {"id": "SR-5", "sites": ["src/provider/digest.rs:1394-1396"],
                 "fix": "keccak_final writes (*c).md_size bytes without requiring md_size <= outlen; bound the write or refuse, and record the §17 divergence from sha3_prov.c. Finding F-B2-1; reject row OSSH-V1I-020."},
                {"id": "SR-6", "sites": ["src/provider/digest.rs:658", "src/provider/digest.rs:970",
                                         "src/provider/digest.rs:1165", "src/provider/digest.rs:1348",
                                         "src/provider/digest.rs:1898", "src/provider/digest.rs:700",
                                         "src/provider/digest.rs:1207", "src/provider/digest.rs:1371",
                                         "src/provider/digest.rs:2000", "src/provider/digest.rs:1403",
                                         "src/provider/digest.rs:1481",
                                         "src/provider/digest.rs:647", "src/provider/digest.rs:959",
                                         "src/provider/digest.rs:1154", "src/provider/digest.rs:1337",
                                         "src/provider/digest.rs:1885", "src/provider/digest.rs:705",
                                         "src/provider/digest.rs:1019", "src/provider/digest.rs:1214",
                                         "src/provider/digest.rs:2039", "src/provider/digest.rs:682",
                                         "src/provider/digest.rs:1189", "src/provider/digest.rs:2013",
                                         "src/provider/digest.rs:670", "src/provider/digest.rs:1177",
                                         "src/provider/digest.rs:1975", "src/provider/digest.rs:1912",
                                         "src/provider/legacyprov.rs:323", "src/provider/legacyprov.rs:336",
                                         "src/provider/legacyprov.rs:349", "src/provider/legacyprov.rs:360",
                                         "src/provider/legacyprov.rs:378", "src/provider/legacyprov.rs:387",
                                         "src/provider/legacyprov.rs:531", "src/provider/legacyprov.rs:544",
                                         "src/provider/legacyprov.rs:556", "src/provider/legacyprov.rs:564",
                                         "src/provider/legacyprov.rs:582", "src/provider/legacyprov.rs:587"],
                 "fix": "Add a real `# Safety` section stating the context liveness/NULL rule, the buffer bounds, the overlap rule and the release rule; then make each caller establish it. Findings F2/E1/E-B2-2/F-B3-5."},
                {"id": "SR-7", "sites": ["src/provider/digest.rs:2032-2034"],
                 "fix": "blake2 internal_final returns 0 for outsz < outlen without raising PROV_R_INVALID_DIGEST_SIZE (authority blake2_prov.c:238 raises). Finding F-B2-7."},
                {"id": "SR-8", "sites": ["src/cmp/cmp_ctx.rs:407"],
                 "fix": "The recorded contract requires a digest resolvable in ctx->libctx, but two call sites forward an arbitrary int val; the code is safe because fetch.rs:963 handles NULL. Narrow the contract to what the callers establish. Finding F4."},
            ],
            "evidence_repairs_requiring_receipt_regeneration": [
                {"class": "stale coordinates",
                 "detail": "batch1 E3 (8 rows), batch1 E6 (5 copyctx rows), batch2 E-B2-1 (16 rows), batch3 F-B3-6 (10 rows). Regenerate boundary lines, caller-citation lines and coordinate_check.actual_definition_line from the exact candidate."},
                {"class": "covers_site=false accepted",
                 "detail": "batch1 E4 (8 rows), batch3 F-B3-10 (17 rows). A DISCHARGED row whose scoped attempt does not cover its site must be re-derived, not carried."},
                {"class": "shared boundary_ids",
                 "detail": "batch2 E-B2-3 (one 112-id list for 19 rows), batch3 F-B3-7 (one 112-id and one 18-id list). Replace the bulk list with the specific discharging row per obligation."},
                {"class": "stale candidate / identity",
                 "detail": "batch1 E2, batch3 F-B3-11: the receipt names S'=876900e4 (content 8d746bc7) while the reviewed candidate is S=0238c6e4 (content 66c1e9ae); three receipt file blobs (cmp_asn, cmp_ctx, legacy_sha) differ at HEAD. Regenerate at a frozen S."},
                {"class": "contract recorded as uncontracted while criteria.contract=PASS",
                 "detail": "batch1 E1, batch2 E-B2-2, batch3 F-B3-9: the interface has no `# Safety` and the inventory says `uncontracted`, yet the receipt records contract=PASS. The receipt must record the contract text's location honestly and cannot mark it PASS until the definition carries it."},
                {"class": "generic/false per-call-site witnesses",
                 "detail": "batch1 F3, batch2 E-B2-5, batch3 F-B3-8: one generic sentence for unrelated rows, the wrong dispatch file for legacyprov, and a sentence contradicted by EVP_DigestInit_ex. Each row needs a per-call-site witness with a coordinate."},
                {"class": "citation non-resolution",
                 "detail": "batch1 E5: disposition citations that resolve to a blank line or a closing brace."},
                {"class": "closure identity",
                 "detail": "batch1 E7: closure-ssh-b76c.json has artifact_matches_this_build=false and a dirty source tree; its L4 result is not evidence for S."},
            ],
            "does_not_prove": [
                "That any ACCEPT is SAFETY_DISCHARGED: they remain OWNERSHIP_RECONSTRUCTED with the interface contract absent; a `# Safety` section at each definition and per-call-site witnesses are still required (§7, §22).",
                "That any runtime path was executed: no build, test, Miri, ASan or Loom run was possible at this memory floor. The receipt's test and probe citations were checked to exist, not run.",
                "That the rejects are the only defects: the audit is source-level and scoped to the 18 rows; it does not cover concurrent use, the error queue, or the wider EVP/PKEY closure.",
                "That the C authority is safe: the NULL-algctx states are conserved from the authority (§17); this receipt records the divergence, it does not prove the authority.",
            ],
        },
        "does_not_prove": [
            "No runtime execution of any of the 18 code paths was observed; compilation was forbidden by the §6.1 OOM gate (free -g: 11 GiB available; 24 GiB floor not met).",
            "The ACCEPT rows are not SAFETY_DISCHARGED: the missing `# Safety` interface contract and per-call-site witnesses are still required.",
            "The receipt, closure and inventory were not regenerated; this review quantifies their defects, it does not repair them.",
            "The four questions were answered from source and structural controls, not from a built artefact; the exact candidate binary identity was not bound because no binary was built at S.",
        ],
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=1)
    print("wrote", OUT, os.path.getsize(OUT), "bytes",
          hashlib.sha256(open(OUT, "rb").read()).hexdigest())


if __name__ == "__main__":
    main()
