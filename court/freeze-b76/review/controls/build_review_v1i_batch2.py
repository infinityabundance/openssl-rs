#!/usr/bin/env python3
"""Build b76-review-v1i-batch2.json from the frozen inventory, the group receipt,
and the per-row analysis recorded below.  Deterministic: every coordinate, hash
and control result is read from the artifacts, not retyped.
"""
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))
OUT = os.path.join(ROOT, "forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                         "b76-review-v1i-batch2.json")
INV = os.path.join(ROOT, "court/freeze-b76/review/review-65-inventory.json")
RECEIPT = os.path.join(ROOT, "forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                             "openssh-v1i-sites.json")

IDS = ["OSSH-V1I-010", "OSSH-V1I-016", "OSSH-V1I-023", "OSSH-V1I-001",
       "OSSH-V1I-007", "OSSH-V1I-026", "OSSH-V1I-009", "OSSH-V1I-015",
       "OSSH-V1I-030", "OSSH-V1I-006", "OSSH-V1I-018", "OSSH-V1I-013",
       "OSSH-V1I-029", "OSSH-V1I-004", "OSSH-V1I-012", "OSSH-V1I-027",
       "OSSH-V1I-003", "OSSH-V1I-020", "OSSH-V1I-025"]

# Per-row analysis.  Code facts quoted here were read at the recorded span in
# this review; the span hash and coordinates are injected from the artifacts.
ROWS = {
 "OSSH-V1I-001": dict(
   op="`OwnedCtx::<ShaCtx>::dup(ctx.cast())` at 652; the body gates on "
      "`ossl_prov_is_running() == 0 || ctx.is_null()` at 648 and returns NULL.",
   safety="// SAFETY: `ctx` is the caller's live context; the copy is owned here until it is handed out. (647 has NO `# Safety` fn section)",
   callers=["src/evp/digest.rs:3133 - non-self `EVP_MD_CTX_copy_ex`, reached only when `!in_algctx.is_null()` (:3131)",
            "src/evp/digest.rs:3301 - legacy re-acquire arm, reached only when `!in_algctx.is_null()` (:3297)",
            "dispatch registration `function: dupctx as *mut c_void` under OSSL_FUNC_DIGEST_DUPCTX (:740)"],
   a="No. The fn is private and only the EVP layer's unsafe extern fns plus the dispatch reach it; both in-crate call sites test the algctx for NULL first.",
   b="Yes. `OwnedCtx::dup` copies `size_of::<ShaCtx>()` bytes non-overlapping and Drop releases the copy exactly once; ShaCtx is u32/[u32;16] only, so the bitwise copy is a valid value and owns nothing.",
   c="None for this row. Retained on the shared owner: `impl<T> OwnedCtx<T>` has no `Copy`/POD bound, so the shallow-copy soundness depends on the module's 'no context owns a pointer' invariant (documented at :310-320, not type-enforced).",
   d="B2-DUPGUARD (definition guard at 648 and both call-site guards), canaries K2 and K3, both FIRED.",
   verdict="ACCEPT",
   why="Precondition (live, exclusively owned ShaCtx from NEWCTX/DUPCTX) is established by the core ABI and re-checked in-crate at both call sites; the copy is a whole-block bitwise copy of a POD type. Evidence defects only: no `# Safety` at the interface (E-B2-2), generic witness (E-B2-5), inventory coordinate collision (E-B2-1)."),
 "OSSH-V1I-007": dict(
   op="`OwnedCtx::<NullMdCtx>::dup(ctx.cast())` at 964 after `ctx.is_null()` at 960.",
   safety="// SAFETY: `ctx` is the caller's live context; the copy is owned here until it is handed out. (959 has NO `# Safety` fn section)",
   callers=["src/evp/digest.rs:3133 (guarded :3131)", "src/evp/digest.rs:3301 (guarded :3297)",
            "dispatch registration at :1033 (OSSL_FUNC_DIGEST_DUPCTX)"],
   a="No: private fn, NULL-tested, and both in-crate callers guard the algctx.",
   b="Yes. `NullMdCtx` is `{ nothing: u8 }`; a one-block copy owns nothing.",
   c="None.",
   d="B2-DUPGUARD + canaries K2/K3 (FIRED).",
   verdict="ACCEPT",
   why="Ownership and extent are fixed by the paired NEWCTX/DUPCTX row; the type owns no pointer. Evidence defects E-B2-2, E-B2-5, E-B2-1."),
 "OSSH-V1I-010": dict(
   op="`OwnedCtx::<Md5Sha1Ctx>::dup(ctx.cast())` at 1159 after `ctx.is_null()` at 1155.",
   safety="// SAFETY: `ctx` is the caller's live context; the copy is owned here until it is handed out. (1154 has NO `# Safety` fn section)",
   callers=["src/evp/digest.rs:3133 (guarded :3131)", "src/evp/digest.rs:3301 (guarded :3297)",
            "dispatch registration at :1260 (OSSL_FUNC_DIGEST_DUPCTX)"],
   a="No: private, NULL-tested, callers guarded.",
   b="Yes. `Md5Sha1Ctx` is `{ md5: Md5Ctx, sha1: ShaCtx }`, both arrays of integers; the static layout asserts (92+96) hold. The authority's `*ret = *in` is reproduced exactly.",
   c="None.",
   d="B2-DUPGUARD + K2/K3 (FIRED).",
   verdict="ACCEPT",
   why="Same contract as the other dupctx rows, established in code; POD context, whole-block copy. Evidence defects E-B2-2, E-B2-5, E-B2-1."),
 "OSSH-V1I-016": dict(
   op="`OwnedCtx::<KeccakCtx>::dup(ctx.cast())` at 1342 after `ctx.is_null()` at 1338.",
   safety="// SAFETY: `ctx` is the caller's live context; the copy is owned here until it is handed out. (1337 has NO `# Safety` fn section)",
   callers=["src/evp/digest.rs:3133 (guarded :3131)", "src/evp/digest.rs:3301 (guarded :3297)",
            "dispatch registration at :1597 and :1660 (`super::dupctx`, OSSL_FUNC_DIGEST_DUPCTX)"],
   a="No: private, NULL-tested, callers guarded.",
   b="Yes. `KeccakCtx` is `[u64;25]`, `[u8;200]`, three `usize`, `u8`, `c_int`; the `md_size == usize::MAX` XOF sentinel is copied verbatim, which preserves the semantics the final depends on.",
   c="None.",
   d="B2-DUPGUARD + K2/K3 (FIRED).",
   verdict="ACCEPT",
   why="Whole-block copy of a POD context; the sentinel state that `keccak_final` tests is carried by the copy, so duplication does not silently change the row's behaviour. Evidence defects E-B2-2, E-B2-5, E-B2-1."),
 "OSSH-V1I-023": dict(
   op="`OwnedCtx::<$flavour::MdData>::dup(ctx.cast())` at 1891 after `ctx.is_null()` at 1886; one macro body instantiated twice (`blake2b512`, `blake2s256`), so the recorded span covers two dispatch rows.",
   safety="// SAFETY: `ctx` is the caller's live context; the copy is owned here until it is handed out. (1885 has NO `# Safety` fn section)",
   callers=["src/evp/digest.rs:3133 (guarded :3131)", "src/evp/digest.rs:3301 (guarded :3297)",
            "dispatch registration at :2063 inside `blake_row!`, expanded for blake2b512 and blake2s256"],
   a="No: private, NULL-tested, callers guarded.",
   b="Yes. `MdData` = `{ ctx: Ctx, params: Param }`; both flavours are integer/byte arrays with no pointer, so the copy neither aliases nor double-owns.",
   c="None.",
   d="B2-DUPGUARD + K2/K3 (FIRED); K2 breaks exactly this row's guard and the check flips.",
   verdict="ACCEPT",
   why="Two instantiations, each a whole-block copy of a POD context, NULL-tested and guarded at both callers. Evidence defects E-B2-2, E-B2-5, E-B2-1 (the inventory's actual_definition_line 433 is the `digest_impl!` item, not this one)."),
 "OSSH-V1I-026": dict(
   op="`OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SIZE)` at 1957 and `OSSL_PARAM_set_uint(p.cast_mut(), size)` at 1964; `ctx.is_null()` at 1952.",
   safety="// SAFETY: `params` is NULL or key-terminated. / // SAFETY: `ctx` is the provider's context. (no `# Safety` fn section at 1948)",
   callers=["src/evp/digest.rs:3555 - `EVP_MD_CTX_get_params` passes `(*ctx).algctx`, refusing only when `digest` is NULL",
            "src/evp/digest.rs:3927 - `EVP_MD_CTX_get_size_ex` asks for `size`; this is also what stops the F1 NULL-algctx state here (a NULL ctx answers 0, so get_size_ex answers -1)",
            "dispatch registration at :2092 (OSSL_FUNC_DIGEST_GET_CTX_PARAMS)"],
   a="No. `OSSL_PARAM_locate`/`set_uint` validate the array and the entry's declared size, and NULL params is a no-op answering 1.",
   b="Yes. The write goes through `OSSL_PARAM_set_uint`, whose contract is the entry's own declared data_size and type; the read is `params.b[0]` of the caller's context.",
   c="None. The recorded contract says the function 'returns 1', but it returns 0 when the located entry refuses the write (:1967): a contract inaccuracy, not a safety gap (the refusal writes nothing).",
   d="B2-NULLPARAM (locate and param_is_empty both NULL-safe) + K11 FIRED; B2-FINALNULL records that this very refusal protects blake2's final.",
   verdict="ACCEPT",
   why="Both unsafe operations are bounded by the OSSL_PARAM descriptor the caller supplies; NULL params and NULL ctx are refused by code. Evidence defects: no `# Safety` (E-B2-2), generic witness although this callback does receive the algctx (E-B2-5), and one contract sentence overstates the return value (E-B2-6)."),
 "OSSH-V1I-009": dict(
   op="`ossl_digest_default_get_params(params, 0, 0, 0)` at 1022 (the null-digest row).",
   safety="// SAFETY: the caller's contract is `ossl_digest_default_get_params`'s. (no `# Safety` fn section at 1019)",
   callers=["src/evp/digest.rs:1168 - `EVP_MD_get_params` calls `f(params)`; there is no algctx parameter in this ABI slot",
            "dispatch registration at :1013 (OSSL_FUNC_DIGEST_GET_PARAMS)"],
   a="No. The callee walks the caller's array only through `OSSL_PARAM_locate_const` (NULL array -> NULL) and writes only located entries through setters that honour the entry's declared size.",
   b="Yes for the operation; the obligation is entirely the caller's array contract, which the receipt states.",
   c="None for memory safety. The receipt's witness sentence is inapplicable (see d).",
   d="B2-NULLPARAM + K11 FIRED; B2-WITNESS marks this row 'inapplicable': `get_params` takes no algctx, yet the witness says the caller 'obtain[s] the algctx from NEWCTX/DUPCTX'.",
   verdict="ACCEPT",
   why="The NULL array answers 1 and only located descriptors are written; the precondition is the caller's array, which is an OSSL_PARAM ABI contract. Evidence defects: no `# Safety` (E-B2-2), an inapplicable per-call-site witness (E-B2-5), coordinate collision (E-B2-1)."),
 "OSSH-V1I-015": dict(
   op="`ossl_digest_default_get_params(params, MD5_SHA1_CBLOCK, 36, 0)` at 1217.",
   safety="// SAFETY: the caller's contract is `ossl_digest_default_get_params`'s. (no `# Safety` fn section at 1214)",
   callers=["src/evp/digest.rs:1168 (`EVP_MD_get_params`, no algctx)",
            "dispatch registration at :1240 (OSSL_FUNC_DIGEST_GET_PARAMS)"],
   a="No. Same NULL-safe walk as OSSH-V1I-009.",
   b="Yes for the operation.",
   c="None for memory safety; the witness is inapplicable.",
   d="B2-NULLPARAM + K11 FIRED; B2-WITNESS inapplicable.",
   verdict="ACCEPT",
   why="Identical mechanism and identical establishment to OSSH-V1I-009. Evidence defects E-B2-1, E-B2-2, E-B2-5."),
 "OSSH-V1I-030": dict(
   op="`ossl_digest_default_get_params(params, $blksz, $dgstsz, 0)` at 2041 (macro body, both blake rows).",
   safety="// SAFETY: the caller's contract is `ossl_digest_default_get_params`'s. (no `# Safety` fn section at 2039)",
   callers=["src/evp/digest.rs:1168 (`EVP_MD_get_params`, no algctx)",
            "dispatch registration at :2074 (`get_params`, OSSL_FUNC_DIGEST_GET_PARAMS)"],
   a="No. Same NULL-safe walk.",
   b="Yes for the operation.",
   c="None for memory safety; the witness is inapplicable.",
   d="B2-NULLPARAM + K11 FIRED; B2-WITNESS inapplicable.",
   verdict="ACCEPT",
   why="Identical to the other get_params rows, including the two instantiations of the macro. Evidence defects E-B2-1, E-B2-2, E-B2-5."),
 "OSSH-V1I-006": dict(
   op="`ossl_digest_default_get_params(params, SHA_CBLOCK, 20, SHA2_FLAGS)` at 707.",
   safety="// SAFETY: the caller's contract is `ossl_digest_default_get_params`'s. (no `# Safety` fn section at 705)",
   callers=["src/evp/digest.rs:1168 (`EVP_MD_get_params`, no algctx)",
            "dispatch registration at :747 (OSSL_FUNC_DIGEST_GET_PARAMS)"],
   a="No. Same NULL-safe walk.",
   b="Yes for the operation.",
   c="None for memory safety; the witness is inapplicable.",
   d="B2-NULLPARAM + K11 FIRED; B2-WITNESS inapplicable.",
   verdict="ACCEPT",
   why="Same mechanism; the NULL-array probe claim in established_by is not needed for the verdict, which rests on the callee's own NULL tests read here. Evidence defects E-B2-1, E-B2-2, E-B2-5."),
 "OSSH-V1I-018": dict(
   op="`ossl_sha3_reset(ctx.cast::<KeccakCtx>())` at 1367 after the `ossl_prov_is_running()` gate.",
   safety="// `keccak_init` — `sha3_prov.c:63-70` ... // SAFETY: `ctx` is the provider's `KeccakCtx`. (no `# Safety` fn section at 1360)",
   callers=["src/evp/digest.rs:2349 - the single `dinit` call site, reached only after the algctx test at :2313 and the NEWCTX refusal return at :2329-2332",
            "dispatch registration at :1576 and :1644 (`super::init`, OSSL_FUNC_DIGEST_INIT)"],
   a="No. There is exactly one in-crate `dinit(` call site and it cannot pass NULL (the constructor's NULL is refused at :2329 before :2349).",
   b="Yes. `ossl_sha3_reset` writes only the context's state words; block_size/pad were fixed by NEWCTX and are not read here.",
   c="None for this row. (A NULL `ctx` would fault at :1367, but the only caller establishes non-NULL in code.)",
   d="B2-DUPGUARD's call-site witness shows the F1 state is refused for init; B2-FINALNULL shows the same is *not* true for final.",
   verdict="ACCEPT",
   why="The precondition is established by the single guarded call site, not by documentation. Evidence defects E-B2-2, E-B2-5."),
 "OSSH-V1I-013": dict(
   op="`ossl_md5_sha1_final(out, ctx.cast::<Md5Sha1Ctx>())` at 1199; the fn tests `outsz < 36` (:1195) but never `ctx.is_null()`.",
   safety="// SAFETY: `ctx` is a live context and `out` is writable for `outsz >= 36`. (no `# Safety` fn section at 1189)",
   callers=["src/evp/digest.rs:2646 - `EVP_DigestFinal_ex` calls `dfinal((*ctx).algctx, md, ...)` with NO algctx test",
            "src/evp/digest.rs:2779 - `EVP_DigestFinalXOF`, same omission",
            "dispatch registration at :1246 (OSSL_FUNC_DIGEST_FINAL)"],
   a="No safe-Rust path, but the unsafe contract is incomplete: `EVP_DigestFinal_ex`'s own state machine can compute algctx==NULL (a refused NEWCTX at :2328-2332 leaves `digest` set and `algctx` NULL), and a caller that satisfies that function's `# Safety` then reaches this body with NULL.",
   b="Yes for the write bound (`outsz >= 36` is checked and only 36 bytes are written, MD5 then SHA-1 at md+16). The precondition that is NOT covered is the liveness of `ctx`: the callee dereferences it through `(*mctx).md5` at md5_sha1.rs:92.",
   c="Yes, unreported: 'dfinal is never called with a NULL algctx'. `EVP_DigestFinal_ex` has no algctx test (unlike the re-acquire arm at :3297 and like the batch-1 copyctx sites), so the same F1 state that batch 1 rejected for copyctx has a second sink here.",
   d="B2-FINALNULL: dfinal_sites=[2646,2779], guarded=[false,false], F1 chain 2311<2328<2332<2335, row classified unprotected (md5_sha1 publishes no GETTABLE_CTX_PARAMS, so `EVP_MD_CTX_get_size_ex` falls back to the static size and proceeds). Repair canary K13 FIRED.",
   verdict="REJECT",
   why="The disposition claims the caller establishes a live Md5Sha1Ctx; it does not. Reachable sequence: EVP_DigestInit_ex fails at NEWCTX (allocation refusal) -> digest set, algctx NULL -> EVP_DigestFinal_ex -> dfinal(NULL) -> `(*mctx).md5` faults. Discharge: test `(*ctx).algctx` in EVP_DigestFinal_ex (and FinalXOF/Update) before dfinal, or make the providers refuse NULL; either is a recorded §17 improvement over 3.6.4, which has the same shape. Evidence defects E-B2-1, E-B2-2, E-B2-5 also apply."),
 "OSSH-V1I-029": dict(
   op="`$flavour::final_(out, ctx.cast::<$flavour::Ctx>())` at 2036, reached only after `outsz < outlen` is refused at :2032; `outlen` is read from `(*md).ctx.outlen` at :2025.",
   safety="// SAFETY: `out` is writable for `outsz >= outlen`. (no `# Safety` fn section at 2013)",
   callers=["src/evp/digest.rs:2646 - `EVP_DigestFinal_ex`",
            "src/evp/digest.rs:2779 - `EVP_DigestFinalXOF` (`outsz == size`; the `outsz < outlen` refusal still applies first, so a short buffer is refused, not overflowed)",
            "dispatch registration at :2055 inside `blake_row!` (both blake rows)"],
   a="No safe-Rust path, and unlike the hand-written finals this body is reachable with a NULL ctx only if `EVP_MD_CTX_get_size_ex` returns >= 0 first; it does not, because blake publishes GETTABLE_CTX_PARAMS and `get_ctx_params` refuses NULL with 0 (:1952-1953), so `get_size_ex` answers -1 and the final is never called (B2-FINALNULL classifies this row protected).",
   b="Yes. `*outl` is written exactly once before the guards (the authority's own order, blake2_prov.c:232) and `out` is written only after `outsz >= outlen`.",
   c="None. One unrecorded *compatibility* divergence: when `outsz < outl` the authority raises PROV_R_INVALID_DIGEST_SIZE (blake2_prov.c:238) and this body returns 0 raising nothing (an ERROR_PASS gap, observed here, not a safety issue).",
   d="B2-FINALNULL protection path; B2-DUPGUARD's sibling guard evidence; no canary targets this row because no check fires on it.",
   verdict="ACCEPT",
   why="The write is bounded by a check the caller's outsz cannot bypass, and the F1 NULL-algctx state is refused upstream *by code in this crate* (unlike sha1/md5_sha1). Residual finding E-B2-7 records the missing error-queue entry."),
 "OSSH-V1I-004": dict(
   op="`SHA1_Final(out, ctx.cast::<ShaCtx>())` at 692; `outsz < 20` is checked at :688, `ctx` never.",
   safety="// SAFETY: `ctx` is a SHA-1 context; `out` is writable for `outsz >= 20`. (no `# Safety` fn section at 682)",
   callers=["src/evp/digest.rs:2646 - `EVP_DigestFinal_ex`, no algctx test",
            "src/evp/digest.rs:2779 - `EVP_DigestFinalXOF`, no algctx test",
            "dispatch registration at :733 (OSSL_FUNC_DIGEST_FINAL)"],
   a="No safe-Rust path, but a contract-satisfying caller reaches this body with NULL: a refused NEWCTX (:2328-2332) leaves digest set / algctx NULL, and `EVP_DigestFinal_ex` calls dfinal without testing algctx.",
   b="Yes for the output bound (20 bytes after `outsz >= 20`); not for the context precondition, which the sole in-crate caller does not establish.",
   c="Yes, unreported: the same 'dfinal may receive a NULL algctx' obligation as OSSH-V1I-013. sha1 publishes no GETTABLE_CTX_PARAMS, so `EVP_MD_CTX_get_size_ex` falls back to the static 20 and proceeds.",
   d="B2-FINALNULL: row unprotected, repair canary K13 FIRED.",
   verdict="REJECT",
   why="Same defect and same discharge as OSSH-V1I-013: add the algctx test in EVP_DigestFinal_ex/FinalXOF (recorded §17 improvement) or refuse NULL in the provider. `SHA1_Final` -> `md32::finalize` dereferences the context, so the fault is a write through a NULL context. Evidence defects E-B2-1, E-B2-2, E-B2-5."),
 "OSSH-V1I-012": dict(
   op="`ossl_md5_sha1_init(ctx.cast::<Md5Sha1Ctx>())` at 1182, then `set_ctx_params(ctx, params)` at 1186.",
   safety="// SAFETY: `ctx` is the context the provider allocated. (no `# Safety` fn section at 1177)",
   callers=["src/evp/digest.rs:2349 - the single `dinit` call site, guarded by :2313/:2329-2332",
            "dispatch registration at :1252 (OSSL_FUNC_DIGEST_INIT)"],
   a="No: the only init call site refuses a NULL constructor result before calling dinit.",
   b="Yes. Both writes are inside the provider's own context; `params` is read only through the declared descriptors.",
   c="None for this row.",
   d="B2-DUPGUARD call-site witness (init cannot receive NULL), B2-NULLPARAM for the params array.",
   verdict="ACCEPT",
   why="Precondition established in code by the single guarded `dinit` call. Evidence defects E-B2-1, E-B2-2, E-B2-5."),
 "OSSH-V1I-027": dict(
   op="`set_ctx_params(ctx, params)` at 1983, then `param_init(&mut (*md).params)` and `$flavour::init(addr_of_mut!((*md).ctx), addr_of!((*md).params))` at 1991-1995.",
   safety="// SAFETY: `ctx` is the provider's context and `params` the caller's array. (no `# Safety` fn section at 1975)",
   callers=["src/evp/digest.rs:2349 (guarded by :2313/:2329-2332)",
            "dispatch registration at :2079 (OSSL_FUNC_DIGEST_INIT, both blake rows)"],
   a="No. `set_ctx_params` refuses a NULL ctx (:1916-1918), so a NULL here returns 0 before any dereference.",
   b="Yes. `blake2::init` requires `p.b[0] in 1..=OUTBYTES`; this body establishes it: `set_ctx_params` refuses out-of-range values (:1933) and otherwise `param_init` writes DIGEST_LENGTH (=OUTBYTES) before the previously validated value is restored (:1991-1994). The two fields are taken with `addr_of_mut!`/`addr_of!`, so no two `&mut` are formed.",
   c="None.",
   d="B2-DUPGUARD's init-call witness; B2-NULLPARAM for the params array; K11 FIRED.",
   verdict="ACCEPT",
   why="The digest-length bound that `blake2::init` documents as a caller obligation is actually enforced by this function in code, not by prose. Evidence defects E-B2-2, E-B2-5, E-B2-1."),
 "OSSH-V1I-003": dict(
   op="`SHA1_Init(ctx.cast::<ShaCtx>())` at 675, then `set_ctx_params(ctx, params)` at 679.",
   safety="// SAFETY: `ctx` is the SHA-1 context the provider allocated. (no `# Safety` fn section at 670)",
   callers=["src/evp/digest.rs:2349 - the single `dinit` call site, guarded by :2313/:2329-2332",
            "dispatch registration at :756 (OSSL_FUNC_DIGEST_INIT)"],
   a="No: the only init call site refuses NULL before dinit.",
   b="Yes. `SHA1_Init` writes the context's own words; params through the declared descriptors.",
   c="None.",
   d="B2-DUPGUARD call-site witness; B2-NULLPARAM.",
   verdict="ACCEPT",
   why="Precondition established by the single guarded call site. Evidence defects E-B2-1, E-B2-2, E-B2-5."),
 "OSSH-V1I-020": dict(
   op="`let c = ctx.cast::<KeccakCtx>(); (*c).md_size` at 1386-1388 and `ossl_sha3_final(c, out, (*c).md_size)` at 1395, guarded only by `outlen > 0` at 1394.",
   safety="// SAFETY: `c` is live and `out` is writable for `outlen`. (no `# Safety` fn section at 1377)",
   callers=["src/evp/digest.rs:2646 - `EVP_DigestFinal_ex` (outlen = EVP_MD_CTX_get_size_ex, which equals md_size for the SHA3 rows, so this arm is bounded)",
            "src/evp/digest.rs:2779 - `EVP_DigestFinalXOF`: outlen = the caller's `size`, and `set_params`' answer is only tested with `>= 0`, so a fixed SHA3 row (no SET_CTX_PARAMS, hence 0) still reaches dfinal with the caller's size",
            "dispatch registration at :1571 and :1639 (`super::keccak_final`, OSSL_FUNC_DIGEST_FINAL)"],
   a="No safe-Rust path, but TWO unsafe preconditions are unestablished: (i) the algctx is never tested before `(*c).md_size` (F1 state sink, as OSSH-V1I-004/013); (ii) `md_size <= outlen` is never required, so `EVP_DigestFinalXOF(sha3_256_ctx, buf, 16)` with a 16-byte buffer writes the row's 32 bytes.",
   b="The output bound is NOT covered: the only size test is `outlen > 0`. The authority has the identical shape (sha3_prov.c:112-129 and EVP_DigestFinalXOF's `>= 0` test at digest.c:530), so this is a conserved hazard, not a conversion regression — but §17 forbids reproducing it as if it were correct, and the crate's `EVP_DigestFinalXOF` `# Safety` (:2726) does not exclude the call.",
   c="Yes, two, both unreported: the NULL-algctx sink (B2-FINALNULL) and the unbounded `md_size` write (B2-KFINAL). Neither appears in the row's contract, which says only 'writes at most md_size bytes to out' while requiring `out` writable for `outlen` — the contract itself permits md_size > outlen.",
   d="B2-KFINAL (writes_md_size=True, bound=False, xof_passes_caller_size=True, xof_ignores_set_params=True, no EVP_MD_xof test) with repair canary K4 FIRED; B2-FINALNULL with row unprotected and K13 FIRED.",
   verdict="REJECT",
   why="Two independent unestablished preconditions. Discharge: (1) refuse `md_size > outlen` in keccak_final or test `EVP_MD_xof` in FinalXOF's provider arm — a §17-recorded safety improvement over 3.6.4; (2) test `(*ctx).algctx` before dfinal (shared with OSSH-V1I-004/013); (3) restate the contract to include `outlen >= md_size`. Evidence defects E-B2-2, E-B2-5 also apply."),
 "OSSH-V1I-025": dict(
   op="`OSSL_PARAM_get_uint(p, &mut size)` at 1930, range check `size < 1 || size as usize > $outbytes` at 1933, then `param_set_digest_length(&mut (*ctx.cast()).params, size as u8)` at 1938.",
   safety="// SAFETY: `params` is NULL or key-terminated per the caller's contract. / // SAFETY: `ctx` is the provider's context. (no `# Safety` fn section at 1912)",
   callers=["src/evp/digest.rs:3461 - `EVP_MD_CTX_set_params` (no algctx test, but this body refuses NULL at :1916-1918)",
            "src/provider/digest.rs:1983 - `internal_init` calls this first, which is how the digest-length bound reaches `blake2::init`",
            "dispatch registration at :2088 (OSSL_FUNC_DIGEST_SET_CTX_PARAMS)"],
   a="No. ctx is NULL-tested, params is NULL-tested, and the only value written is index 0 of a `[u8; 64]`/`[u8; 32]` with the range already checked.",
   b="Yes. `param_set_digest_length` writes `p.b[0]` only; the accepted range is 1..=OUTBYTES and `size as u8` cannot truncate at 64.",
   c="None.",
   d="B2-NULLPARAM + K11 FIRED; the range check is read at :1933 (a canary for it would need a stateful harness, which this review did not build — see does_not_prove).",
   verdict="ACCEPT",
   why="Both preconditions (live ctx, well-formed params) are established in code and the value is range-checked before the write. Evidence defects E-B2-1, E-B2-2, E-B2-5."),
}


def get(url, args):
    out = subprocess.run([sys.executable, url] + args, capture_output=True, text=True, cwd=ROOT)
    return out


def dispatch_line(prov_lines, item, row_line):
    pat = re.compile(r"function: (super::)?" + re.escape(item) + r" as \*mut c_void")
    hits = [i + 1 for i, x in enumerate(prov_lines) if pat.search(x)]
    # nearest registration after the definition
    after = [h for h in hits if h > row_line]
    return after[0] if after else (hits[0] if hits else None)


def module_span(lines, row_line):
    """Enclosing `mod NAME { ... }` brace span around row_line (1-based)."""
    mod_re = re.compile(r"^\s*(?:pub(?:\((?:super|crate)\))?\s+)?mod\s+[$A-Za-z_][$A-Za-z0-9_]*\s*\{\s*$")
    start = None
    for i in range(row_line - 1, -1, -1):
        if mod_re.match(lines[i]):
            start = i
            break
    if start is None:
        return None, None
    depth = 0
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth <= 0:
            return start + 1, i + 1
    return start + 1, len(lines)


def main():
    inv = json.load(open(INV))
    rec = json.load(open(RECEIPT))
    by_id = {o["discharge_boundary_id"]: o for o in inv["obligations"]
             if o["discharge_boundary_id"] in IDS}
    rb = {b["id"]: b for b in rec["boundaries"]}
    prov = open(os.path.join(ROOT, "src/provider/digest.rs")).read().split("\n")

    audit = json.loads(get(os.path.join(HERE, "v1i_batch2_audit.py"), ["--json"]).stdout)
    canary = get(os.path.join(HERE, "run_canaries_v1i_batch2.py"), [])
    canary_lines = [l for l in canary.stdout.strip().split("\n") if l.strip()]
    canary_all = canary_lines[-1]

    obligations = []
    for oid in IDS:
        o, b, a = by_id[oid], rb[oid], ROWS[oid]
        regs = [i + 1 for i, x in enumerate(prov)
                if re.search(r"function: (super::)?" + re.escape(o["item"]) + r" as \*mut c_void", x)
                and i + 1 > o["line"]]
        ms, me = module_span(prov, o["line"])
        if ms is not None:
            regs = [r for r in regs if ms < r < me]
        callers = [c for c in a["callers"] if not c.startswith("dispatch registration")]
        callers.append("dispatch registration(s) inside the enclosing module (lines %s-%s) of src/provider/digest.rs: %s"
                       % (ms, me, ", ".join(str(r) for r in regs[:3]) or "NONE"))
        obligations.append({
            "boundary": oid,
            "item": o["item"],
            "file": o["file"],
            "line": o["line"],
            "mechanism": o["mechanism"],
            "contract_location": (
                "the contract exists only as the `contract` field of boundary %s in "
                "openssl-v1i-sites.json (quoted below) plus a `// SAFETY:` block comment at the "
                "operation; there is NO `# Safety` section on the definition" % oid),
            "unsafe_operations_read": [a["op"]],
            "safety_comment_quoted": a["safety"],
            "callers_enumerated": callers,
            "answers": {
                "a_safe_rust_can_cause_ub": a["a"],
                "b_all_unsafe_covered": a["b"],
                "c_hidden_obligation": a["c"],
                "d_load_bearing_control": a["d"],
            },
            "control": {
                "id": "CTRL-AUDIT-B2",
                "path": "court/freeze-b76/review/controls/v1i_batch2_audit.py",
                "checks": ["B2-SPAN", "B2-ITEM", "B2-COORD", "B2-SAFETY", "B2-DISPATCH",
                           "B2-DUPGUARD", "B2-NULLPARAM", "B2-KFINAL", "B2-COPYCTX",
                           "B2-FINALNULL", "B2-JOIN", "B2-WITNESS"],
                "canaries": ["K1-pristine", "K2", "K3", "K4", "K5", "K6", "K7", "K8",
                             "K9", "K10", "K11", "K12", "K13"],
                "canary_harness": "court/freeze-b76/review/controls/run_canaries_v1i_batch2.py",
                "result": canary_all,
            },
            "verdict": a["verdict"],
            "verdict_reason": a["why"],
            "stable_id": o["stable_id"],
            "id": o["id"],
            "recorded_contract": b["contract"],
            "recorded_contract_source": "openssh-v1i-sites.json boundary %s (field `contract`)" % oid,
            "receipt_boundary_line": b["line"],
            "span_sha256": o["recorded_span"]["sha256"],
            "span_hash_rederived": True,
        })

    checks = {c["id"]: c for c in audit["checks"]}
    accept = [o["boundary"] for o in obligations if o["verdict"] == "ACCEPT"]
    reject = [o["boundary"] for o in obligations if o["verdict"] == "REJECT"]
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip()
    blob = hashlib.sha256(open(os.path.join(ROOT, "src/provider/digest.rs"), "rb").read()).hexdigest()
    inst = {n: hashlib.sha256(open(os.path.join(HERE, n), "rb").read()).hexdigest()
            for n in ("v1i_batch2_audit.py", "run_canaries_v1i_batch2.py")}

    doc = {
        "schema": "openssl-rs/campaign/safe-c33/atlas-refresh/review/v1",
        "kind": "independent-adversarial-review",
        "subphase": "safe-c33/b76-review-v1i-batch2",
        "generated_utc": subprocess.run(
            ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"], capture_output=True, text=True).stdout.strip(),
        "review": {
            "role": "independent adversarial reviewer (AGENTS.md §15)",
            "independence": (
                "The reviewer wrote none of the 19 conversions, the openssh-v1i receipt, the "
                "b76c closures or the closure instrument, and did not author AGENTS.md. Verdicts "
                "rest only on source read at the recorded spans during this review and on "
                "controls executed during this review. No author-supplied result (receipt "
                "contract, established_by, criteria, negative_controls, tests) is accepted as "
                "evidence unless re-derived here. No tracked file was modified; nothing was "
                "committed or pushed."),
            "instructions_read": ["AGENTS.md §0-§7", "§9", "§15", "§16", "§21", "§22"],
            "review_inputs": {
                "inventory": "court/freeze-b76/review/review-65-inventory.json",
                "group_receipt": "forensics/memory-safety/campaign/safe-c33/atlas-refresh/openssh-v1i-sites.json",
                "precedent": "forensics/memory-safety/campaign/safe-c33/atlas-refresh/b76-review-v1i-batch1.json",
                "freeze": "court/freeze-b76/FREEZE-b76.json",
                "controls": ["court/freeze-b76/review/controls/v1i_batch2_audit.py",
                             "court/freeze-b76/review/controls/run_canaries_v1i_batch2.py"],
            },
        },
        "candidate_identity": {
            "source_head": "0238c6e4adbc7ed85a42be68b6fb965e139bd93e",
            "head_at_review": head,
            "src_content_sha256": "66c1e9ae6fcc3292b697e06febc0a20289c6d897779bf79f7f6f8015cef3f532",
            "src_content_hash_rederived": True,
            "src_content_hash_rule": ("sha256('openssl-rs/src-rs/v1\\0' + sorted relpath\\0bytes\\0); "
                                      "relpaths relative to the repository root; 878 .rs files"),
            "src_unchanged_between_S_and_review_head": True,
            "src_unchanged_witness": ("the re-derived digest equals the freeze value "
                                      "(66c1e9ae…), so the tree read at HEAD d2fe349bc is S's "
                                      "src content; HEAD moved only by batch-1 evidence commits"),
            "audited_file_blob_sha256": blob,
            "audited_file_blob_matches_receipt": blob == (
                "2affef415e400c531de72d2c37e47ba9d17c90fb968871f8acf1f133009cfc72"),
            "instrument_sha256": inst,
            "verification_note": ("src/provider/digest.rs hashes to the receipt's own "
                                  "source_blob_sha256, so the rows were read in the file the "
                                  "receipt measured. No build or test was run: available memory "
                                  "was 12 GiB, below the §6.1 24 GiB floor."),
        },
        "method": {
            "task1": ("read each body at its recorded span, quoted the unsafe operation, and "
                      "compared the receipt's contract with what the code permits; the contract "
                      "is never accepted as evidence"),
            "task2": ("enumerated every caller from source (dinit/dfinal/dupctx/copyctx/"
                      "get_params/get_ctx_params/set_ctx_params call sites in src/evp/digest.rs "
                      "plus the dispatch registrations), and decided per caller whether the "
                      "precondition is established by code"),
            "task3": ("answered the four questions per row; a documented precondition was not "
                      "counted as established (§21.1)"),
            "controls": ("an external, test-only source-level audit (12 checks) plus 13 canaries "
                         "that mutate a private copy; nothing was compiled and no tracked file "
                         "was touched"),
        },
        "obligations": obligations,
        "controls_executed": [
            {"id": c["id"], "path": "court/freeze-b76/review/controls/v1i_batch2_audit.py",
             "purpose": c["description"], "result": ("PASS" if c["pass"] else "FAIL") + " — " + c["observed"]}
            for c in audit["checks"]
        ] + [
            {"id": "canary-harness",
             "path": "court/freeze-b76/review/controls/run_canaries_v1i_batch2.py",
             "purpose": "prove every detector is load-bearing (repair canaries flip FAIL->PASS, break canaries flip PASS->FAIL)",
             "result": canary_all},
        ],
        "findings": [
            {"id": "F-B2-1", "severity": "memory-safety (conserved from the authority)",
             "statement": ("keccak_final writes the context's md_size bytes to `out` whenever "
                           "outlen > 0 (src/provider/digest.rs:1394-1396) and never requires "
                           "md_size <= outlen. EVP_DigestFinalXOF (src/evp/digest.rs:2779) passes "
                           "the caller's `size` as outlen and calls dfinal on `set_params >= 0`, "
                           "which is 0 for a fixed SHA3 row, so EVP_DigestFinalXOF(sha3_256, "
                           "buf16, 16) writes 32 bytes. 3.6.4 has the same shape "
                           "(sha3_prov.c:112-129, digest.c:530): conserved, not introduced, but "
                           "the crate's own # Safety at :2726 admits the call. Control B2-KFINAL.")},
            {"id": "F-B2-2", "severity": "memory-safety (conserved from the authority)",
             "statement": ("EVP_DigestFinal_ex (:2646) and EVP_DigestFinalXOF (:2779) call dfinal "
                           "with (*ctx).algctx and no NULL test. A refused NEWCTX (:2328-2332) "
                           "leaves digest set and algctx NULL, so EVP_DigestFinal_ex on that "
                           "context calls a final with NULL; sha1::internal_final (:692), "
                           "md5_sha1::internal_final (:1199) and keccak_final (:1388) then "
                           "dereference it. blake2 is protected because it publishes "
                           "GETTABLE_CTX_PARAMS and get_ctx_params refuses NULL (:1952). Control "
                           "B2-FINALNULL. This is the batch-1 F1 state with a second sink.")},
            {"id": "E-B2-1", "severity": "evidence (coordinates)",
             "statement": ("16 of the 19 records carry coordinate_check.actual_definition_line = "
                           "433/465/479/515/596, which are the `digest_impl!`/`sha1::set_ctx_params` "
                           "items, while the recorded site is a different, hand-written function "
                           "(dupctx 647/959/1154/1337/1885, get_params 705/1019/1214/2039, "
                           "internal_final 682/1189/2013, internal_init 670/1177/1975, "
                           "set_ctx_params 1912). `stale` is still reported false, so the field "
                           "that says which definition was bound is name-resolved, not "
                           "identity-resolved (§22). Only 026/018/020 are correct. The recorded "
                           "line and span hash are correct in all 19: B2-SPAN 19/19, B2-ITEM 19/19.")},
            {"id": "E-B2-2", "severity": "evidence (contract at interface)",
             "statement": ("None of the 19 definitions carries a `# Safety` section; the receipt "
                           "nonetheless records criteria.contract = PASS for all of them. The "
                           "contract text lives only in the receipt and in `// SAFETY:` block "
                           "comments. (The functions are private, so clippy's missing_safety_doc "
                           "does not fire — which is why this was not caught mechanically.)")},
            {"id": "E-B2-3", "severity": "evidence (join)",
             "statement": ("All 19 obligations carry the SAME 112-element boundary_ids list, so "
                           "the inventory->receipt join is non-discriminating; the discharging row "
                           "is named only by discharge_boundary_id. This is the batch-1 "
                           "'boundary row accepted by a content address' class in its inventory "
                           "form. Control B2-JOIN.")},
            {"id": "E-B2-4", "severity": "evidence (recurrence)",
             "statement": ("The batch-1 NULL-algctx copyctx defect is unchanged on this candidate: "
                           "copyctx((*out).algctx, (*in_).algctx) at src/evp/digest.rs:3042 and "
                           ":3079 still has no algctx test. B2-COPYCTX FAIL is the recurrence "
                           "witness (K10 flips it).")},
            {"id": "E-B2-5", "severity": "evidence (per-call-site witnesses)",
             "statement": ("All 19 rows cite the same generic `established_by` sentence ('caller: "
                           "src/evp/digest.rs and the provider dispatch … obtain the algctx from "
                           "NEWCTX/DUPCTX') with no coordinate, so §22's per-call-site witness is "
                           "absent everywhere. For the four `get_params` rows (006/009/015/030) the "
                           "sentence is not merely generic but inapplicable: that ABI slot "
                           "(OSSL_FUNC_digest_get_params, called at src/evp/digest.rs:1168) has no "
                           "algctx parameter at all.")},
            {"id": "E-B2-6", "severity": "compatibility (contract text)",
             "statement": ("Boundary OSSH-V1I-026's contract says the function 'returns 1'; the "
                           "body returns 0 when OSSL_PARAM_set_uint refuses the located entry "
                           "(:1967). No write occurs on that path, so this is a contract "
                           "inaccuracy, not a safety gap.")},
            {"id": "E-B2-7", "severity": "compatibility (error queue)",
             "statement": ("blake2::internal_final returns 0 for `outsz < outlen` without raising "
                           "PROV_R_INVALID_DIGEST_SIZE, which the authority raises at "
                           "blake2_prov.c:238 (ERROR_PASS). Observed in source; no error-queue "
                           "court was run here.")},
        ],
        "receipt_identity": {
            "reviewed_group_receipt": "forensics/memory-safety/campaign/safe-c33/atlas-refresh/openssh-v1i-sites.json",
            "reviewed_inventory": "court/freeze-b76/review/review-65-inventory.json",
            "note": ("The group receipt's source_blob_sha256 matches the current file, and its "
                     "criteria are PASS for all 19 rows. The evidence defects above are in the "
                     "derived coordinate field (inventory), the join, the witnesses and the "
                     "interface contracts — not in the recorded operation coordinates."),
        },
        "summary": {
            "obligations_reviewed": 19,
            "selection_rule": ("the 19 lexicographically-next stable_ids after batch 1: sorted by "
                               "(stable_id, id), rows 20..38 of the 56 openssh-v1i obligations in "
                               "the inventory; all are src/provider/digest.rs"),
            "accept": len(accept),
            "reject": len(reject),
            "accept_list": accept,
            "reject_list": reject,
            "safe_rust_ub_found": False,
            "c_valid_abi_ub_path_found": True,
            "hidden_obligations_found": 3,
            "hidden_obligations": [
                "keccak_final: md_size <= outlen is not required (F-B2-1), reachable via EVP_DigestFinalXOF on a fixed SHA3 row",
                "internal_final/keccak_final: dfinal may receive a NULL algctx in the batch-1 F1 state and these bodies dereference it (F-B2-2)",
                "OwnedCtx<T>::dup is a shallow bitwise copy over an unconstrained T; sound for the five POD context types here but not enforced by the type (retained, §9)",
            ],
            "new_obligations_introduced": 0,
            "accepts_resting_on_unobserved_evidence": 0,
            "evidence_record_defects": ["E-B2-1", "E-B2-2", "E-B2-3", "E-B2-4", "E-B2-5", "E-B2-6", "E-B2-7"],
            "controls_run": 2,
            "audit_checks": len(audit["checks"]),
            "canaries_fired": canary_all.split(" ")[0],
            "runtime_controls_run": 0,
            "remaining_unreviewed_v1i": 37,
            "unique_inventory_ids": 19,
            "stable_id_collisions": ("five `dupctx` rows and four `get_params` rows share one "
                                    "stable_id each by construction; the inventory id is "
                                    "line-qualified and the 19 ids are distinct"),
            "build_or_test_run": False,
            "build_blocked_by": "free -g available 12 GiB < 24 GiB (§6.1): no compilation attempted",
        },
        "does_not_prove": [
            "That the 16 ACCEPTs are SAFETY_DISCHARGED: they remain OWNERSHIP_RECONSTRUCTED with the interface contract absent; a # Safety section at each definition and per-call-site witnesses are still required (§7, §22).",
            "That the provider callbacks are correct under concurrent use: no test exercises two threads against one algctx, and the dispatch rows publish no Send/Sync claim (not examined here).",
            "That EVP_DigestFinalXOF's overflow is reachable at runtime on this build: the witness is source-level (B2-KFINAL), no binary was run. Neither the crash nor its absence was observed.",
            "That the F1 state is reachable without an allocation failure: the witness is the refused NEWCTX path (:2328-2332); a provider-shutdown refusal is filtered by each body's ossl_prov_is_running() gate and was not measured.",
            "That the OSSL_PARAM setters used by get_params/get_ctx_params are correct for every declared type: their contracts were read, not exercised; no params court was run.",
            "That the 13 canaries cover the blake2 digest-length range check at :1933 — a canary for it needs a stateful harness that this review did not build.",
            "That the error-queue divergence E-B2-7 is the only compatibility difference in these 19 rows: no differential court was run against 3.6.4.",
            "Anything about the other 37 openssh-v1i obligations, the openssh-v1l callbacks, or the b76c closures.",
        ],
    }
    with open(OUT, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=False)
        f.write("\n")
    data = open(OUT, "rb").read()
    print("wrote", OUT)
    print("sha256", hashlib.sha256(data).hexdigest(), "bytes", len(data))
    print("accept", len(accept), "reject", len(reject), reject)


if __name__ == "__main__":
    main()
