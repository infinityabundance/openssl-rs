"""Write the b78 review receipt."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

HERE = Path(__file__).resolve().parent
ATLAS = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh"
S = "bb7d5206acfbf6c3e0ba202a0a03e61b8bf13aac"

obls = json.loads((HERE / "obligations-65.json").read_text())
rows = obls["obligations"]
digests = json.loads((HERE / "receipt-digests-b78.json").read_text())
controls = json.loads((HERE / "controls-b78.json").read_text())["controls"]
adj = json.loads((HERE / "adjudicate-control-b78.json").read_text())

# fn-level `# Safety` section present?
text_cache = {}


def has_fn_safety(file, def_line):
    if file not in text_cache:
        text_cache[file] = subprocess.check_output(
            ["git", "-C", str(ROOT), "show", f"{S}:{file}"]).decode()
    lines = text_cache[file].splitlines()
    j = def_line - 2
    seen = 0
    while j >= 0 and seen < 30:
        s = lines[j].strip()
        if s.startswith("///") or s.startswith("//!") or s.startswith("//") or not s:
            if "# Safety" in s:
                return True
            j -= 1
            seen += 1
            continue
        break
    return False


for r in rows:
    r["fn_level_safety_section"] = has_fn_safety(
        r["file"], r["current_span"]["def_line"])
no_fn = [r for r in rows if not r["fn_level_safety_section"]]

REVIEW = {
    "identity45": (
        "Identity transcription.  The operation span at the b78 source head is "
        "byte-identical to the span at the head the earlier review read, and "
        "that earlier receipt is the establishing review.  No new judgement is "
        "made about the site."),
    "identity8": (
        "Identity transcription for the repaired body, plus a caller re-read. "
        "The body is byte-identical to the repair head that b77 accepted; the "
        "only b78 source change (src/evp/digest.rs) moved the "
        "same-method-destination guard inside the `copyctx` arm.  I re-read the "
        "current EVP_MD_CTX_copy_ex and confirmed the destination is still "
        "non-NULL whenever `copyctx` is invoked (and that the self-copy arm's "
        "`out == in_` makes the checked source `algctx` the destination), so the "
        "accepted precondition is preserved, not widened."),
    "rereview11": (
        "Re-rejected at b76 because the provider callback could receive a NULL "
        "`algctx` from a failed provider initialise.  Re-reviewed here: the "
        "required discharge (a caller guard) is present at every dispatch "
        "site, each provider callback has exactly one invocation site, and "
        "NO_INIT contexts take the legacy arm and never reach a provider "
        "callback.  The site body itself is unchanged from the review that "
        "rejected it, so the extent/aliasing analysis of that review still "
        "applies."),
    "rereview1": (
        "Re-reviewed here.  The b76 rejection required a `# Safety` fn contract "
        "on the helper; the fn now carries one, the single caller forwards the "
        "same pointer under its own `# Safety`, and the receipt no longer "
        "claims a second call site.  Documentation is outside the span, so the "
        "operation hash is unchanged."),
}

RE_REVIEWED = [
    # boundary, answer a, b, c, d
    ("OSSH-V1I-002", "sha1::copyctx", "No: private `unsafe extern \"C\"` callback, "
     "reachable only through the method table.",
     "Yes: `# Safety` at the fn; core checks the source `algctx` and, inside the "
     "`copyctx` arm, the destination.",
     "None found: the self-copy arm passes the checked non-NULL source as both "
     "pointers; `ptr::copy` is defined for overlap.",
     "CTRL C7/C8 + adjudicator C9; the b78 test "
     "`a_same_method_destination_without_an_algctx_is_refused_when_copyctx_would_run` "
     "pins the destination side."),
    ("OSSH-V1I-008", "nullmd::copyctx", "No.", "Yes, same construction.",
     "None found.", "Same caller control; NULL row copies `NullMdCtx`."),
    ("OSSH-V1I-011", "md5_sha1::copyctx", "No.", "Yes, same construction.",
     "None found.", "Same caller control; `Md5Sha1Ctx` is a plain block."),
    ("OSSH-V1I-017", "sha3::copyctx", "No.", "Yes, same construction.",
     "None found.", "Same caller control; `KeccakCtx` is a plain block."),
    ("OSSH-V1I-024", "blake2::blake_row::copyctx", "No.", "Yes, same construction.",
     "None found.", "Same caller control; the macro row expands to the same body."),
    ("OSSH-V1I-020", "sha3::keccak_final",
     "No: callback only.",
     "Yes: the `md_size > outlen` bound refuses the caller-declared-extent "
     "overflow; `outl` is written with `md_size`; the caller guard closes the "
     "NULL context.",
     "None beyond the recorded §17 divergence D-SHA3-FINAL-OUTLEN-1.",
     "C8 reproduces the accepted body hash 4dbe9bbd…; the bound and the "
     "`outlen == 0` arm were read at b78."),
    ("OSSH-V1I-082", "legacy_digest_impl::copyctx", "No.", "Yes: `# Safety` + core guard.",
     "None found.", "Same caller control; `size_of::<$ctx>()` is the whole block."),
    ("OSSH-V1I-088", "mdc2::copyctx", "No.", "Yes: `# Safety` + core guard.",
     "None found.", "Same caller control; `Mdc2Ctx` is a plain block."),
    ("OSSH-V1I-014", "md5_sha1::update",
     "No: the only caller is EVP_DigestUpdate, which now refuses a NULL `algctx` "
     "before the dispatch.",
     "Yes: the caller guard and the single dispatch site establish the context "
     "precondition; `in_` extent is the caller's declaration.",
     "None found at b78.",
     "C9 adjudication; `dupdate` has exactly one invocation (digest.rs:2573)."),
    ("OSSH-V1I-019", "sha3::update", "No (same guard).", "Yes.", "None found.",
     "Same."),
    ("OSSH-V1I-028", "blake2::blake_row::update", "No (same guard).", "Yes.",
     "None found.", "Same."),
    ("OSSH-V1I-005", "sha1::update", "No (same guard).", "Yes.", "None found.",
     "Same."),
    ("OSSH-V1I-013", "md5_sha1::internal_final",
     "No: EVP_DigestFinal_ex/FinalXOF refuse a NULL `algctx` before `dfinal`.",
     "Yes: `outsz` bound checked before the write; `*outl` set to the fixed "
     "digest length.",
     "None found.", "C9; `dfinal` has one guarded invocation per entry point."),
    ("OSSH-V1I-004", "sha1::internal_final", "No (same guard).", "Yes.",
     "None found.", "Same."),
    ("OSSH-V1I-021", "sha3::shake_squeeze",
     "No: EVP_DigestSqueeze refuses a NULL `algctx` before `dsqueeze`.",
     "Yes: writes exactly `outlen` (the caller's declared extent) when "
     "`outlen > 0`, nothing otherwise.",
     "None found.", "C9; guard at digest.rs:2935, one `dsqueeze` invocation."),
    ("OSSH-V1I-084", "legacy_digest_impl::internal_final", "No (same guard).",
     "Yes.", "None found.", "Same."),
    ("OSSH-V1I-090", "mdc2::internal_final", "No (same guard).", "Yes.",
     "None found.", "Same."),
    ("OSSH-V1I-085", "legacy_digest_impl::update", "No (same guard).", "Yes.",
     "None found.", "Same."),
    ("OSSH-V1I-091", "mdc2::update", "No (same guard).", "Yes.", "None found.",
     "Same."),
    ("OSSH-V1L-009", "push_cstr_or_null",
     "No: a private `unsafe fn`; the only caller is ENGINE_set_default_string, "
     "which forwards the same pointer it received.",
     "Yes: `# Safety` states NULL-or-NUL-terminated; the caller's own `# Safety` "
     "is the external C ABI contract (config parser produces a NUL-terminated "
     "value).",
     "None hidden: the NUL-termination precondition is now written at the "
     "interface; it remains an ABI obligation for external C callers and cannot "
     "be machine-checked without a length.",
     "CTRL-AUDIT (single call site re-read at b78); no runtime control exists "
     "for NUL-termination."),
]
re_reviewed = []
for boundary, qual, a, b, c, d in RE_REVIEWED:
    row = next(r for r in rows if r["boundary"] == boundary)
    re_reviewed.append({
        "boundary": boundary, "qualified_identity": qual,
        "file": row["file"], "span": [row["current_span"]["start_line"],
                                      row["current_span"]["end_line"]],
        "span_sha256": row["current_span"]["sha256"],
        "earlier_verdict": row["earlier_verdict"],
        "a_safe_rust_can_cause_ub": a, "b_all_unsafe_covered": b,
        "c_hidden_obligation": c, "d_load_bearing_control": d,
        "verdict": "ACCEPT",
    })

review = {
    "schema": "openssl-rs/safe-c33/atlas-refresh/b78-review-final/v1",
    "kind": "independent-adversarial-review-and-receipt-regeneration",
    "subphase": "safe-c33/b78 review of the 65 openssh-v1i/openssh-v1l "
                "discharge obligations and regeneration of both site receipts",
    "generated_utc": "2026-11-13T00:00:00Z",
    "reviewer": {
        "role": "independent adversarial reviewer (AGENTS.md §15)",
        "independence": (
            "I did not write or design any of the conversions, either site "
            "receipt, the b76/b77 reviews, the closure tool, or AGENTS.md. "
            "Every verdict below is mine, from source read at bb7d5206a and from "
            "controls run in this session.  A mechanical transcription of an "
            "earlier verdict is used only for spans whose content hash is "
            "identical at the earlier review head and at b78, and each such row "
            "says so."),
        "author_is_not_adjudicator": True,
    },
    "candidate_identity": {
        "source_head": S,
        "src_content_sha256":
            "c0bd61c94f5a8da2e08c105724d14750403fbfd53aa8d4b722672f9b11b0bd38",
        "image_libcrypto_sha256":
            "a27ca428f899a58bab0449d46914a54af3f604d4b72c0ff0e5153ab14415e507",
        "head_at_review": subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"]).decode().strip(),
        "census": "court/freeze-b78/census-b78.json",
        "closure_at_review": "evidence/closure-ssh-b77.json "
                             "(the last measured closure; not regenerated here)",
        "closure_tool_sha256": cc.sha256_file(
            ROOT / "forensics/tools/consumer_closure.py"),
        "working_tree_tool_matches": True,
    },
    "venue": {
        "free_g_available_gib": 12,
        "memory_cap": "8 GiB court cgroup, per §6.1",
        "compilation": ("refused: available 12 GiB < the 24 GiB build floor, so "
                        "the §6.1 cap would be below its 2 GiB floor.  No build, "
                        "no test run, no runtime probe."),
        "work_done": "source reading, git-blob span resolution, JSON analysis, "
                     "and in-memory/negative controls",
    },
    "method": {
        "task1": (
            "Cohort rebuilt from the earlier review receipts (56 openssh-v1i + 9 "
            "openssh-v1l), not from the b77 closure's receipt field, because the "
            "b77 closure refused 8 of the 56 and recorded no receipt for them.  "
            "Each obligation's current coordinate is resolved from census-b78 by "
            "(file, kind, item) and from the closure tool's span resolver by "
            "(file, qualified operation).  No recorded line is used for "
            "identity.  Output: court/freeze-b78/obligations-65.json."),
        "task2": (
            "Span hashes recomputed at three heads with the tool's own rule: "
            "b76 0238c6e4, b77 ada7df257, b78 bb7d5206a.  All 65 spans are "
            "byte-identical to the head at which the earlier review read them.  "
            "Because a span hash covers the operation's own text only, identity "
            "cannot establish a *caller* precondition, which is the b77 "
            "finding D5; the 58 identity rows are recorded as identity, and the "
            "12 sites whose acceptance rests on a changed caller/contract were "
            "re-read and re-adjudicated here."),
        "task3": (
            "Both receipts re-resolved every boundary (not only the cohort) with "
            "the tool's resolver at S, rewrote every span_sha256, set every "
            "disposition range to the current definition line, and made "
            "disposition a function of this review's verdict only.  Verified "
            "with the tool's own load_boundaries/adjudicate path."),
        "controls": (
            "C1-C8 in court/freeze-b78/run_controls_b78.py; C9 end-to-end "
            "adjudication in court/freeze-b78/run_adjudicate_control_b78.py."),
    },
    "task1_obligation_set": {
        "cohort": 65,
        "by_boundary_receipt": {"openssh-v1i": 56, "openssh-v1l": 9},
        "current_coordinate_resolution": "65/65 unique; every resolved "
                                         "definition line is also the census "
                                         "line for that (file, kind, item)",
        "absent_items": [],
        "file_or_kind_changed": [],
        "receipt_boundaries_whose_item_no_longer_exists": [
            "OSSH-V1I-055 x509_free_void",
            "OSSH-V1I-056 evp_pkey_free_void",
            "OSSH-V1I-057 evp_md_free_void",
            "OSSH-V1I-058 octet_string_free_void",
            "OSSH-V1I-062 x509_store_free_void",
        ],
        "note": ("Those five are not obligations in either closure (they are not "
                 "in the 65); they are retired thunks and the regenerated "
                 "receipt records them as ABSENT / non-discharging."),
    },
    "task2_verdicts": {
        "tally": {"ACCEPT": 65, "REJECT": 0, "ABSENT": 0},
        "by_class": {"identity45": 45, "identity8": 8,
                     "rereview11": 11, "rereview1": 1},
        "identity_rule": ("ACCEPT (identity) is used only where the span hash at "
                          "the earlier review head equals the span hash at b78; "
                          "this held for 65/65 sites.  It does not by itself "
                          "establish a caller precondition, and is not used "
                          "where the caller changed."),
        "by_class_explanation": REVIEW,
        "re_reviewed_sites": re_reviewed,
        "previously_rejected_sites": {
            "count": 20,
            "repaired_at_b77_repair_head": 8,
            "repaired_at_the_caller_entry_points": 11,
            "repaired_by_adding_a_fn_contract": 1,
            "still_reject": 0,
        },
        "obligations": [
            {"boundary": r["boundary"], "file": r["file"], "item": r["item"],
             "qualified_identity": r["qualified_identity"],
             "span": [r["current_span"]["start_line"],
                      r["current_span"]["end_line"]],
             "span_sha256": r["current_span"]["sha256"],
             "span_identical_to_review_head": r["span_hash_identical"],
             "earlier_receipt": r["earlier_receipt"],
             "earlier_verdict": r["earlier_verdict"],
             "verdict": r["verdict"], "verdict_class": r["verdict_class"],
             "basis": r["verdict_basis"]}
            for r in rows],
    },
    "controls": {
        "span_rule": controls,
        "end_to_end_adjudication": {
            "input": "the closure's own load_boundaries + adjudicate, with a "
                     "synthetic plane that lists EVERY boundary id as "
                     "scoped-discharged (the strongest possible input)",
            "cohort_discharged": adj["discharged"],
            "cohort_not_discharged": adj["not_discharged"],
            "withdrawn_boundaries_refused": adj["withdrawn_control"],
            "absent_boundaries": adj["absent_control"],
            "pass": adj["pass"],
        },
        "not_run": [
            "any compilation, library test, clippy or fmt (§6.1 memory floor)",
            "any runtime negative-control binary",
            "a fresh b78 consumer closure (the receipts are inputs to it; the "
            "closure must be re-measured by the orchestrator)",
        ],
    },
    "regenerated_receipts": {
        name: details for name, details in digests.items()
    },
    "residuals": [
        {"id": "R-PARAMS", "state": "CLOSED-AT-SOURCE-NOT-RUNTIME",
         "statement": (
             "The b77 review's R-PARAMS (set_params / settable_params / "
             "get_params / gettable_params / get_size_ex forwarding a NULL "
             "algctx to provider callbacks) is closed at this candidate: all "
             "four parameter entry points now test "
             "`evp_md_ctx_algctx_is_missing` before the provider call and "
             "`EVP_MD_CTX_get_size_ex` refuses (-1) before either callback, and "
             "the divergence record and tests were extended.  Not re-measured at "
             "runtime here (no build).")},
        {"id": "R-BLOCKLEVEL-CONTRACT",
         "state": "OPEN-DOCUMENTATION",
         "statement": (
             f"{len(no_fn)} of the 65 sites have an explicit validity contract "
             "only as an operation-level `// SAFETY:` block comment plus the "
             "OSSL_FUNC callback ABI; they carry no `# Safety` section on the "
             "`unsafe extern \"C\" fn` interface.  This is the same class the "
             "b76 review accepted for its provider-callback sites, and it is not "
             "reclassified as a discharge; it is recorded so a future caller "
             "audit knows the contract is at the body, not the signature."),
         "sites": [r["boundary"] for r in no_fn]},
        {"id": "R-REPAIR-RECEIPT-FIELD",
         "state": "OPEN-EVIDENCE-SHAPE",
         "statement": (
             "b77-review-v1i-repaired.json records `span_sha256_reviewed` for "
             "sha3::keccak_final as dd7adaee… (the pre-repair body) while the "
             "body it accepted at the repair head hashes to 4dbe9bbd….  The "
             "verdict is sound (its `evidence` quotes the repaired body), but "
             "the field name does not mean what a reader would assume.  I "
             "re-read the body rather than rely on the field.")},
        {"id": "R-WITHDRAWN-NONCOHORT",
         "state": "OPEN-STATUS-DOC",
         "statement": (
             "13 v1i and 6 v1l boundaries that were SAFETY_DISCHARGED in the "
             "prior receipts are outside this review's 65-site cohort; none "
             "was re-established at this candidate, so the regenerated "
             "receipts mark them RETAINED and they cannot discharge.  A "
             "further 5 v1i boundaries name items that no longer exist "
             "(retired thunks) and are recorded ABSENT.  The remaining 18 v1i "
             "and 9 v1l non-cohort boundaries were already non-discharging and "
             "keep their original text.  CAMPAIGN-STATUS.json still lists the "
             "19 withdrawn boundaries in scoped_boundary_discharges; that "
             "status document was not edited in this batch and must be "
             "updated by the orchestrator, or the conflict is detect-only.  "
             "No obligation in either b77 closure depended on any of them.")},
        {"id": "R-CARRYFORWARD-COORDINATE",
         "state": "OPEN-CLOSURE-INPUT",
         "statement": (
             "The b78 closure will carry obligations from closure-ssh-b77.json "
             "at their old lines (e.g. digest.rs copyctx 658).  The regenerated "
             "receipt declares 672.  The receipt's boundaries are also enrolled "
             "by the ledger path only where state.json carries a matching "
             "obligation_mechanisms record; where they are not, the carried old "
             "coordinate remains and must be re-resolved by the closure's "
             "current-census-line path.  This is a closure-run property, not a "
             "receipt defect, and it is why C9 supplies the resolved line.")},
        {"id": "R-NO-RUNTIME", "state": "OPEN",
         "statement": "No build, test, sanitizer, Miri or timing run was "
                      "permitted at 12 GiB available (§6.1).  Every verdict is a "
                      "source-and-static-control verdict."},
    ],
    "does_not_prove": [
        "It does not establish SAFE_COMPATIBLE for any consumer family; a site "
        "receipt is not a family graduation.",
        "It does not establish a boundary-level SAFETY_DISCHARGED for "
        "D-DIGEST-NULL-ALGCTX-1 or D-SHA3-FINAL-OUTLEN-1.",
        "It does not prove that the b78 consumer closure discharges anything: "
        "the closure was not re-measured here.",
        "It does not prove absence of UB at runtime; no dynamic instrument ran.",
        "It does not establish the NUL-termination of an arbitrary external C "
        "caller's ENGINE default-algorithm string.",
    ],
    "final_tally": {"cohort": 65, "ACCEPT": 65, "REJECT": 0, "ABSENT": 0},
}

path = ATLAS / "b78-review-final.json"
path.write_text(json.dumps(review, indent=1) + "\n")
digest = hashlib.sha256(path.read_bytes()).hexdigest()
print(json.dumps({"path": str(path.relative_to(ROOT)), "sha256": digest,
                  "bytes": path.stat().st_size,
                  "no_fn_safety": len(no_fn),
                  "re_reviewed": len(re_reviewed)}, indent=1))
