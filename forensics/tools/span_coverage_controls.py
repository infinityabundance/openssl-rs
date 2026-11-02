#!/usr/bin/env python3
"""Adversarial controls for content-addressed scoped coverage.

Each control mutates one fixture source file, then calls the REAL
``consumer_closure.adjudicate`` path (span masking, qualifier resolution,
recorded-hash comparison).  Nothing here reimplements the adjudicator.

Run from the repository root:

    python3 forensics/tools/span_coverage_controls.py

Exit status is non-zero if any observed result differs from the expectation.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import consumer_closure as cc

MODULE = "//! fixture module documentation { }\n"
DOC = "/// Leading documentation for target.\n"
QUAL = "#[cfg(test)]\n"
TARGET = (
    "pub unsafe fn target(arg: u8) -> u8 {\n"
    "    let _brace = '{';\n"
    "    let _raw = r#\"}\"#;\n"
    "    /* nested /* } */ { */\n"
    "    arg\n"
    "}\n"
)
OTHER = (
    "pub unsafe fn other() -> u8 {\n"
    "    2\n"
    "}\n"
)
BASE = MODULE + DOC + QUAL + TARGET + "\n" + OTHER
TARGET_CLOSE_LINE = 9
SIBLING = (
    "mod a {\n"
    "    pub unsafe fn dupctx() -> u8 { 1 }\n"
    "}\n\n"
    "mod b {\n"
    "    pub unsafe fn dupctx() -> u8 { 2 }\n"
    "}\n"
)
CONSTGEN = (
    "unsafe fn constgen<const N: usize>() -> [u8; {N}] {\n"
    "    let _ = 1;\n"
    "    0\n"
    "}\n"
)
BODYLESS = (
    "trait T {\n"
    "    fn bodyless(&self);\n"
    "}\n\n"
    "fn next() -> u8 {\n"
    "    7\n"
    "}\n"
)
ANGLEBRACE = (
    "unsafe fn angle<const N: usize>() -> W<{N}> {\n"
    "    let _ = 1;\n"
    "    0\n"
    "}\n"
)
UNBOUND = (
    "unsafe fn unbound() -> u8 {\n"
    "    1\n"
    "}\n"
)


def obligation(item="target", line=4, file="src/ctl/lib.rs"):
    return {"file": file, "line": line, "current_census_line": line,
            "mechanism": "EVP_PKEY_PROVIDER", "status": None,
            "discharge_receipt": None, "status_reason": None,
            "kind": "UNSAFE_FN_DEF", "item": item}


def plane():
    return {"mechanism_discharges": {},
            "scoped_boundary_discharges": {
                "CTL-1": {"receipt": "control-fixture"},
                "CTL-SIB": {"receipt": "control-fixture"}},
            "err_scope": {}}


MECHS = {"EVP_PKEY_PROVIDER": {"state": "OWNERSHIP_RECONSTRUCTED"}}
# Test-only: the fixture repository has no candidate commit.  A real closure
# run never passes this; its production path refuses as `span-unbound` instead.
TEST_ONLY_ALLOW_WORKTREE_SPAN = True


def observed(result):
    if result.get("status") == "DISCHARGED":
        return "DISCHARGED", result.get("span_discharge", {})
    rejections = result.get("span_discharge_rejections") or []
    if rejections:
        return rejections[0]["classification"], rejections[0]
    attempts = result.get("scoped_discharge_attempts") or []
    if attempts and not attempts[0].get("identity_match"):
        return "identity-mismatch", attempts[0]
    if result.get("stale_discharge_rejections"):
        return "stale", result["stale_discharge_rejections"][0]
    return str(result.get("status")), {}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fixture", default="court/tmp/span-hash-migration/control-fixture")
    ap.add_argument("--report",
                    default="forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                            "span-coverage-controls.md")
    ap.add_argument("--results",
                    default="court/tmp/span-hash-migration/control-results.json")
    args = ap.parse_args(argv)
    repo = Path(args.fixture).resolve()
    (repo / "src/ctl").mkdir(parents=True, exist_ok=True)
    source = repo / "src/ctl/lib.rs"

    def write(text):
        source.write_text(text)
        cc.clear_span_cache()

    write(BASE)
    base_span = cc.resolve_operation_span(
        repo, "src/ctl/lib.rs", "target", "target",
        allow_worktree=TEST_ONLY_ALLOW_WORKTREE_SPAN)
    base_hash = base_span["sha256"]
    assert base_span["end_line"] == TARGET_CLOSE_LINE, base_span

    def run(item="target", operation="target", digest=base_hash, line=4,
            file="src/ctl/lib.rs"):
        boundary = {
            "id": "CTL-1", "file": file, "kind": "UNSAFE_FN_DEF",
            "operation": operation,
            "disposition": f"SAFETY_DISCHARGED (scope: {file}:1-30)",
            "span_sha256": digest,
            "span_schema": cc.SPAN_HASH_SCHEMA,
        }
        return cc.adjudicate(obligation(item, line=line, file=file), MECHS,
                             [boundary], plane(), repo=repo,
                             allow_worktree_span=TEST_ONLY_ALLOW_WORKTREE_SPAN)

    results = []

    def target_line(item):
        try:
            return cc.resolve_operation_span(
                repo, "src/ctl/lib.rs", item, item,
                allow_worktree=TEST_ONLY_ALLOW_WORKTREE_SPAN)["def_line"]
        except cc.SpanResolutionError:
            return 4

    def control(cid, mutation, expected, mutate, *, item="target",
                span_end=None):
        write(BASE)
        mutate(source)
        cc.clear_span_cache()
        line = target_line(item)
        result = run(item=item, line=line)
        cls, detail = observed(result)
        # Report the span the resolver actually found, even when the hash
        # refuses it; None means the span itself was unparsable/ambiguous.
        try:
            end = cc.resolve_operation_span(
                repo, "src/ctl/lib.rs", item, item,
                allow_worktree=TEST_ONLY_ALLOW_WORKTREE_SPAN)["end_line"]
        except cc.SpanResolutionError:
            end = None
        ok = expected(cls) and (span_end is None or end == span_end)
        results.append({"control": cid, "mutation": mutation,
                        "observed": cls, "span_end": end,
                        "pass": bool(ok),
                        "detail": detail.get("detail") if isinstance(detail, dict) else None})
        return ok

    def expect(cls):
        return lambda got: got == cls

    # (a) one code line inside the discharged operation
    control("a", "change one body line (`arg` -> `arg + 1`)",
            expect("span-hash-mismatch"),
            lambda src: src.write_text(BASE.replace("    arg\n}", "    arg + 1\n}")))

    # (b) comments inserted above the operation
    control("b", "insert ordinary comments above the operation",
            expect("DISCHARGED"),
            lambda src: src.write_text("// inserted comment\n// second comment\n" + BASE))
    control("b2", "insert a documentation comment above the operation",
            expect("DISCHARGED"),
            lambda src: src.write_text("/// inserted documentation comment\n" + BASE))

    # (c) reorder two untouched operations (decision: ACCEPT)
    control("c", "move `other` above `target` (content unchanged; decision: ACCEPT)",
            expect("DISCHARGED"),
            lambda src: src.write_text(MODULE + "\n" + OTHER + "\n" + DOC + QUAL + TARGET))

    # (d) rename the operation; the census identity changes with it
    control("d", "rename `target` -> `target_renamed` (census item follows)",
            expect("identity-mismatch"), item="target_renamed",
            mutate=lambda src: src.write_text(BASE.replace("fn target", "fn target_renamed")))

    # (e) change the operation's qualifier / cfg attribute
    control("e", "change `#[cfg(test)]` and `pub` -> `pub(crate)`",
            expect("span-hash-mismatch"),
            lambda src: src.write_text(
                BASE.replace("#[cfg(test)]", "#[cfg(all())]")
                    .replace("pub unsafe fn target", "pub(crate) unsafe fn target")))

    # (f) edit the excluded leading doc comment (decision: ACCEPT)
    control("f", "edit the excluded leading `///` doc comment (decision: ACCEPT)",
            expect("DISCHARGED"),
            lambda src: src.write_text(BASE.replace(
                "/// Leading documentation for target.",
                "/// Changed documentation, still outside the span.")))

    # (g) duplicate identity collision
    control("g", "add a second unqualified `fn target`",
            expect("ambiguous-identity"),
            lambda src: src.write_text(BASE + "\npub unsafe fn target(x: u8) -> u8 { x }\n"))

    # (h) braces inside char literals, raw strings and nested comments
    control("h1", "span already contains '{', r#\"}\"#, and a nested comment",
            expect("DISCHARGED"), lambda src: None, span_end=TARGET_CLOSE_LINE)
    control("h2", "insert `b'}'` into the body (span must not mis-close)",
            expect("span-hash-mismatch"),
            lambda src: src.write_text(BASE.replace(
                "    arg\n}", "    let _extra = b'}';\n    arg\n}")),
            span_end=TARGET_CLOSE_LINE + 1)

    # (i) whitespace-only reformat inside the body
    control("i", "change indentation of one body line (expected cost: REFUSE)",
            expect("span-hash-mismatch"),
            lambda src: src.write_text(BASE.replace("    arg\n}", "        arg\n}")))

    # (j) negative control: untouched operation
    control("j", "untouched discharged operation",
            expect("DISCHARGED"), lambda src: None)

    # Sibling control: a::dupctx is discharged; b::dupctx is a same-file
    # operation with the same last component.  The boundary must not discharge
    # the sibling, and editing the sibling must not disturb a::dupctx.
    sibling = repo / "src/ctl/sibling.rs"

    def sibling_run(ob_item, ob_line, digest):
        boundary = {
            "id": "CTL-SIB", "file": "src/ctl/sibling.rs",
            "kind": "UNSAFE_FN_DEF", "operation": "a::dupctx",
            "disposition": "SAFETY_DISCHARGED (scope: src/ctl/sibling.rs:1-30)",
            "span_sha256": digest,
            "span_schema": cc.SPAN_HASH_SCHEMA,
        }
        return cc.adjudicate(
            obligation(ob_item, line=ob_line, file="src/ctl/sibling.rs"),
            MECHS, [boundary], plane(), repo=repo,
            allow_worktree_span=TEST_ONLY_ALLOW_WORKTREE_SPAN)

    def sibling_control(cid, mutation, expected, ob_item, ob_line, mutate):
        sibling.write_text(SIBLING)
        cc.clear_span_cache()
        digest = cc.resolve_operation_span(
            repo, "src/ctl/sibling.rs", "a::dupctx", "dupctx",
            allow_worktree=TEST_ONLY_ALLOW_WORKTREE_SPAN)["sha256"]
        mutate(sibling)
        cc.clear_span_cache()
        result = sibling_run(ob_item, ob_line, digest)
        cls, detail = observed(result)
        ok = expected(cls)
        results.append({"control": cid, "mutation": mutation,
                        "observed": cls, "span_end": None,
                        "pass": bool(ok),
                        "detail": detail.get("detail") if isinstance(detail, dict) else None})

    sibling_control("s1", "boundary a::dupctx against sibling b::dupctx",
                    expect("ambiguous-identity"), "dupctx", 6,
                    lambda src: None)
    sibling_control("s2", "edit b::dupctx body, then test b against a::dupctx",
                    expect("ambiguous-identity"), "dupctx", 6,
                    lambda src: src.write_text(SIBLING.replace("{ 2 }", "{ 3 }")))
    sibling_control("s3", "edit b::dupctx body, then test a against a::dupctx",
                    expect("DISCHARGED"), "dupctx", 2,
                    lambda src: src.write_text(SIBLING.replace("{ 2 }", "{ 3 }")))

    # Const-generic body-brace control: the `{N}` in `[u8; {N}]` is not the body.
    constgen = repo / "src/ctl/constgen.rs"
    constgen.write_text(CONSTGEN)
    cc.clear_span_cache()
    constgen_hash = cc.resolve_operation_span(
        repo, "src/ctl/constgen.rs", "constgen", "constgen",
        allow_worktree=TEST_ONLY_ALLOW_WORKTREE_SPAN)["sha256"]
    constgen.write_text(CONSTGEN.replace("let _ = 1;", "let _ = 2;"))
    cc.clear_span_cache()
    constgen_boundary = {
        "id": "CTL-1", "file": "src/ctl/constgen.rs",
        "kind": "UNSAFE_FN_DEF", "operation": "constgen",
        "disposition": "SAFETY_DISCHARGED (scope: src/ctl/constgen.rs:1-10)",
        "span_sha256": constgen_hash, "span_schema": cc.SPAN_HASH_SCHEMA,
    }
    constgen_result = cc.adjudicate(
        obligation("constgen", line=1, file="src/ctl/constgen.rs"),
        MECHS, [constgen_boundary], plane(), repo=repo,
        allow_worktree_span=TEST_ONLY_ALLOW_WORKTREE_SPAN)
    cg_cls, _ = observed(constgen_result)
    try:
        cg_end = cc.resolve_operation_span(
            repo, "src/ctl/constgen.rs", "constgen", "constgen",
            allow_worktree=TEST_ONLY_ALLOW_WORKTREE_SPAN)["end_line"]
    except cc.SpanResolutionError:
        cg_end = None
    results.append({"control": "constgen",
                    "mutation": "edit body of `[u8; {N}]` function after signature",
                    "observed": cg_cls, "span_end": cg_end,
                    "pass": bool(cg_cls == "span-hash-mismatch" and cg_end == 4),
                    "detail": None})

    # Bodyless trait method: no body brace; must refuse, never extend to `next`.
    bodyless = repo / "src/ctl/bodyless.rs"
    bodyless.write_text(BODYLESS)
    cc.clear_span_cache()
    bodyless_boundary = {
        "id": "CTL-1", "file": "src/ctl/bodyless.rs",
        "kind": "UNSAFE_FN_DEF", "operation": "bodyless",
        "disposition": "SAFETY_DISCHARGED (scope: src/ctl/bodyless.rs:1-10)",
        "span_sha256": "0" * 64, "span_schema": cc.SPAN_HASH_SCHEMA,
    }
    bodyless_result = cc.adjudicate(
        obligation("bodyless", line=2, file="src/ctl/bodyless.rs"),
        MECHS, [bodyless_boundary], plane(), repo=repo,
        allow_worktree_span=TEST_ONLY_ALLOW_WORKTREE_SPAN)
    bl_cls, _ = observed(bodyless_result)
    results.append({"control": "bodyless",
                    "mutation": "bodyless trait method `fn bodyless(&self);`",
                    "observed": bl_cls, "span_end": None,
                    "pass": bool(bl_cls == "span-unparsable"),
                    "detail": None})

    # Angle-bracket const expression in the return type: `<{` refuses.
    angle = repo / "src/ctl/anglebrace.rs"
    angle.write_text(ANGLEBRACE)
    cc.clear_span_cache()
    angle_boundary = {
        "id": "CTL-1", "file": "src/ctl/anglebrace.rs",
        "kind": "UNSAFE_FN_DEF", "operation": "angle",
        "disposition": "SAFETY_DISCHARGED (scope: src/ctl/anglebrace.rs:1-10)",
        "span_sha256": "0" * 64, "span_schema": cc.SPAN_HASH_SCHEMA,
    }
    angle_result = cc.adjudicate(
        obligation("angle", line=1, file="src/ctl/anglebrace.rs"),
        MECHS, [angle_boundary], plane(), repo=repo,
        allow_worktree_span=TEST_ONLY_ALLOW_WORKTREE_SPAN)
    ang_cls, _ = observed(angle_result)
    results.append({"control": "anglebrace",
                    "mutation": "return type `W<{N}>` before the body",
                    "observed": ang_cls, "span_end": None,
                    "pass": bool(ang_cls == "span-unparsable"),
                    "detail": None})

    # No bound source commit: content path must refuse, never read the worktree.
    unbound = repo / "src/ctl/unbound.rs"
    unbound.write_text(UNBOUND)
    cc.clear_span_cache()
    unbound_hash = cc.resolve_operation_span(
        repo, "src/ctl/unbound.rs", "unbound", "unbound",
        allow_worktree=TEST_ONLY_ALLOW_WORKTREE_SPAN)["sha256"]
    stripped = cc.span_source_commit({"identity": {}}, repo)
    saved_commit = cc._EVIDENCE_ENV.get("source_commit")
    cc._EVIDENCE_ENV["source_commit"] = stripped
    unbound_boundary = {
        "id": "CTL-1", "file": "src/ctl/unbound.rs",
        "kind": "UNSAFE_FN_DEF", "operation": "unbound",
        "disposition": "SAFETY_DISCHARGED (scope: src/ctl/unbound.rs:1-10)",
        "span_sha256": unbound_hash, "span_schema": cc.SPAN_HASH_SCHEMA,
    }
    unbound_result = cc.adjudicate(
        obligation("unbound", line=1, file="src/ctl/unbound.rs"),
        MECHS, [unbound_boundary], plane(), repo=repo,
        allow_worktree_span=False)
    cc._EVIDENCE_ENV["source_commit"] = saved_commit
    un_cls, _ = observed(unbound_result)
    results.append({"control": "unbound",
                    "mutation": "fixture inventory has no identity.source_head",
                    "observed": un_cls, "span_end": None,
                    "pass": bool(stripped is None and un_cls == "span-unbound"),
                    "detail": None})

    report = Path(args.report)
    report.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Content-addressed scoped coverage controls", "",
             "Fixture: `src/ctl/lib.rs` and `src/ctl/sibling.rs`; predicate: "
             "fully-qualified identity AND the obligation bound to the "
             "boundary's resolved span (same definition, equal qualified "
             "identity, or census line inside the span) AND the recorded span "
             "hash equals the current span hash. The harness calls the real "
             "`consumer_closure.adjudicate` path.", "",
             "| control | mutation | observed | span end | PASS |",
             "|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r['control']} | {r['mutation']} | {r['observed']} | "
                     f"{r['span_end']} | {'PASS' if r['pass'] else 'FAIL'} |")
    lines += [
        "", "## Decisions and expected costs", "",
        "- (c) **ACCEPT.** Content addressing is coordinate-independent: moving "
        "an untouched operation changes neither its identity nor its span text, "
        "so the same recorded hash still matches. This is the intended change "
        "from coordinate coverage.",
        "- (f) **ACCEPT.** A leading `///`, `//!`, or `/** */` doc comment is "
        "excluded by condition 1. The receipt's `contract`/`established` "
        "fields are the recorded contract claim; neither those fields nor the "
        "migration map is changed by a source doc-comment edit.",
        "- (g) **REFUSE as `ambiguous-identity`.** A duplicate last component "
        "is reported as the existing `scope_item` collision class. A real "
        "receipt's own qualifier (`sha1::dupctx`) may resolve exactly one "
        "definition; that is a tightening, never a broadening. In the b51b "
        "migration, 37 collisions resolve this way and no unqualified "
        "collision is accepted.",
        "- (h) **Span stays exact.** `'{'`, `b'{'`, `r#\"...\"#`, `br#\"...\"#`, "
        "escaped strings, and nested `/* */` comments are masked before brace "
        "matching. New literal-brace content changes the hash, so the refusal "
        "is `span-hash-mismatch`, never a guessed span or `span-unparsable`.",
        "- (i) **Expected cost: REFUSE.** Internal whitespace reformat (for "
        "example an indentation change) changes the normalised span text and "
        "is refused fail-closed. Trailing whitespace alone is normalised away "
        "and does not change the hash.",
        "- (s1/s2/s3) **Sibling binding.** `a::dupctx` and `b::dupctx` share "
        "the last component. A boundary naming `a::dupctx` refuses the "
        "`b::dupctx` obligation (`ambiguous-identity`) even when its declared "
        "range covers the sibling's line. Editing `b::dupctx`'s body neither "
        "discharges `b` nor changes `a`'s disposition (`s3` still discharges).",
        "- (constgen) **Body brace at depth 0.** The `{N}` in `[u8; {N}]` is "
        "inside brackets and is not the body; the real body is hashed. Editing "
        "the body changes the hash (`span-hash-mismatch`).",
        "- (bodyless) **No body, no guess.** `fn bodyless(&self);` reaches a "
        "top-level `;` before any `{` and is refused as `span-unparsable`; it "
        "never extends to the next item.",
        "- (anglebrace) **`<{` is refused.** A return type `W<{N}>` contains "
        "`<` immediately followed by `{` before the body; the resolver refuses "
        "as `span-unparsable` rather than guessing an angle-bracket depth.",
        "- (unbound) **No worktree fallback.** With a fixture inventory lacking "
        "`identity.source_head`, `span_source_commit` returns None and the "
        "content path refuses as `span-unbound`; the matching hash on disk is "
        "not read. The harness opts into worktree reads only via the test-only "
        "`allow_worktree_span` flag (never set by a real closure run).",
        "", "Command:", "", "```",
        "python3 forensics/tools/span_coverage_controls.py", "```"]
    report.write_text("\n".join(lines) + "\n")
    Path(args.results).write_text(json.dumps(results, indent=1) + "\n")

    for r in results:
        print(f"{r['control']}: {r['observed']} (span_end={r['span_end']}) "
              f"{'PASS' if r['pass'] else 'FAIL'}")
    failed = [r for r in results if not r["pass"]]
    print(f"[controls] {len(results) - len(failed)}/{len(results)} PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
