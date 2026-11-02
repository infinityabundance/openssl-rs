# Content-addressed scoped coverage controls

Fixture: `src/ctl/lib.rs` and `src/ctl/sibling.rs`; predicate: fully-qualified identity AND the obligation bound to the boundary's resolved span (same definition, equal qualified identity, or census line inside the span) AND the recorded span hash equals the current span hash. The harness calls the real `consumer_closure.adjudicate` path.

| control | mutation | observed | span end | PASS |
|---|---|---|---|---|
| a | change one body line (`arg` -> `arg + 1`) | span-hash-mismatch | 9 | PASS |
| b | insert ordinary comments above the operation | DISCHARGED | 11 | PASS |
| b2 | insert a documentation comment above the operation | DISCHARGED | 10 | PASS |
| c | move `other` above `target` (content unchanged; decision: ACCEPT) | DISCHARGED | 14 | PASS |
| d | rename `target` -> `target_renamed` (census item follows) | identity-mismatch | 9 | PASS |
| e | change `#[cfg(test)]` and `pub` -> `pub(crate)` | span-hash-mismatch | 9 | PASS |
| f | edit the excluded leading `///` doc comment (decision: ACCEPT) | DISCHARGED | 9 | PASS |
| g | add a second unqualified `fn target` | ambiguous-identity | None | PASS |
| h1 | span already contains '{', r#"}"#, and a nested comment | DISCHARGED | 9 | PASS |
| h2 | insert `b'}'` into the body (span must not mis-close) | span-hash-mismatch | 10 | PASS |
| i | change indentation of one body line (expected cost: REFUSE) | span-hash-mismatch | 9 | PASS |
| j | untouched discharged operation | DISCHARGED | 9 | PASS |
| s1 | boundary a::dupctx against sibling b::dupctx | ambiguous-identity | None | PASS |
| s2 | edit b::dupctx body, then test b against a::dupctx | ambiguous-identity | None | PASS |
| s3 | edit b::dupctx body, then test a against a::dupctx | DISCHARGED | None | PASS |
| constgen | edit body of `[u8; {N}]` function after signature | span-hash-mismatch | 4 | PASS |
| bodyless | bodyless trait method `fn bodyless(&self);` | span-unparsable | None | PASS |
| anglebrace | return type `W<{N}>` before the body | span-unparsable | None | PASS |
| unbound | fixture inventory has no identity.source_head | span-unbound | None | PASS |

## Decisions and expected costs

- (c) **ACCEPT.** Content addressing is coordinate-independent: moving an untouched operation changes neither its identity nor its span text, so the same recorded hash still matches. This is the intended change from coordinate coverage.
- (f) **ACCEPT.** A leading `///`, `//!`, or `/** */` doc comment is excluded by condition 1. The receipt's `contract`/`established` fields are the recorded contract claim; neither those fields nor the migration map is changed by a source doc-comment edit.
- (g) **REFUSE as `ambiguous-identity`.** A duplicate last component is reported as the existing `scope_item` collision class. A real receipt's own qualifier (`sha1::dupctx`) may resolve exactly one definition; that is a tightening, never a broadening. In the b51b migration, 37 collisions resolve this way and no unqualified collision is accepted.
- (h) **Span stays exact.** `'{'`, `b'{'`, `r#"..."#`, `br#"..."#`, escaped strings, and nested `/* */` comments are masked before brace matching. New literal-brace content changes the hash, so the refusal is `span-hash-mismatch`, never a guessed span or `span-unparsable`.
- (i) **Expected cost: REFUSE.** Internal whitespace reformat (for example an indentation change) changes the normalised span text and is refused fail-closed. Trailing whitespace alone is normalised away and does not change the hash.
- (s1/s2/s3) **Sibling binding.** `a::dupctx` and `b::dupctx` share the last component. A boundary naming `a::dupctx` refuses the `b::dupctx` obligation (`ambiguous-identity`) even when its declared range covers the sibling's line. Editing `b::dupctx`'s body neither discharges `b` nor changes `a`'s disposition (`s3` still discharges).
- (constgen) **Body brace at depth 0.** The `{N}` in `[u8; {N}]` is inside brackets and is not the body; the real body is hashed. Editing the body changes the hash (`span-hash-mismatch`).
- (bodyless) **No body, no guess.** `fn bodyless(&self);` reaches a top-level `;` before any `{` and is refused as `span-unparsable`; it never extends to the next item.
- (anglebrace) **`<{` is refused.** A return type `W<{N}>` contains `<` immediately followed by `{` before the body; the resolver refuses as `span-unparsable` rather than guessing an angle-bracket depth.
- (unbound) **No worktree fallback.** With a fixture inventory lacking `identity.source_head`, `span_source_commit` returns None and the content path refuses as `span-unbound`; the matching hash on disk is not read. The harness opts into worktree reads only via the test-only `allow_worktree_span` flag (never set by a real closure run).

Command:

```
python3 forensics/tools/span_coverage_controls.py
```
