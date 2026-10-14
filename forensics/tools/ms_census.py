#!/usr/bin/env python3
"""openssl-rs — the compiler-backed source census (Phase 25.1).

Phase 25 is the memory-safety stratum. Its **primary unit is a compiler-derived unsafe
operation**: one operation the compiler establishes, at a file/line/column, with the
toolchain that derived it. A regular-expression scan or a text grep is a *projection* of the
source, not the source's unsafe operations, so it is never the unit
(`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` section 3.1). This tool is 25.1: it builds the
census of the candidate's unsafe operations the honest (compiler-backed) way and writes
`artifacts/phase25/source-census.json`.

What is the authority, and why not the three lints alone
-------------------------------------------------------
The three lints the brief names -- `clippy::undocumented_unsafe_blocks`, the rustc lint
`unsafe_op_in_unsafe_fn` and `clippy::missing_safety_doc` -- are **documentation** checks: each
reports an unsafe construct that *lacks* something. The copy of this crate on the branch is
deliberately clean under all three (`Cargo.toml` sets `unsafe_op_in_unsafe_fn = "deny"` and
`undocumented_unsafe_blocks = "deny"`, so the crate would not build otherwise), which means on a
clean crate they report **nothing** and cannot enumerate a census. The enumerating authority is
the compiler's built-in `unsafe_code` lint -- it fires on **every** `unsafe` construct, so it is
the compiler's own list of where unsafe code is -- and clippy runs it post-expansion, with
macro-expansion-aware spans and `expansion` provenance. So this tool runs one clippy invocation
with all four lints as warnings and `--message-format=json`, and:

  * `unsafe_code` is the **authority for which unsafe contexts exist** (one diagnostic per
    construct); the three named lints are the authority for whether each context is
    **documented** -- they producing nothing is itself the recorded fact that the crate is
    documentation-clean, and a context that regressed would appear here as a diagnostic;
  * a purpose-built tokenizer over the compiler's own span text **enumerates each unsafe
    operation inside the context** -- one site per raw dereference, unsafe/extern call, method
    call, static access, pointer read/write, transmute, inline asm and so on -- against
    `memory_safety_schemas.UNSAFE_OPERATION_KINDS`. The compiler establishes the context and its
    span; the enumerator gives each operation in it its own span and its own stable `site_id`,
    while the enclosing `context_id` still names the compiler-identified context it sits in
    (never a bare regex over the raw file). The older context-level kind-set classifier is kept
    **unchanged** as an independent cross-check.

The macro-expanded source
-------------------------
The census is complete only over the **macro-expanded** crate, and clippy lints post-expansion, so
the census is the expanded crate's. To make that explicit and reproducible this tool additionally
installs a **pinned nightly** (`nightly-2026-10-01`, recorded with its rustc commit hash), emits
the macro-expanded crate source (`cargo +nightly-... rustc -- -Zunpretty=expanded`), and
content-hashes it into `inputs[]`. The expanded source is not committed (it is ~34 MB and
reproducible from the pinned toolchain); its digest and the toolchain identity are. If the pinned
nightly cannot be installed, the tool records that as an explicit limitation and falls back to the
clippy-JSON contexts plus the whole-tree lexical scan -- it never silently skips expansion.

An honest limitation, recorded not hidden: the operation *kind* is a classification, not a
compiler fact. The compiler establishes that the context exists; the tokenizer assigns the kind and
records `classification_method` on the site. The kind is therefore a secondary label on a
compiler-established unit, and `sites[].classification_method` says so on every row.

Why the operation extractor is the compiler-anchored span scan, not a raw HIR/MIR dump
-------------------------------------------------------------------------------------
The primary unit is a *compiler-derived* operation, so a HIR/MIR-backed enumerator was
investigated first, with the pinned nightly, before this extractor was chosen. The choice is a
measured one and is recorded rather than hidden:

  * `-Zunpretty=hir-tree` and `-Zunpretty=thir-tree` are **not reproducible at this crate's
    scale**. Emitting either for the lib aborts inside the compiler with
    `memory allocation of 2147483648 bytes failed` (hir-tree) / `memory allocation of 1207468032
    bytes failed` (thir-tree): the trees carry a fully-typed, span-annotated copy of every
    expression, which the 32 MB crate projects beyond the venue's per-process budget. The 450-byte
    probe used to prototype the formats expands ~194x for thir-tree, so the projection is gigabytes.
  * `-Zunpretty=mir -Zmir-include-spans` *is* producible (measured: 4,922,910 lines / 364 MB) and
    its per-operation spans align with the compiler's own `unsafe_code` context spans, including
    macro-expanded spans (both point at the macro definition body). But MIR is post-desugaring: a
    method call and a free-function call print identically, a union field access is not labelled
    as one, `ptr::read`/`read_unaligned`/`assert_unchecked` are indistinguishable from any other
    call, and the debug null-check instrumentation duplicates each raw dereference as a chain of
    `PtrToPtr`/`Transmute`/assert statements that share the dereference's span. Reconstructing the
    census's operation vocabulary from MIR would be a heuristic layer, not a compiler fact.

So the operation-level extractor is the compiler-anchored span scan: the compiler (the built-in
`unsafe_code` lint) establishes each unsafe context and its exact span, and the scan enumerates
the **distinct operations inside that compiler-established span**, each with its own span and
stable id. Every site records `classification_method` (the method that produced it), the compiler
context it belongs to, and the operation's own span; the `rule` records this decision and the
`crosschecks` reconcile it against the unchanged context-level classifier.

LOC is a secondary projection
-----------------------------
`rust_physical_loc`, `rust_code_loc`, `safe_rust_code_loc` and `unsafe_context_code_loc` are
computed here, but `unsafe_context_code_loc` is the union of the **compiler-identified unsafe
context spans** (so the split is the compiler's, not a guess) and the whole projection is a
**secondary** view of the census, never a safety claim. `docs/UNSAFE.md` and
`docs/NON_CLAIMS.md` are the authorities on what may be said.

Outputs
-------
  artifacts/phase25/source-census.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_bytes,
    sha256_file,
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`: this tool runs the
# compiler, so the manifest does not list it `metadata_only` and a host invocation is refused.
import phase25_guard  # noqa: E402

# The record kinds and their closed vocabularies. Imported, never restated, so the census cannot
# drift from the schema the court validates it against.
import memory_safety_schemas as schemas  # noqa: E402

# The lexical scanner whose `code_only` defines "code" for the secondary LOC projection and the
# source-lexical cross-check. Reused rather than re-implemented so the two cannot disagree.
import unsafe_footprint as lexical  # noqa: E402

# The lossless columnar encoding the Phase-25 artefacts are stored in. Every reader
# (this tool, the derived planes and the courts) decodes through it, so the scheme has
# exactly one implementation.
import ms_codec  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"
GENERATOR = "forensics/tools/ms_census.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_census.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
CARGO_TOML = REPO_ROOT / "Cargo.toml"
BUILD_RS = REPO_ROOT / "build.rs"
TOOLCHAIN_FILE = REPO_ROOT / "rust-toolchain.toml"
SRC = REPO_ROOT / "src"
TESTS = REPO_ROOT / "tests"

# Scratch, under the gitignored `/work` tree the brief mandates. The tool refuses on the host, so
# this path only ever exists inside the court.
WORK = Path("/work/court/p25")

# The pinned nightly used to emit the macro-expanded source. The date pins the toolchain; the
# commit hash is recorded in the census so the expansion basis is a fact, not a hope.
NIGHTLY = "nightly-2026-10-01"
NIGHTLY_HOME = "/work/.phase25-rustup"
NIGHTLY_CARGO_HOME = "/work/.phase25-cargo"

# The build/compiler identity stamped on every site. `compiler` is a string on the schema, so the
# exact toolchain is recorded here rather than re-typed per row, and the per-row value is the same
# string so a row read alone still names its toolchain.
COMPILER_CLAUSE = "rustc-1.98.1+clippy-0.1.98"

# The three lints the brief names, plus the enumerating lint. Recorded so the invocation is
# auditable and the census can state which lints each context was reported by.
AUTHORITY_LINTS = (
    "unsafe_code",
    "clippy::undocumented_unsafe_blocks",
    "clippy::missing_safety_doc",
    "unsafe_op_in_unsafe_fn",
)

# The compiler's own message -> the record's context kind (a closed vocabulary in the schema).
MESSAGE_CONTEXT_KIND: dict[str, str] = {
    "usage of an `unsafe` block": "UNSAFE_BLOCK",
    "declaration of an `unsafe` function": "UNSAFE_FN",
    "declaration of an `unsafe` method": "UNSAFE_FN",
    "implementation of an `unsafe` method": "UNSAFE_FN",
    "implementation of an `unsafe` trait": "UNSAFE_IMPL",
    "usage of an `unsafe extern` block": "EXTERN_BLOCK",
    "usage of the unsafe `#[no_mangle]` attribute": "FFI_EXPORT_FN",
    "usage of the unsafe `#[export_name]` attribute": "FFI_EXPORT_FN",
}

# Context kinds whose operation is fixed by the construct itself (the tokenizer does not have to
# find it): an `unsafe impl` is the `UNSAFE_IMPL` operation, an exported symbol is `FFI_EXPORT`, an
# `unsafe extern` block is where an `EXTERN_FUNCTION_CALL` resolves.
FIXED_OPERATION_KIND: dict[str, str] = {
    "UNSAFE_IMPL": "UNSAFE_IMPL",
    "FFI_EXPORT_FN": "FFI_EXPORT",
    "EXTERN_BLOCK": "EXTERN_FUNCTION_CALL",
}

# The priority order in which the tokenizer's findings become a single `operation_kind`. The most
# specific/LOAD-BEARING operation a context performs is the one the site names; the full set is
# kept in `operation_kinds` so nothing found is dropped.
KIND_PRIORITY = (
    "INLINE_ASM",
    "TRANSMUTE",
    "ASSERT_UNCHECKED",
    "C_VARIADIC_BOUNDARY",
    "RAW_POINTER_WRITE",
    "RAW_POINTER_READ",
    "UNION_FIELD_ACCESS",
    "STATIC_MUT_ACCESS",
    "RAW_POINTER_DEREFERENCE",
    "UNSAFE_METHOD_CALL",
    "UNSAFE_FUNCTION_CALL",
)

# The placeholder a context carries when the compiler reports sites in it but the source states no
# `SAFETY:` contract there. It is non-empty (the schema refuses a context with sites and no
# contract) and clearly labelled, and its count is a recorded finding rather than a silent pass.
UNCONTRACTED = "(no SAFETY contract in source; recorded open for 25.3)"

# The non-claims every Phase-25 artefact carries. Verbatim from
# docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md section 0.
NON_CLAIMS = (
    "safe Rust does not prove protocol correctness: memory safety is not behavioural correctness",
    "unsafe Rust is not inherently vulnerable: an unsafe operation with a discharged contract is "
    "sound, so an unsafe site is not a defect",
    "unsafe LOC is not a vulnerability count: lines of unsafe code are a secondary projection of "
    "the compiler-derived census, and a count is not a risk",
    "the operation kind is a classification on a compiler-established context, not a compiler "
    "fact; the site records the classification method",
    "`exposure_class` and `risk_tier` are provisional placeholders in this census "
    "(INTERNAL_REACHABLE / S4, the over-stating-reachability direction); the exposure/data-flow "
    "classification is 25.7's measurement, not this subphase's claim",
    "the census is not exhaustive of runtime reachability: it inventories the shipped surface, "
    "and reachability is 25.5/25.7's measurement",
)

# --------------------------------------------------------------------------------------------
# the shipped first-party surface: what "every file accounted for" means
# --------------------------------------------------------------------------------------------

# The config manifests that are build inputs to the shipped crate.
CONFIG_FILES = (CARGO_TOML,)

_GENERATED = re.compile(r"(?i)do not edit")
_RUST_SOURCE_KINDS = {"RUST_SOURCE"}


def _is_generated(text: str) -> bool:
    """Whether a source file declares itself generated, from its own header.

    A generated file says so in its first lines ("Generated by ... do not edit." or "... —
    GENERATED, do not edit."). Requiring both a `generated` mention and `do not edit` inside the
    first three lines keeps a hand-written file whose prose merely mentions generation from being
    misclassified.
    """
    head = "\n".join(text.splitlines()[:3])
    return bool(_GENERATED.search(head)) and "generat" in head.lower()


def shipped_surface() -> list[dict]:
    """The shipped first-party source/build files, each with its kind and origin.

    Deterministic: the files are walked in sorted order. `origin` is `GENERATED` for a file that
    declares itself generated and `FIRST_PARTY` otherwise; a generated file is still first-party
    (it ships), and the boundary is recorded rather than implied.
    """
    out: list[dict] = []

    def add(path: Path, kind: str) -> None:
        relpath = path.relative_to(REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        origin = "GENERATED" if kind == "RUST_SOURCE" and _is_generated(text) else "FIRST_PARTY"
        out.append({"path": relpath, "kind": kind, "origin": origin, "abs": path})

    for path in sorted(SRC.rglob("*.rs")):
        add(path, "RUST_SOURCE")
    for path in sorted(SRC.rglob("*.c")):
        add(path, "C_SOURCE")
    for path in sorted(TESTS.rglob("*.rs")):
        add(path, "RUST_SOURCE")
    if BUILD_RS.is_file():
        add(BUILD_RS, "BUILD_SCRIPT")
    for path in CONFIG_FILES:
        if path.is_file():
            add(path, "CONFIG")
    if TOOLCHAIN_FILE.is_file():
        add(TOOLCHAIN_FILE, "CONFIG")
    return out


LANGUAGE_BY_KIND = {
    "RUST_SOURCE": "rust",
    "C_SOURCE": "c",
    "C_HEADER": "c",
    "ASM_SOURCE": "asm",
    "BUILD_SCRIPT": "rust",
    "GENERATED_BINDING": "rust",
    "CONFIG": "toml",
    "OTHER": "other",
}


# --------------------------------------------------------------------------------------------
# the tokenizer: classify the operation(s) inside a compiler-identified context
# --------------------------------------------------------------------------------------------

_RAW_STRING = re.compile(r"(?:br|rb|r)(#{0,255})\"")
_LIFETIME = re.compile(r"'[A-Za-z_][A-Za-z0-9_]*")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUM = re.compile(r"(?:0[xX][0-9a-fA-F_]+|[0-9][0-9_]*)")
_OPS = (
    "::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "..=", "...", "..",
    "(", ")", "{", "}", "[", "]", ",", ";", ":", ".", "*", "&", "|", "!", "+", "-", "/", "%",
    "<", ">", "=", "@", "?", "~", "^",
)
# Token values after which a `*` is a prefix dereference rather than a multiplication.
_PREFIX_OK = frozenset({
    "(", ",", "=", ";", "{", "}", "&", "!", "=>", ":", "+", "-", "*", "/", "%", "<", ">",
    "|", "^", "[", "return", "match", "if", "while", "for", "in", "as", "?", "~", "@",
})
_CALL_KEYWORDS = frozenset({"if", "while", "for", "match", "loop", "return", "fn", "let", "in"})
_WRITE_METHODS = frozenset({"write", "write_bytes", "write_unaligned", "write_volatile"})
_READ_METHODS = frozenset({"read", "read_unaligned", "read_volatile"})
_ASM_MACROS = frozenset({"asm", "global_asm", "naked_asm", "llvm_asm"})
_UNCHECKED = frozenset({"assert_unchecked", "unreachable_unchecked"})


def tokenize(text: str) -> list[tuple[str, str, int, int]]:
    """A minimal Rust lexer: `(kind, value, start, end)` for every significant token.

    Comments and whitespace are dropped; string/char literals collapse to one `lit` token (their
    content is never a construct); lifetimes are their own token so the char-literal branch does
    not eat them. `start`/`end` are **character** offsets into `text` (the caller maps them to
    file bytes); the operation enumerator needs them so every operation can carry its own span.
    This is a scanner, not a parser, and is documented as such -- it is scoped to a single
    compiler-identified context span, never run over a whole file.
    """
    out: list[tuple[str, str, int, int]] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if text.startswith("/*", i):
            depth, j = 0, i
            while j < n:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                else:
                    j += 1
            i = j
            continue
        m = _RAW_STRING.match(text, i)
        if m is not None:
            term = '"' + m.group(1)
            e = text.find(term, m.end())
            i = n if e < 0 else e + len(term)
            out.append(("lit", "", m.start(), i))
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(("lit", "", i, j))
            i = j
            continue
        if c == "'":
            if i + 2 < n and (text[i + 2] == "'" or text[i + 1] == "\\"):
                j = i + 1
                while j < n and text[j] != "'":
                    j += 2 if (text[j] == "\\" and j + 1 < n) else 1
                end = min(j + 1, n)
                out.append(("lit", "", i, end))
                i = end
                continue
            m = _LIFETIME.match(text, i)
            if m is not None:
                out.append(("lifetime", m.group(0), m.start(), m.end()))
                i = m.end()
                continue
            i += 1
            continue
        m = _IDENT.match(text, i)
        if m is not None:
            out.append(("id", m.group(0), m.start(), m.end()))
            i = m.end()
            continue
        m = _NUM.match(text, i)
        if m is not None:
            out.append(("num", m.group(0), m.start(), m.end()))
            i = m.end()
            continue
        for op in _OPS:
            if text.startswith(op, i):
                out.append(("op", op, i, i + len(op)))
                i += len(op)
                break
        else:
            i += 1
    return out


def classify_operations(toks: list[tuple[str, str, int, int]]) -> list[str]:
    """The unsafe-operation kinds present in a token stream, from `UNSAFE_OPERATION_KINDS`.

    This is the **context-level** classifier: it answers *which* kinds appear in a context, and it
    is kept unchanged as the independent cross-check the operation-level enumerator is reconciled
    against. It returns a sorted, de-duplicated kind set, so it cannot see that a context holds
    two operations of the same kind -- that granularity is `enumerate_operations`'s.

    A small state machine, not a regex over raw text: it looks at token *sequences* so a `*` that
    is a pointer type (`*const`/`*mut`) is not read as a dereference, and an identifier that is a
    keyword (`if x(`) is not read as a function call.
    """
    found: set[str] = set()
    vals = [v for _k, v, _s, _e in toks]
    kinds = [k for k, _v, _s, _e in toks]
    for idx, (kind, value, _s, _e) in enumerate(toks):
        nxt = toks[idx + 1] if idx + 1 < len(toks) else None
        prev = toks[idx - 1] if idx > 0 else None
        if kind == "id":
            if value in _ASM_MACROS and nxt is not None and nxt[1] == "!":
                found.add("INLINE_ASM")
            if value in ("transmute", "transmute_copy"):
                found.add("TRANSMUTE")
            if value in _UNCHECKED:
                found.add("ASSERT_UNCHECKED")
            if value in _WRITE_METHODS and prev is not None and prev[1] == ".":
                found.add("RAW_POINTER_WRITE")
            if value in _READ_METHODS and prev is not None and prev[1] == ".":
                found.add("RAW_POINTER_READ")
            if value in ("write", "read", "copy", "copy_nonoverlapping") and \
                    idx >= 3 and vals[idx - 1] == "::" and vals[idx - 2] in ("ptr", "intrinsics"):
                found.add("RAW_POINTER_WRITE" if value != "read" else "RAW_POINTER_READ")
            if value == "static" and nxt is not None and nxt[1] == "mut":
                found.add("STATIC_MUT_ACCESS")
        if kind == "op" and value == "*":
            if nxt is None or (nxt[1] in ("const", "mut")):
                continue
            if prev is None or prev[1] in _PREFIX_OK:
                found.add("RAW_POINTER_DEREFERENCE")
    # A method call: `.ident(` where ident is not a keyword.
    for idx in range(len(toks) - 2):
        if toks[idx][1] == "." and toks[idx + 1][0] == "id" and toks[idx + 2][1] == "(" \
                and toks[idx + 1][1] not in _CALL_KEYWORDS:
            found.add("UNSAFE_METHOD_CALL")
    # A free function call: `ident(` (not a keyword) or `path::ident(`.
    for idx in range(len(toks) - 1):
        if toks[idx][0] == "id" and toks[idx][1] not in _CALL_KEYWORDS \
                and toks[idx + 1][1] == "(" and idx > 0 and toks[idx - 1][1] != "." \
                and not (toks[idx - 1][1] in ("fn", "struct", "enum", "union", "trait")):
            found.add("UNSAFE_FUNCTION_CALL")
    del kinds
    return sorted(found, key=lambda k: (KIND_PRIORITY.index(k) if k in KIND_PRIORITY else 99, k))


def _kind_rank(kind: str) -> int:
    """The load-bearing order of `KIND_PRIORITY`; an unknown kind sorts last."""
    return KIND_PRIORITY.index(kind) if kind in KIND_PRIORITY else len(KIND_PRIORITY)


def _record_op(by_span: dict[tuple[int, int], str], kind: str, s: int, e: int) -> None:
    """Keep the highest-priority kind for one token span -- a token is one operation."""
    old = by_span.get((s, e))
    if old is None or _kind_rank(kind) < _kind_rank(old):
        by_span[(s, e)] = kind


def enumerate_operations(toks: list[tuple[str, str, int, int]]) -> list[tuple[str, int, int]]:
    """Every unsafe-operation occurrence in a token stream, as `(kind, start, end)`.

    This is the **operation-level** extractor and the census's primary unit. Where
    `classify_operations` answers *which kinds* a context contains, this answers *how many
    operations and where*: each raw dereference `*p`, each `.method(`, each `call(`, each
    `transmute`, each `asm!`, each `static mut`, each raw read/write/copy is its own
    `(kind, start, end)` with the token's own span, so a context holding two dereferences yields
    two entries rather than one. `start`/`end` are character offsets into the tokenized text.

    One token is one operation: where a token matches more than one rule (a `p.write(x)` is both a
    raw write and a method call), the more specific kind in `KIND_PRIORITY` wins, so a token is
    never counted twice. The result is sorted by span so it is deterministic regardless of the
    rule order that produced it.
    """
    by_span: dict[tuple[int, int], str] = {}
    vals = [v for _k, v, _s, _e in toks]
    n = len(toks)
    for idx, (kind, value, s, e) in enumerate(toks):
        nxt = toks[idx + 1] if idx + 1 < n else None
        prev = toks[idx - 1] if idx > 0 else None
        cand: str | None = None
        if kind == "id":
            if value in _ASM_MACROS and nxt is not None and nxt[1] == "!":
                cand = "INLINE_ASM"
            if value in ("transmute", "transmute_copy"):
                cand = "TRANSMUTE"
            if value in _UNCHECKED:
                cand = "ASSERT_UNCHECKED"
            if value in _WRITE_METHODS and prev is not None and prev[1] == ".":
                cand = "RAW_POINTER_WRITE"
            if value in _READ_METHODS and prev is not None and prev[1] == ".":
                cand = "RAW_POINTER_READ"
            if value in ("write", "read", "copy", "copy_nonoverlapping") and idx >= 3 and \
                    vals[idx - 1] == "::" and vals[idx - 2] in ("ptr", "intrinsics"):
                cand = "RAW_POINTER_WRITE" if value != "read" else "RAW_POINTER_READ"
            if value == "static" and nxt is not None and nxt[1] == "mut":
                cand = "STATIC_MUT_ACCESS"
        elif kind == "op" and value == "*":
            if nxt is not None and nxt[1] not in ("const", "mut") and \
                    (prev is None or prev[1] in _PREFIX_OK):
                cand = "RAW_POINTER_DEREFERENCE"
        if cand is not None:
            _record_op(by_span, cand, s, e)
    # A method call: `.ident(` where ident is not a keyword.
    for idx in range(n - 2):
        if toks[idx][1] == "." and toks[idx + 1][0] == "id" and toks[idx + 2][1] == "(" \
                and toks[idx + 1][1] not in _CALL_KEYWORDS:
            _record_op(by_span, "UNSAFE_METHOD_CALL", toks[idx + 1][2], toks[idx + 1][3])
    # A free function call: `ident(` (not a keyword) or `path::ident(`.
    for idx in range(1, n - 1):
        if toks[idx][0] == "id" and toks[idx][1] not in _CALL_KEYWORDS \
                and toks[idx + 1][1] == "(" and toks[idx - 1][1] != "." \
                and toks[idx - 1][1] not in ("fn", "struct", "enum", "union", "trait"):
            _record_op(by_span, "UNSAFE_FUNCTION_CALL", toks[idx][2], toks[idx][3])
    return sorted(((k, s, e) for (s, e), k in by_span.items()),
                  key=lambda o: (o[1], o[2], o[0]))


# --------------------------------------------------------------------------------------------
# contract extraction (the enclosing safety contract the source states)
# --------------------------------------------------------------------------------------------

_BLOCK_COMMENT_START = ("//", "/*", "*", "///", "//!")


def _preceding_comment(lines: list[str], line_start: int) -> str:
    """The comment region immediately above a context, as text (or "").

    Walks upward over blank lines, attribute lines and comment lines; stops at the first line that
    is none of those. The region is returned so a caller can look for the `SAFETY:`/`# Safety`
    marker inside it.
    """
    i = line_start - 2  # 0-based index of the line above a 1-based `line_start`
    collected: list[str] = []
    steps = 0
    while i >= 0 and steps < 40:
        stripped = lines[i].strip()
        if stripped == "":
            collected.append(lines[i])
            i -= 1
            steps += 1
            continue
        if stripped.startswith("#[") and stripped.endswith("]"):
            collected.append(lines[i])
            i -= 1
            steps += 1
            continue
        if stripped.startswith(_BLOCK_COMMENT_START):
            collected.append(lines[i])
            i -= 1
            steps += 1
            continue
        break
    collected.reverse()
    return "\n".join(collected)


def extract_contract(lines: list[str], line_start: int) -> tuple[str, str]:
    """`(state, text)` for a context's stated safety contract.

    `state` is `STATED` when a `SAFETY:` comment or a `# Safety` doc section is found above the
    context, `UNSTATED` otherwise (which the caller records as an open contract, not a pass).
    """
    region = _preceding_comment(lines, line_start)
    if not region:
        return "UNSTATED", ""
    for marker in ("SAFETY", "# Safety", "# SAFETY"):
        at = region.find(marker)
        if at >= 0:
            return "STATED", region[at:].strip()
    return "UNSTATED", ""


# --------------------------------------------------------------------------------------------
# measurement: clippy + nighty expansion
# --------------------------------------------------------------------------------------------

def _run(argv: list[str], *, env: dict | None = None) -> subprocess.CompletedProcess:
    full = dict(os.environ)
    if env:
        full.update(env)
    return subprocess.run(argv, cwd=str(REPO_ROOT), env=full, capture_output=True, text=True,
                          check=False)


def _clippy_diagnostics() -> list[dict]:
    """The compiler's `unsafe_code` diagnostics, one per unsafe construct.

    One clippy invocation, all four lints as warnings, JSON message stream. Only
    `compiler-message` lines whose code is one of the authority lints are kept; a diagnostic with
    no primary span (a crate-level note) is not a construct and is dropped.
    """
    WORK.mkdir(parents=True, exist_ok=True)
    raw = WORK / "clippy.json"
    argv = ["cargo", "clippy", "--lib", "--tests", "--message-format=json", "--"]
    for lint in AUTHORITY_LINTS:
        argv += ["-W", lint]
    res = _run(argv)
    raw.write_text(res.stdout, encoding="utf-8")
    if res.returncode != 0 and '"reason":"compiler-message"' not in res.stdout:
        raise SystemExit(
            f"ms_census: clippy failed ({res.returncode}) with no diagnostics:\n{res.stderr[-4000:]}"
        )
    out: list[dict] = []
    for line in res.stdout.splitlines():
        if '"reason":"compiler-message"' not in line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = rec.get("message") or {}
        code = (msg.get("code") or {}).get("code")
        if code not in AUTHORITY_LINTS:
            continue
        spans = [s for s in (msg.get("spans") or []) if s.get("is_primary")]
        if not spans:
            continue
        out.append({"message": msg.get("message"), "lint": code, "span": spans[0]})
    return out


def _run_geiger() -> None:
    """Run the pinned cargo-geiger in its own `/work` environment, writing its JSON summary.

    cargo-geiger is installed once under `/work/.phase25-geiger` (a `cargo install` outside the
    image) and needs the admitted authority's libssl on `LD_LIBRARY_PATH`; it is a *cross-check*,
    not the authority, so its absence is recorded with a reason rather than failing the census.
    """
    WORK.mkdir(parents=True, exist_ok=True)
    tool = Path(str(GEIGER_BIN))
    missing = WORK / "geiger.missing"
    if not tool.is_file():
        missing.write_text(
            f"the pinned cargo-geiger binary {tool} is absent (install with "
            f"`cargo install cargo-geiger --root /work/.phase25-geiger --locked`); the census "
            f"records its absence rather than skipping it silently", encoding="utf-8")
        return
    env = {
        "CARGO_HOME": "/work/.phase25-cargo",
        "RUSTUP_TOOLCHAIN": "1.98.1",
        "LD_LIBRARY_PATH": str(AUTHORITY_PREFIX_LIB),
    }
    res = _run([str(tool), "--output-format", "Json"], env=env)
    if res.returncode == 0 and res.stdout.strip():
        (WORK / "geiger.json").write_text(res.stdout, encoding="utf-8")
    else:
        missing.write_text(f"cargo-geiger exited {res.returncode}: {res.stderr.strip()[-300:]}",
                           encoding="utf-8")


def _toolchain() -> dict:
    """The exact toolchain the census was derived with, versions and commit hashes."""
    rustc = _run(["rustc", "--version", "--verbose"]).stdout
    cargo = _run(["cargo", "--version"]).stdout
    clippy = _run(["cargo", "clippy", "--version"]).stdout

    def commit(text: str) -> str:
        m = re.search(r"commit-hash:\s*([0-9a-f]+)", text)
        return m.group(1) if m else "unknown"

    nightly_env = {"RUSTUP_HOME": NIGHTLY_HOME, "CARGO_HOME": NIGHTLY_CARGO_HOME,
                   "RUSTUP_TOOLCHAIN": NIGHTLY}
    nres = _run(["rustc", "--version", "--verbose"], env=nightly_env)
    nok = nres.returncode == 0 and "nightly" in nres.stdout
    return {
        "rustc": rustc.splitlines()[0].strip() if rustc else "unknown",
        "rustc_commit": commit(rustc),
        "cargo": cargo.strip(),
        "clippy": clippy.strip(),
        "nightly_channel": NIGHTLY,
        "nightly_rustc": nres.stdout.splitlines()[0].strip() if nok else "unavailable",
        "nightly_commit": commit(nres.stdout) if nok else "unknown",
        "nightly_installed": nok,
        "lints": list(AUTHORITY_LINTS),
        "compiler_clause": COMPILER_CLAUSE,
    }


def expand_source(tc: dict) -> dict:
    """Emit the macro-expanded crate source with the pinned nightly; content-hash it.

    Returns `{"status", "sha256", "bytes", "note"}`. Never silently skips expansion: if the pinned
    nightly is unavailable the status is `unavailable` with the reason, and the caller records that
    as a cross-check limitation while the clippy-JSON census still stands (clippy lints
    post-expansion, so the census is the expanded crate's either way).
    """
    if not tc.get("nightly_installed"):
        return {"status": "unavailable", "sha256": "unknown", "bytes": 0,
                "note": (f"the pinned nightly {NIGHTLY} could not be installed, so the expanded "
                         f"source was not emitted; the census falls back to the clippy-JSON "
                         f"contexts (which clippy reports post-expansion) plus the whole-tree "
                         f"lexical scan")}
    WORK.mkdir(parents=True, exist_ok=True)
    out = WORK / "expanded.rs"
    env = {"RUSTUP_HOME": NIGHTLY_HOME, "CARGO_HOME": NIGHTLY_CARGO_HOME,
           "RUSTUP_TOOLCHAIN": NIGHTLY, "CARGO_TARGET_DIR": str(WORK / "target-nightly")}
    res = _run(["cargo", "rustc", "--lib", "--", "-Zunpretty=expanded"], env=env)
    if res.returncode != 0 or not res.stdout:
        return {"status": "failed", "sha256": "unknown", "bytes": 0,
                "note": (f"`cargo +{NIGHTLY} rustc --lib -- -Zunpretty=expanded` failed: "
                         f"{res.stderr.strip()[-300:]}")}
    out.write_text(res.stdout, encoding="utf-8")
    return {"status": "emitted", "sha256": sha256_bytes(res.stdout.encode("utf-8")),
            "bytes": len(res.stdout.encode("utf-8")),
            "note": f"macro-expanded crate source emitted by `{tc['nightly_channel']}`"}


# --------------------------------------------------------------------------------------------
# building the census body
# --------------------------------------------------------------------------------------------

def _context_id(file: str, bs: int, be: int, kind: str) -> str:
    return "uc-" + sha256_bytes(f"{file}\0{bs}\0{be}\0{kind}".encode("utf-8"))[:16]


def _site_id(file: str, bs: int, be: int, kind: str) -> str:
    """A site's stable id: `sha16(file, byte_start, byte_end, operation_kind)`.

    The span is the operation's own span (not its context's), so a context holding two
    operations yields two distinct ids, and an unrelated edit elsewhere leaves the id unchanged.
    """
    return "us-" + sha256_bytes(f"{file}\0{bs}\0{be}\0{kind}".encode("utf-8"))[:16]


def _module_of(relpath: str) -> str:
    parts = relpath.split("/")
    if parts[0] == "src":
        if len(parts) == 2:
            return parts[1][:-3]
        return parts[1]
    return parts[0]


def _macro_provenance(span: dict) -> str | None:
    """The macro a context came from, as a compact provenance string, or None.

    Format: `name!@invocation_file:invocation_line<-definition_file:definition_line`. The
    invocation is where the macro was called and the definition is where its body lives, so a
    reader can see both ends of an expansion from the row alone.
    """
    exp = span.get("expansion")
    if not exp:
        return None
    inv = exp.get("span") or {}
    dfn = exp.get("def_site_span") or {}
    return (f"{exp.get('macro_decl_name')}@{inv.get('file_name')}:{inv.get('line_start')}"
            f"<-{dfn.get('file_name')}:{dfn.get('line_start')}")


def _char_byte_offsets(text: str) -> list[int]:
    """`offsets[i]` = the byte offset of character `i` in `text`, for `i` up to `len(text)`.

    The tokenizer works in character offsets and a site's span is a *byte* range, so the map is
    built once per context and indexed by the token's character offset. Rust source is valid
    UTF-8, so re-encoding the decoded text reproduces the file's bytes.
    """
    offs = [0] * (len(text) + 1)
    for i, ch in enumerate(text):
        offs[i + 1] = offs[i] + len(ch.encode("utf-8"))
    return offs


def _byte_line_starts(raw: bytes) -> list[int]:
    """The byte offset of the start of every line in `raw` (line 1 starts at 0)."""
    starts = [0]
    for i, b in enumerate(raw):
        if b == 0x0A:
            starts.append(i + 1)
    return starts


def _line_col(starts: list[int], off: int) -> tuple[int, int]:
    """One-based `(line, column)` of a byte offset, from a precomputed line-start table."""
    lo, hi = 0, len(starts)
    while lo < hi:
        mid = (lo + hi) // 2
        if starts[mid] <= off:
            lo = mid + 1
        else:
            hi = mid
    line = max(lo, 1)
    return line, off - starts[line - 1] + 1


def _own_text(raw: bytes, bs: int, be: int, children: list[dict]) -> tuple[str, int]:
    """A context's own text: its byte span minus every nested context's span.

    Returns `(text, base)` where `base` is the absolute byte offset `text` starts at. Nested
    contexts are blanked to spaces in place, so byte offsets in `text` map to `base + offset`.
    """
    bs_c, be_c = min(bs, len(raw)), min(be, len(raw))
    buf = bytearray(raw[bs_c:be_c])
    for c in children:
        lo = max(c["bs"], bs_c) - bs_c
        hi = min(c["be"], be_c) - bs_c
        for k in range(lo, max(lo, hi)):
            buf[k] = 0x20
    return bytes(buf).decode("utf-8", "replace"), bs_c


def _context_operations(file: str, raw: bytes, bs: int, be: int, children: list[dict],
                        kind: str, line_starts: list[int]) -> list[tuple[str, int, int, int, int]]:
    """`(operation_kind, byte_start, byte_end, line, column)` for every operation in a context.

    A `FIXED_OPERATION_KIND` context (an `unsafe impl`, an exported symbol, an `extern` block) is
    its construct's single operation, at the context's own span. Any other context is enumerated
    operation by operation over its own text; each operation carries its own byte span and the
    line/column of its start.
    """
    if kind in FIXED_OPERATION_KIND:
        ln, col = _line_col(line_starts, bs)
        return [(FIXED_OPERATION_KIND[kind], bs, be, ln, col)]
    own, base = _own_text(raw, bs, be, children)
    offs = _char_byte_offsets(own)
    out: list[tuple[str, int, int, int, int]] = []
    for op_kind, cs, ce in enumerate_operations(tokenize(own)):
        s = base + offs[cs]
        e = base + offs[ce]
        if e <= s:
            e = min(s + 1, len(raw))
        ln, col = _line_col(line_starts, s)
        out.append((op_kind, s, e, ln, col))
    return out


def build_body(tc: dict, expansion: dict, diagnostics: list[dict]) -> dict:
    """The census body: files, compiler-identified contexts, classified sites, cross-checks, LOC."""
    surface = shipped_surface()
    file_text: dict[str, str] = {}
    file_bytes: dict[str, bytes] = {}
    files: list[dict] = []
    for entry in surface:
        raw = entry["abs"].read_bytes()
        file_bytes[entry["path"]] = raw
        file_text[entry["path"]] = raw.decode("utf-8", "replace")
        files.append({
            "census_id": f"sc:{entry['path']}",
            "path": entry["path"],
            "kind": entry["kind"],
            "language": LANGUAGE_BY_KIND.get(entry["kind"], "other"),
            "origin": entry["origin"],
            "shipped": True,
            "file_sha256": sha256_file(entry["abs"]),
            "unsafe_operations": 0,
            "evidence": ["shipped:first-party", f"origin:{entry['origin']}"],
        })

    # Dedup the compiler's diagnostics by span identity (the lib and the test target can each
    # report a shared construct once; identical reports are one construct).
    seen: set[tuple] = set()
    raw_ctx: list[dict] = []
    for diag in diagnostics:
        span = diag["span"]
        file = span.get("file_name")
        if not file or not file.startswith(("src/", "tests/")):
            continue
        kind = MESSAGE_CONTEXT_KIND.get(diag["message"])
        if kind is None:
            continue
        key = (file, span["byte_start"], span["byte_end"], kind)
        if key in seen:
            continue
        seen.add(key)
        raw_ctx.append({
            "file": file, "bs": span["byte_start"], "be": span["byte_end"],
            "line": span["line_start"], "column": span["column_start"],
            "line_end": span["line_end"], "kind": kind, "message": diag["message"],
            "lint": diag["lint"], "macro_provenance": _macro_provenance(span),
        })
    raw_ctx.sort(key=lambda c: (c["file"], c["bs"], c["be"], c["kind"]))

    # Per-file nested spans, so a context's *own* text excludes its nested contexts: a site is an
    # operation in the context's own body, not a copy of a child's.
    by_file: dict[str, list[dict]] = {}
    for ctx in raw_ctx:
        by_file.setdefault(ctx["file"], []).append(ctx)

    contexts: list[dict] = []
    sites: list[dict] = []
    contexts_by_kind: dict[str, int] = {}
    sites_by_kind: dict[str, int] = {}
    uncontracted = 0
    contexts_without_site = 0
    per_file_sites: dict[str, int] = {}
    lines = {p: file_text[p].split("\n") for p in file_text}
    line_starts = {p: _byte_line_starts(file_bytes[p]) for p in file_bytes}
    # The union of context line ranges per file, for the secondary LOC projection.
    unsafe_lines: dict[str, set[int]] = {}
    # The context-level classifier's answer per context and the operation-level sites' kinds, so
    # the two can be reconciled (the independent cross-check).
    ctx_kind_sets: dict[str, list[str]] = {}
    site_kind_sets: dict[str, set[str]] = {}
    site_id_seen: set[str] = set()
    site_id_collisions: list[str] = []

    for ctx in raw_ctx:
        file = ctx["file"]
        bs, be = ctx["bs"], ctx["be"]
        children = [c for c in by_file[file]
                    if c is not ctx and bs <= c["bs"] and c["be"] <= be]
        raw = file_bytes[file]

        state, contract = extract_contract(lines[file], ctx["line"])
        if state == "UNSTATED":
            contract = UNCONTRACTED

        kind = ctx["kind"]
        # The context-level classifier's answer is the independent cross-check: it is the
        # unchanged pre-correction census path, and it can disagree with the operation-level
        # enumerator (a `p.write(x)` is one raw write operation, but two kinds).
        if kind in FIXED_OPERATION_KIND:
            method = f"construct:{kind}"
            ctx_kinds = [FIXED_OPERATION_KIND[kind]]
        else:
            method = "context-span-op-scan:v2"
            own, _base = _own_text(raw, bs, be, children)
            ctx_kinds = classify_operations(tokenize(own))

        ops = _context_operations(file, raw, bs, be, children, kind, line_starts[file])
        cid = _context_id(file, bs, be, kind)
        site_ids: list[str] = []
        site_kinds: set[str] = set()
        for op_kind, s, e, ln, col in ops:
            sid = _site_id(file, s, e, op_kind)
            if sid in site_id_seen:
                site_id_collisions.append(sid)
            site_id_seen.add(sid)
            site_ids.append(sid)
            site_kinds.add(op_kind)
            sites.append({
                "site_id": sid,
                "file": file,
                "line": ln,
                "column": col,
                "operation_kind": op_kind,
                "context_id": cid,
                # `span` is `[byte_start, byte_end, line_end, column_start]`: the operation's own
                # compiler-anchored span, kept so a site id re-derives from the site alone.
                "span": [s, e, ln, col],
                "compiler": COMPILER_CLAUSE,
                "compiler_derived": True,
                "exposure_class": "INTERNAL_REACHABLE",
                "risk_tier": "S4",
                "safety_obligation_ids": [],
                "evidence": ["unsafe_code"],
                "module": _module_of(file),
                "function": _nearest_fn(lines[file], ln),
                "macro_provenance": ctx["macro_provenance"],
                "classification_method": method,
                "candidate_commit": _commit_placeholder(),
            })
            sites_by_kind[op_kind] = sites_by_kind.get(op_kind, 0) + 1
            per_file_sites[file] = per_file_sites.get(file, 0) + 1
        if not ops:
            contexts_without_site += 1

        if state == "UNSTATED":
            uncontracted += 1
        contexts_by_kind[kind] = contexts_by_kind.get(kind, 0) + 1
        unsafe_lines.setdefault(file, set()).update(range(ctx["line"], ctx["line_end"] + 1))
        ctx_kind_sets[cid] = ctx_kinds
        site_kind_sets[cid] = site_kinds
        contexts.append({
            "context_id": cid,
            "kind": kind,
            "file": file,
            "line": ctx["line"],
            # `span` is `[byte_start, byte_end, line_end, column_start]`: a compact, documented
            # form of the compiler's span, kept so a context id re-derives from the context.
            "span": [bs, be, ctx["line_end"], ctx["column"]],
            "safety_contract": contract,
            "contract_state": state,
            "site_ids": site_ids,
            "reported_by": ctx["lint"],
            "macro_provenance": ctx["macro_provenance"],
            "evidence": ["unsafe_code"],
        })

    # The independent cross-check: the context-level kind classifier against the operation-level
    # sites. They disagree exactly where a context holds an operation kind the classifier also
    # sees as another kind (a raw pointer write is also a method call to the classifier), and
    # every disagreement is recorded as one aggregated residual, never tuned away.
    ctx_diffs = [(cid, sorted(set(ctx_kind_sets[cid])), sorted(site_kind_sets.get(cid, set())))
                 for cid in sorted(ctx_kind_sets) if set(ctx_kind_sets[cid]) != site_kind_sets.get(cid, set())]
    reconcile_residuals: list[dict] = []
    if ctx_diffs:
        sample = "; ".join(f"{cid} {ck}->{sk}" for cid, ck, sk in ctx_diffs[:5])
        reconcile_residuals.append({
            "source": "context-tokenizer",
            "class": "out_of_scope",
            "detail": (f"the context-level kind classifier and the operation-level scan disagree on "
                       f"{len(ctx_diffs)} context(s): the classifier counts a raw read/write method "
                       f"as both the read/write kind and `UNSAFE_METHOD_CALL`, while the "
                       f"operation-level scan records one operation per token (the more specific "
                       f"kind wins), so the kind sets differ by construction. Examples: {sample}"),
        })

    # The `sites` list and every site's `candidate_commit` are stamped with the toolchain call's
    # commit; `_commit_placeholder` is resolved once by the caller and rewritten here.
    commit = _CANDIDATE_COMMIT
    for site in sites:
        site["candidate_commit"] = commit

    # Per-file operation counts are derived, never typed.
    for row in files:
        row["unsafe_operations"] = per_file_sites.get(row["path"], 0)

    # The LOC projection: physical and code lines, and the code lines inside compiler contexts.
    physical = code = unsafe_code = 0
    for row in files:
        if row["kind"] not in _RUST_SOURCE_KINDS:
            continue
        text = file_text[row["path"]]
        physical += text.count("\n") + (0 if text.endswith("\n") or not text else 1)
        view = lexical.code_only(text, keep_strings=True)
        for idx, line in enumerate(view.split("\n"), start=1):
            if line.strip():
                code += 1
                if idx in unsafe_lines.get(row["path"], ()):
                    unsafe_code += 1
    safe_code = code - unsafe_code

    # The cross-checks: cargo-geiger, a source-lexical scan and the context-level tokenizer, each
    # reconciled against the census with every disagreement recorded as a residual, never tuned.
    crosschecks, residuals = _crosschecks(files, file_text, diagnostics, len(contexts), len(sites),
                                          contexts_by_kind, ctx_diffs, reconcile_residuals)

    counts = {
        "files": len(files),
        "rust_files": sum(1 for f in files if f["kind"] in _RUST_SOURCE_KINDS),
        "c_files": sum(1 for f in files if f["kind"] == "C_SOURCE"),
        "generated_files": sum(1 for f in files if f["origin"] == "GENERATED"),
        "unsafe_contexts": len(contexts),
        "sites": len(sites),
        "operations": len(sites),
        "contexts_with_operations": sum(1 for c in contexts if c["site_ids"]),
        "max_operations_in_context": max((len(c["site_ids"]) for c in contexts), default=0),
        "site_id_collisions": len(site_id_collisions),
        "contexts_reconciled": len(ctx_kind_sets) - len(ctx_diffs),
        "contexts_reconciliation_differences": len(ctx_diffs),
        "contexts_by_kind": dict(sorted(contexts_by_kind.items())),
        "sites_by_kind": dict(sorted(sites_by_kind.items())),
        "uncontracted_contexts": uncontracted,
        "contexts_without_site": contexts_without_site,
    }

    body = {
        "rule": {
            "authority": (
                "the compiler is the authority for unsafe operations, never a regex: the "
                "enumerating diagnostic is the built-in `unsafe_code` lint, emitted by one clippy "
                "run over the crate with `--message-format=json`, one diagnostic per unsafe "
                "construct, with macro-expansion-aware spans and `expansion` provenance. A "
                "regular-expression scan or a text grep is a projection, and is never the unit "
                "(docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md section 3.1)"
            ),
            "documented_lints": (
                "`clippy::undocumented_unsafe_blocks`, `unsafe_op_in_unsafe_fn` and "
                "`clippy::missing_safety_doc` are the documentation authority: the crate is "
                "`deny`-clean under all three, so they report nothing (the census records that as "
                "`documentation_clean`), and a context that regressed would appear as a diagnostic "
                "of one of them. `undocumented_unsafe_blocks` cannot enumerate a deny-clean crate, "
                "which is why `unsafe_code` is the enumerating authority"
            ),
            "operations": (
                "the primary unit is a compiler-derived unsafe *operation*: the compiler "
                "establishes each unsafe context and its exact span (the built-in `unsafe_code` "
                "lint), and the operation-level enumerator scans that compiler-established span "
                "for each distinct operation -- one site per raw dereference, unsafe/extern call, "
                "method call, static access, pointer read/write, transmute, inline asm -- so a "
                "context holding two operations yields two sites, each with its own span and its "
                "own stable `site_id` derived from (file, span, operation kind), while "
                "`context_id` still names the compiler context the operation sits in. The "
                "operation *kind* is a classification against "
                "memory_safety_schemas.UNSAFE_OPERATION_KINDS, a secondary label on a "
                "compiler-established unit, and `classification_method` records the method on "
                "every site"
            ),
            "operation_extraction": (
                "`context-span-op-scan:v2`: the operation-level extractor. A HIR/MIR-backed "
                "enumerator was investigated first and is recorded here as the measured reason "
                "this extractor is the compiler-anchored span scan rather than a raw dump. "
                "`-Zunpretty=hir-tree` and `-Zunpretty=thir-tree` are not reproducible at this "
                "crate's scale (the lib aborts with `memory allocation of 2147483648 bytes "
                "failed` and `memory allocation of 1207468032 bytes failed` respectively); "
                "`-Zunpretty=mir -Zmir-include-spans` is producible (4,922,910 lines / 364 MB) "
                "and its spans align with the compiler contexts, but MIR is post-desugaring "
                "(method calls, union accesses and the ptr::read/read_unaligned/assert_unchecked "
                "family are not distinguishable, and debug instrumentation duplicates each raw "
                "dereference), so reconstructing the census's operation vocabulary from it would "
                "be a heuristic layer rather than a compiler fact. The extractor therefore "
                "enumerates the operations inside the compiler-established context span; the "
                "enclosing context and the operation's own span are the compiler-anchored facts, "
                "and every site records this method"
            ),
            "expansion": expansion["note"],
            "crosscheck_policy": (
                "cargo-geiger, a source-lexical scan and the context-level kind classifier are "
                "reconciled against the census; every disagreement is recorded as a residual and "
                "classified, never tuned to zero. A cross-check that uses a different unit "
                "(geiger counts unsafe expressions; the lexical scan counts keywords; the "
                "context-level classifier counts kind *sets* per context while the primary unit "
                "is an operation *instance*) disagrees by construction, and the disagreement is "
                "the residual"
            ),
            "loc_definition": (
                "rust_physical_loc is every line of the shipped Rust files; rust_code_loc is the "
                "lines that are code after comments are removed (the same scanner the lexical "
                "cross-check uses); unsafe_context_code_loc is the code lines inside the union of "
                "the compiler-identified unsafe context spans; safe_rust_code_loc is "
                "rust_code_loc - unsafe_context_code_loc. The split is the compiler's, and the "
                "whole projection is a secondary view, never a safety claim"
            ),
            "provisional_fields": (
                "`sites[].exposure_class` (INTERNAL_REACHABLE) and `sites[].risk_tier` (S4) are "
                "placeholders the schema requires: the exposure/data-flow classification is 25.7's "
                "measurement and is not made here. INTERNAL_REACHABLE is chosen because "
                "over-stating reachability is the safe direction for a memory-safety census; the "
                "sites' `safety_obligation_ids` are likewise empty pending 25.3"
            ),
        },
        "toolchain": tc,
        "documentation_clean": not any(
            d["lint"] in ("clippy::undocumented_unsafe_blocks", "clippy::missing_safety_doc",
                          "unsafe_op_in_unsafe_fn")
            for d in diagnostics
        ),
        "files": files,
        "unsafe_contexts": contexts,
        "sites": sites,
        "crosschecks": crosschecks,
        "loc": {
            "rust_physical_loc": physical,
            "rust_code_loc": code,
            "safe_rust_code_loc": safe_code,
            "unsafe_context_code_loc": unsafe_code,
            "note": ("a secondary projection of the compiler-derived census; unsafe LOC is not a "
                     "vulnerability count (docs/UNSAFE.md, docs/NON_CLAIMS.md)"),
        },
        "counts": counts,
        "residuals": residuals,
        "non_claims": list(NON_CLAIMS),
    }
    return body


def _nearest_fn(lines: list[str], line: int) -> str:
    """The name of the nearest `fn` above a context line, or "" when there is none."""
    for idx in range(min(line, len(lines)) - 1, -1, -1):
        m = re.search(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", lines[idx])
        if m is not None:
            return m.group(1)
    return ""


def _crosschecks(files: list[dict], file_text: dict[str, str], diagnostics: list[dict],
                 n_contexts: int, n_sites: int, contexts_by_kind: dict,
                 ctx_diffs: list | None = None,
                 reconcile_residuals: list | None = None) -> tuple[dict, list]:
    """cargo-geiger + a source-lexical scan + the context-level classifier, each reconciled."""
    residuals: list[dict] = list(reconcile_residuals or [])

    # The source-lexical scan, over the shipped Rust files, through the same scanner the LOC
    # projection uses (unsafe_footprint.code_only).
    lex = {"files": 0, "unsafe_keyword_occurrences": 0, "unsafe_blocks": 0, "unsafe_fns": 0,
           "unsafe_externs": 0, "unsafe_impls": 0, "extern_c_fns": 0, "safety_comments": 0}
    for row in files:
        if row["kind"] not in _RUST_SOURCE_KINDS:
            continue
        text = file_text[row["path"]]
        m = lexical._metrics(text)
        lex["files"] += 1
        lex["unsafe_keyword_occurrences"] += m["unsafe_sites"]
        lex["unsafe_blocks"] += m["unsafe_blocks"]
        lex["unsafe_fns"] += m["unsafe_fns"]
        lex["unsafe_externs"] += m["unsafe_externs"]
        lex["unsafe_impls"] += m["unsafe_impls"]
        lex["extern_c_fns"] += m["extern_c_fns"]
        lex["safety_comments"] += m["safety_comments"]

    if lex["unsafe_keyword_occurrences"] != n_contexts:
        residuals.append({
            "source": "lexical",
            "class": "out_of_scope",
            "detail": (f"the lexical scan counts {lex['unsafe_keyword_occurrences']} `unsafe` "
                       f"keywords but the compiler reports {n_contexts} unsafe contexts: the "
                       f"scanner counts a keyword in a type (`unsafe fn()` pointer) the lint does "
                       f"not report as a construct, and the lint reports pre-expansion constructs "
                       f"the scanner sees once. The projection is not the unit, so the difference "
                       f"is recorded, not reconciled away"),
        })

    # cargo-geiger, in its own /work environment. Its JSON summary is read if present; a geiger
    # that could not run is recorded with its reason, never silently absent.
    geiger: dict = {"tool": "cargo-geiger", "status": "unavailable", "summary": None,
                    "note": "cargo-geiger was not run"}
    gpath = WORK / "geiger.json"
    if gpath.is_file():
        try:
            data = json.loads(gpath.read_text(encoding="utf-8"))
            pkg = (data.get("packages") or [{}])[0].get("unsafety") or {}
            used = pkg.get("used") or {}

            def gv(section: str) -> int:
                return int(((used.get(section) or {}).get("unsafe_")) or 0)

            geiger = {
                "tool": "cargo-geiger 0.13.0",
                "status": "measured",
                "summary": {
                    "unsafe_functions": gv("functions"),
                    "unsafe_exprs": gv("exprs"),
                    "unsafe_item_impls": gv("item_impls"),
                    "unsafe_methods": gv("methods"),
                },
                "note": ("cargo-geiger counts unsafe *expressions* (a different unit from a "
                         "compiler-reported construct), so it disagrees by construction"),
            }
            if gv("functions") != contexts_by_kind.get("UNSAFE_FN", 0):
                residuals.append({
                    "source": "geiger",
                    "class": "out_of_scope",
                    "detail": (f"geiger counts {gv('functions')} unsafe functions used, the "
                               f"compiler reports {contexts_by_kind.get('UNSAFE_FN', 0)} unsafe fn "
                               f"constructs: geiger's unit is an expression/definition count, not a "
                               f"diagnostic, so the difference is a unit difference recorded as a "
                               f"residual"),
                })
            if gv("item_impls") != contexts_by_kind.get("UNSAFE_IMPL", 0):
                residuals.append({
                    "source": "geiger",
                    "class": "out_of_scope",
                    "detail": (f"geiger counts {gv('item_impls')} unsafe impls, the compiler "
                               f"reports {contexts_by_kind.get('UNSAFE_IMPL', 0)}: recorded as a "
                               f"unit difference"),
                })
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            geiger["note"] = f"cargo-geiger output could not be read: {exc}"
    elif (WORK / "geiger.missing").is_file():
        geiger["note"] = (WORK / "geiger.missing").read_text(encoding="utf-8").strip()
        residuals.append({"source": "geiger", "class": "evidence_missing",
                          "detail": f"cargo-geiger did not run: {geiger['note']}"})

    crosschecks = {
        "lexical": lex,
        "geiger": geiger,
        "context_tokenizer": {
            "contexts": n_contexts,
            "contexts_reconciled": n_contexts - len(ctx_diffs or []),
            "contexts_differing": len(ctx_diffs or []),
            "note": ("the unchanged context-level kind classifier is the independent cross-check "
                     "of the operation-level extractor: it counts kind *sets* per context while "
                     "the primary unit is an operation instance, so it differs wherever a token "
                     "is both a raw read/write and a method call"),
        },
        "canonical": {"contexts": n_contexts, "sites": n_sites, "by_kind": dict(contexts_by_kind)},
        "residual_count": len(residuals),
    }
    return crosschecks, residuals


# The pinned cargo-geiger cross-check binary, installed once into the gitignored /work tree, and
# the admitted authority prefix whose libssl it needs on LD_LIBRARY_PATH at run time.
GEIGER_BIN = Path("/work/.phase25-geiger/bin/cargo-geiger")
AUTHORITY_PREFIX_LIB = Path(
    "/work/forensics/authorities/prefix/openssl-3.6.4-production/lib")


# The candidate commit, resolved once at measure time by `main` from `git rev-parse HEAD` (the
# commit being measured; the census lands in the commit after it). Module-level so the row builder
# does not thread it through every helper.
_CANDIDATE_COMMIT = "unknown"


def _commit_placeholder() -> str:
    return _CANDIDATE_COMMIT


# --------------------------------------------------------------------------------------------
# the on-disk encoding: a lossless, deterministic columnar form
# --------------------------------------------------------------------------------------------
#
# The census repeats a file path, a module, a kind, a method, a compiler clause and a commit on
# every one of ~172,000 sites and ~64,000 contexts. Written one object per record the artefact is
# 120 MB -- over GitHub's 100 MB pre-receive limit -- so the writer strips every field that
# re-derives from the committed source and codec-packs the rest. `strip_view`/`restore_view` are
# exact inverses over the evidence the court reads: `site_id`, `context_id`, `module`, `line`,
# `column` and `span` are all functions of `(file, byte_start, byte_end, kind)` and the committed
# bytes, so nothing that the court re-derives is stored twice, and nothing is lost.

_SITE_STORED = (
    "file", "bs", "be", "operation_kind", "ctx", "function", "macro_provenance",
    "classification_method", "candidate_commit", "compiler", "compiler_derived",
    "exposure_class", "risk_tier", "safety_obligation_ids", "evidence",
)
_CONTEXT_STORED = (
    "kind", "file", "bs", "be", "safety_contract", "contract_state", "reported_by",
    "macro_provenance", "evidence",
)


def strip_view(view: dict) -> dict:
    """The census view with every re-derivable field removed, as stored on disk."""
    contexts = view.get("unsafe_contexts") or []
    ctx_index = {c["context_id"]: i for i, c in enumerate(contexts)}
    stripped_ctx = []
    for c in contexts:
        span = c.get("span") or [None, None]
        stripped_ctx.append({
            "kind": c["kind"], "file": c["file"], "bs": span[0], "be": span[1],
            "safety_contract": c["safety_contract"], "contract_state": c["contract_state"],
            "reported_by": c["reported_by"], "macro_provenance": c["macro_provenance"],
            "evidence": c["evidence"],
        })
    stripped_sites = []
    for s in view.get("sites") or []:
        span = s.get("span") or [None, None]
        stripped_sites.append({
            "file": s["file"], "bs": span[0], "be": span[1],
            "operation_kind": s["operation_kind"], "ctx": ctx_index[s["context_id"]],
            "function": s["function"], "macro_provenance": s["macro_provenance"],
            "classification_method": s["classification_method"],
            "candidate_commit": s["candidate_commit"], "compiler": s["compiler"],
            "compiler_derived": s["compiler_derived"], "exposure_class": s["exposure_class"],
            "risk_tier": s["risk_tier"],
            "safety_obligation_ids": s["safety_obligation_ids"], "evidence": s["evidence"],
        })
    out = dict(view)
    out["unsafe_contexts"] = stripped_ctx
    out["sites"] = stripped_sites
    return out


def restore_view(stripped: dict) -> dict:
    """Rebuild the census view -- ids, spans, modules, lines -- from the stored form."""
    starts_cache: dict[str, list[int]] = {}

    def starts(file: str) -> list[int]:
        table = starts_cache.get(file)
        if table is None:
            path = REPO_ROOT / file
            raw = path.read_bytes() if path.is_file() else b""
            table = _byte_line_starts(raw)
            starts_cache[file] = table
        return table

    contexts: list[dict] = []
    for c in stripped.get("unsafe_contexts") or []:
        file, bs, be, kind = c["file"], c["bs"], c["be"], c["kind"]
        table = starts(file)
        contexts.append({
            "context_id": _context_id(file, bs, be, kind), "kind": kind, "file": file,
            "line": _line_col(table, bs)[0],
            "span": [bs, be, _line_col(table, be)[0], _line_col(table, bs)[1]],
            "safety_contract": c["safety_contract"], "contract_state": c["contract_state"],
            "site_ids": [], "reported_by": c["reported_by"],
            "macro_provenance": c["macro_provenance"], "evidence": c["evidence"],
        })
    sites: list[dict] = []
    for s in stripped.get("sites") or []:
        file, bs, be, kind = s["file"], s["bs"], s["be"], s["operation_kind"]
        table = starts(file)
        line, column = _line_col(table, bs)
        site_id = _site_id(file, bs, be, kind)
        sites.append({
            "site_id": site_id, "file": file, "line": line, "column": column,
            "operation_kind": kind, "context_id": contexts[s["ctx"]]["context_id"],
            "span": [bs, be, line, column], "compiler": s["compiler"],
            "compiler_derived": s["compiler_derived"], "exposure_class": s["exposure_class"],
            "risk_tier": s["risk_tier"], "safety_obligation_ids": s["safety_obligation_ids"],
            "evidence": s["evidence"], "module": _module_of(file), "function": s["function"],
            "macro_provenance": s["macro_provenance"],
            "classification_method": s["classification_method"],
            "candidate_commit": s["candidate_commit"],
        })
        contexts[s["ctx"]]["site_ids"].append(site_id)
    out = dict(stripped)
    out["unsafe_contexts"] = contexts
    out["sites"] = sites
    return out


def encode_body(view: dict) -> dict:
    """The on-disk body: the derived fields stripped, the rest columnar-packed."""
    return ms_codec.encode_body(strip_view(view))


def decode_body(body: dict) -> dict:
    """Invert `encode_body`; an already-decoded view is returned unchanged."""
    if not isinstance(body, dict) or body.get("encoding") != ms_codec.ENCODING:
        return body
    return restore_view(ms_codec.decode_body(body))


def _resolve_commit() -> str:
    res = _run(["git", "rev-parse", "HEAD"])
    return res.stdout.strip() if res.returncode == 0 else "unknown"


# --------------------------------------------------------------------------------------------
# the pure checks (the court re-runs these over the committed artefact)
# --------------------------------------------------------------------------------------------

# The derived-operation cache: `_derived_operation_sets` re-scans the shipped source for every
# context's operations, and the sensitivity control calls the check many times over bodies that
# share their contexts. The cache is keyed by the contexts' `(id, file, span, kind)` identity, so
# a mutation that changes only `sites`/`site_ids` reuses the derivation.
_DERIVED_OPS_CACHE: dict = {}


def _derived_operation_sets(body: dict) -> dict[str, set[tuple]]:
    """Re-derive every context's operations from the shipped source, keyed by context id.

    Pure over the body and the on-disk source: for each compiler-identified context the source is
    re-scanned for the operations in its own span (minus nested contexts), returning
    `{(operation_kind, byte_start, byte_end)}` per context. This is the *operation count* the
    census's sites must match, so a context holding two operations that the census recorded as one
    site is a finding even if its `site_ids` list was edited to agree.
    """
    contexts = body.get("unsafe_contexts") or []
    key = tuple((c.get("context_id"), c.get("file"), (c.get("span") or [None, None])[0],
                 (c.get("span") or [None, None])[1], c.get("kind")) for c in contexts)
    cached = _DERIVED_OPS_CACHE.get(key)
    if cached is not None:
        return cached
    by_file: dict[str, list[dict]] = {}
    for c in contexts:
        by_file.setdefault(c.get("file"), []).append(c)
    raw_cache: dict[str, bytes] = {}
    out: dict[str, set[tuple]] = {}
    for c in contexts:
        cid = c.get("context_id")
        file = c.get("file")
        span = c.get("span") or [None, None]
        bs, be = span[0], span[1]
        if file is None or bs is None or be is None:
            out[cid] = set()
            continue
        raw = raw_cache.get(file)
        if raw is None:
            path = REPO_ROOT / file
            raw = path.read_bytes() if path.is_file() else b""
            raw_cache[file] = raw
        children = [{"bs": (o.get("span") or [0, 0])[0], "be": (o.get("span") or [0, 0])[1]}
                    for o in by_file.get(file, []) if o is not c
                    and bs <= (o.get("span") or [0, 0])[0] and (o.get("span") or [0, 0])[1] <= be]
        starts = _byte_line_starts(raw)
        ops = _context_operations(file, raw, bs, be, children, c.get("kind"), starts)
        out[cid] = {(k, s, e) for k, s, e, _ln, _col in ops}
    _DERIVED_OPS_CACHE[key] = out
    return out


def census_findings(body: dict, surface: list[dict] | None = None) -> list[str]:
    """Every way the committed census contradicts itself, derived from the artefact alone.

    Pure over `body` and the shipped surface (no compiler): it is what the
    `MS-SOURCE-CENSUS` court runs. Checks: every shipped first-party file is accounted for and its
    digest matches; every site is compiler-derived and resolves to a compiler-identified context;
    site and context ids are stable and unique; each site's id re-derives from its own span; the
    context/site back-references are consistent; a context with N compiler-anchored operations
    yields N sites (re-derived from the source, so a fusion is caught); per-file operation counts,
    the counts block and the LOC arithmetic are derived, not typed; and every cross-check
    disagreement is a classified residual.

    `surface` defaults to the shipped surface on disk; the self-test passes the surface its
    synthetic body is scoped to.
    """
    problems: list[str] = []

    # The committed census is columnar on disk; re-derive the view the checks read. On a fresh
    # measurement the body is already the view, so this is a no-op.
    body = decode_body(body)

    files = body.get("files") or []
    contexts = body.get("unsafe_contexts") or []
    sites = body.get("sites") or []
    by_path = {f.get("path"): f for f in files}
    surface = shipped_surface() if surface is None else surface

    # 1. Every shipped first-party file is accounted for, with a matching digest.
    known = {e["path"]: e for e in surface}
    for path in sorted(known):
        row = by_path.get(path)
        if row is None:
            problems.append(f"the shipped file {path} is not accounted for in the census")
            continue
        actual = sha256_file(REPO_ROOT / path)
        if row.get("file_sha256") != actual:
            problems.append(f"{path}: recorded file_sha256 does not match the file on disk")
        if row.get("origin") != known[path]["origin"]:
            problems.append(f"{path}: origin {row.get('origin')!r} is not the derived "
                            f"{known[path]['origin']!r}")
    for path in sorted(by_path):
        if path not in known:
            problems.append(f"the census records {path}, which is not in the shipped surface")

    # 2. Schema validation of every record.
    for row in files:
        problems += [f"files[{row.get('path')}]: {p}" for p in schemas.validate_source_census(row)]
    for ctx in contexts:
        problems += [f"unsafe_contexts[{ctx.get('context_id')}]: {p}"
                     for p in schemas.validate_unsafe_context(ctx)]
    for site in sites:
        problems += [f"sites[{site.get('site_id')}]: {p}"
                     for p in schemas.validate_unsafe_site(site)]

    # 3. Ids are stable and unique, and recompute from the context's stored span.
    ctx_ids = [c.get("context_id") for c in contexts]
    if len(ctx_ids) != len(set(ctx_ids)):
        problems.append("context ids are not unique")
    ctx_id_set = set(ctx_ids)
    ctx_by_id = {c.get("context_id"): c for c in contexts}
    for ctx in contexts:
        span = ctx.get("span") or [None, None]
        want = _context_id(ctx.get("file"), span[0], span[1], ctx.get("kind"))
        if ctx.get("context_id") != want:
            problems.append(f"context {ctx.get('context_id')} is not the stable id of its span")
    site_ids = [s.get("site_id") for s in sites]
    if len(site_ids) != len(set(site_ids)):
        problems.append("site ids are not unique")
    for site in sites:
        span = site.get("span") or [None, None]
        want = _site_id(site.get("file"), span[0], span[1], site.get("operation_kind"))
        if site.get("site_id") != want:
            problems.append(f"site {site.get('site_id')} is not the stable id of its own span")

    # 4. Every site is compiler-derived and resolves to a compiler-identified context.
    for site in sites:
        if site.get("compiler_derived") is not True or not site.get("compiler"):
            problems.append(f"site {site.get('site_id')} is not compiler-derived")
        if site.get("context_id") not in ctx_id_set:
            problems.append(f"site {site.get('site_id')} names context "
                            f"{site.get('context_id')!r}, which the compiler did not report")

    # 5. Context back-references are consistent with the sites.
    site_id_set = set(site_ids)
    listed_ids: set[str] = set()
    for ctx in contexts:
        for sid in ctx.get("site_ids") or []:
            listed_ids.add(sid)
            if sid not in site_id_set:
                problems.append(f"context {ctx.get('context_id')} names site {sid}, which is absent")
    for site in sites:
        if site.get("context_id") in ctx_by_id and site.get("site_id") not in listed_ids:
            problems.append(f"site {site.get('site_id')} is not listed by its context")

    # 5b. The primary-unit invariant: a context with N compiler-anchored operations must yield N
    # sites, and each site must be one of the operations the source enumerates there. This is the
    # check that a fusion (two operations collapsed to one site) fails even when the context's
    # `site_ids` list is edited to match; it re-derives the operations from the shipped source, so
    # it is independent of the census's own counts.
    derived_ops = _derived_operation_sets(body)
    sites_by_ctx: dict[str, list[dict]] = {}
    for site in sites:
        sites_by_ctx.setdefault(site.get("context_id"), []).append(site)
    for ctx in contexts:
        cid = ctx.get("context_id")
        want_ops = derived_ops.get(cid, set())
        got_ops = set()
        for site in sites_by_ctx.get(cid, []):
            span = site.get("span") or [None, None]
            got_ops.add((site.get("operation_kind"), span[0], span[1]))
        if want_ops != got_ops:
            problems.append(
                f"context {cid}: the census records {len(got_ops)} operation(s) but the source "
                f"enumerates {len(want_ops)}; a context with N operations must yield N sites "
                f"(missing {sorted(want_ops - got_ops)[:3]}, extra {sorted(got_ops - want_ops)[:3]})")
        if len(ctx.get("site_ids") or []) != len(got_ops):
            problems.append(
                f"context {cid}: site_ids lists {len(ctx.get('site_ids') or [])} id(s) but "
                f"{len(got_ops)} site(s) name it")

    # 6. Per-file operation counts and the counts block are derived, not typed.
    derived_per_file: dict[str, int] = {}
    for site in sites:
        derived_per_file[site.get("file")] = derived_per_file.get(site.get("file"), 0) + 1
    for row in files:
        if row.get("unsafe_operations") != derived_per_file.get(row.get("path"), 0):
            problems.append(f"{row.get('path')}: unsafe_operations is not the derived site count")
    counts = body.get("counts") or {}
    expected = {
        "files": len(files),
        "unsafe_contexts": len(contexts),
        "sites": len(sites),
        "operations": len(sites),
        "generated_files": sum(1 for f in files if f.get("origin") == "GENERATED"),
    }
    for key, val in expected.items():
        if counts.get(key) != val:
            problems.append(f"counts.{key}={counts.get(key)!r} is not the derived {val}")
    with_ops = sum(1 for c in contexts if c.get("site_ids"))
    if counts.get("contexts_with_operations") != with_ops:
        problems.append("counts.contexts_with_operations is not the derived count")
    max_ops = max((len(c.get("site_ids") or []) for c in contexts), default=0)
    if counts.get("max_operations_in_context") != max_ops:
        problems.append("counts.max_operations_in_context is not the derived maximum")
    by_kind: dict[str, int] = {}
    for site in sites:
        by_kind[site.get("operation_kind")] = by_kind.get(site.get("operation_kind"), 0) + 1
    if (counts.get("sites_by_kind") or {}) != dict(sorted(by_kind.items())):
        problems.append("counts.sites_by_kind is not the derived per-kind site count")

    # 7. The LOC split derives from the context spans and is arithmetically consistent.
    loc = body.get("loc") or {}
    if loc.get("safe_rust_code_loc") != (loc.get("rust_code_loc") or 0) - \
            (loc.get("unsafe_context_code_loc") or 0):
        problems.append("loc.safe_rust_code_loc is not code_loc - unsafe_context_code_loc")

    # 8. Every cross-check disagreement is recorded as a classified residual.
    crosschecks = body.get("crosschecks") or {}
    residuals = body.get("residuals") or []
    for r in residuals:
        if r.get("class") not in schemas.RESIDUAL_CLASSES:
            problems.append(f"residual {r.get('source')!r} has class {r.get('class')!r}, not a "
                            f"closed residual class")
    geiger = crosschecks.get("geiger") or {}
    if geiger.get("status") != "measured" and not any(r.get("source") == "geiger"
                                                      for r in residuals):
        problems.append("cargo-geiger did not measure and left no residual recording why")
    lex = crosschecks.get("lexical") or {}
    if lex.get("unsafe_keyword_occurrences") != counts.get("unsafe_contexts") \
            and not any(r.get("source") == "lexical" for r in residuals):
        problems.append("the lexical cross-check disagrees with the census and left no residual")

    # 9. The authority and toolchain are recorded.
    if not body.get("toolchain") or not body["toolchain"].get("rustc"):
        problems.append("the toolchain is not recorded")
    return problems


def _kind_for_context(contexts: list[dict], context_id: str) -> str:
    for ctx in contexts:
        if ctx.get("context_id") == context_id:
            return str(ctx.get("kind"))
    return ""


def census_sensitivity_control(body: dict, surface: list[dict] | None = None) -> dict:
    """Seed six mutations and require each caught, with specificity holding.

    Each mutation is a distinct way a census could lie: an unsafe operation that no compiler
    reported, an unsafe operation hidden by dropping the macro-generated context that holds it, a
    context whose safety contract was removed, a site forged as safe, a shipped file dropped from
    the census, and -- the operation-level defect this subphase corrects -- **two operations in
    one context fused into a single site** (its `site_ids` edited to match, so only the source
    re-derivation can catch it). The baseline must be clean and each mutation must produce its own
    finding, so a control that "caught" everything indiscriminately would not pass.
    """
    # The committed artefact is columnar on disk; the mutations below index `sites`,
    # `unsafe_contexts` and `files` as records, so decode once here (a fresh measurement's
    # body is already the view).
    body = decode_body(body)
    baseline = census_findings(body, surface)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline, "specificity_holds":
                    False, "mutations": {}}

    def check(label: str, mutated: dict, marker: str) -> bool:
        # The mutated body shares every unchanged sub-list with the original; a census body is
        # ~120,000 records and deep-copying it five times is minutes of pure allocation for a test
        # that only replaces a handful of rows.
        found = census_findings(mutated, surface)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {
            "caught": caught,
            "findings": len(found),
            "delta": len(found) - len(baseline),
            "marker": marker,
        }
        return caught

    # m1: add a raw dereference no compiler reported (a fabricated operation).
    def add_raw_deref() -> dict:
        sites = list(body.get("sites") or [])
        forged = dict(sites[0])
        forged["site_id"] = "us-forged-raw-deref"
        forged["operation_kind"] = "RAW_POINTER_DEREFERENCE"
        forged["context_id"] = "uc-not-a-real-context"
        sites.append(forged)
        return {**body, "sites": sites}

    m1 = check("add_raw_deref", add_raw_deref(), "which the compiler did not report")

    # m2: hide unsafe in a macro by dropping the macro-generated context that carries it.
    def hide_macro() -> dict:
        ctxs = list(body.get("unsafe_contexts") or [])
        victim = next((c for c in ctxs if c.get("macro_provenance")), None)
        if victim is None:
            return body
        return {**body, "unsafe_contexts": [c for c in ctxs if c is not victim]}

    m2 = check("hide_unsafe_in_macro", hide_macro(), "which the compiler did not report")

    # m3: remove a context's SAFETY contract while it still has sites.
    def remove_contract() -> dict:
        ctxs = list(body.get("unsafe_contexts") or [])
        for idx, ctx in enumerate(ctxs):
            if ctx.get("site_ids"):
                ctxs[idx] = {**ctx, "safety_contract": ""}
                return {**body, "unsafe_contexts": ctxs}
        return body

    m3 = check("remove_safety_contract", remove_contract(), "must state its safety contract")

    # m4: forge a site as safe (not compiler-derived).
    def forge_safe() -> dict:
        sites = list(body.get("sites") or [])
        if sites:
            sites[0] = {**sites[0], "compiler_derived": False}
        return {**body, "sites": sites}

    m4 = check("forge_site_safe", forge_safe(), "is not compiler-derived")

    # m5: drop a shipped file from the census.
    def drop_file() -> dict:
        return {**body, "files": (body.get("files") or [])[1:]}

    m5 = check("drop_file", drop_file(), "is not accounted for")

    # m6: fuse two operations in one context into a single site -- the defect this correction
    # fixes. The dropped site is removed from both `sites` and the context's `site_ids`, so the
    # back-reference stays consistent and only the source re-derivation (N operations -> N sites)
    # catches it.
    def fuse_two_operations() -> dict:
        sites = list(body.get("sites") or [])
        by_ctx: dict[str, list[dict]] = {}
        for s in sites:
            by_ctx.setdefault(s.get("context_id"), []).append(s)
        victim = next((cid for cid, rows in by_ctx.items() if len(rows) >= 2), None)
        if victim is None:
            return body
        dropped = by_ctx[victim][-1].get("site_id")
        new_sites = [s for s in sites if s.get("site_id") != dropped]
        new_ctxs = []
        for c in body.get("unsafe_contexts") or []:
            if c.get("context_id") == victim:
                c = {**c, "site_ids": [i for i in c.get("site_ids") or [] if i != dropped]}
            new_ctxs.append(c)
        return {**body, "sites": new_sites, "unsafe_contexts": new_ctxs}

    m6 = check("fuse_two_operations", fuse_two_operations(), "must yield N sites")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and m6 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synthetic_body() -> dict:
    """A tiny well-formed census body, built without a compiler, for the self-test.

    The context is a **real** multi-operation region of `src/aes.rs` -- `get_u32`'s
    `unsafe { u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]) }` -- so the body's sites
    are the actual operations the source enumerates there and `census_findings`'s source
    re-derivation agrees with it. It holds eight operations (four dereferences, three method
    calls and one function call), which is the point: one context, eight sites.
    """
    file = "src/aes.rs"
    raw = (REPO_ROOT / file).read_bytes()
    bs, be = 3158, 3226
    kind = "UNSAFE_BLOCK"
    starts = _byte_line_starts(raw)
    cid = _context_id(file, bs, be, kind)
    sites: list[dict] = []
    site_ids: list[str] = []
    sites_by_kind: dict[str, int] = {}
    for op_kind, s, e, ln, col in _context_operations(file, raw, bs, be, [], kind, starts):
        sid = _site_id(file, s, e, op_kind)
        site_ids.append(sid)
        sites_by_kind[op_kind] = sites_by_kind.get(op_kind, 0) + 1
        sites.append({"site_id": sid, "file": file, "line": ln, "column": col,
                      "operation_kind": op_kind, "context_id": cid, "span": [s, e, ln, col],
                      "compiler": COMPILER_CLAUSE, "compiler_derived": True,
                      "exposure_class": "INTERNAL_REACHABLE", "risk_tier": "S4",
                      "safety_obligation_ids": [], "evidence": [],
                      "macro_provenance": "synthetic!@src/aes.rs:69<-src/aes.rs:1",
                      "classification_method": "context-span-op-scan:v2"})
    own, _base = _own_text(raw, bs, be, [])
    ctx_kinds = sorted(set(classify_operations(tokenize(own))))
    site_kind_set = sorted({s["operation_kind"] for s in sites})
    return {
        "rule": {}, "toolchain": {"rustc": "synthetic"},
        "files": [{"census_id": f"sc:{file}", "path": file, "kind": "RUST_SOURCE",
                   "language": "rust", "origin": "FIRST_PARTY", "shipped": True,
                   "file_sha256": sha256_file(REPO_ROOT / file),
                   "unsafe_operations": len(sites), "evidence": []}],
        "unsafe_contexts": [{"context_id": cid, "kind": kind, "file": file, "line": 70,
                             "span": [bs, be, 70, 5],
                             "safety_contract": "// SAFETY: synthetic", "site_ids": site_ids,
                             "contract_state": "STATED",
                             "macro_provenance": "synthetic!@src/aes.rs:69<-src/aes.rs:1",
                             "evidence": []}],
        "sites": sites,
        "crosschecks": {"geiger": {"status": "unavailable", "note": "synthetic"},
                        "lexical": {"unsafe_keyword_occurrences": 1},
                        "context_tokenizer": {
                            "contexts": 1,
                            "contexts_reconciled": 1 if ctx_kinds == site_kind_set else 0,
                            "contexts_differing": 0 if ctx_kinds == site_kind_set else 1}},
        "loc": {"rust_physical_loc": 10, "rust_code_loc": 8, "safe_rust_code_loc": 6,
                "unsafe_context_code_loc": 2},
        "counts": {"files": 1, "unsafe_contexts": 1, "sites": len(sites),
                   "operations": len(sites), "contexts_with_operations": 1,
                   "max_operations_in_context": len(sites), "generated_files": 0,
                   "sites_by_kind": dict(sorted(sites_by_kind.items()))},
        "residuals": [{"source": "geiger", "class": "evidence_missing", "detail": "synthetic"}],
        "non_claims": [],
    }


def self_test() -> int:
    """Prove the guard refuses the host, the tokenizer classifies, and the control is honest."""
    failures: list[str] = []

    refusal = phase25_guard.host_refusal_reasons("ms_census.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of ms_census.py")

    # Tokenizer: a pointer type is not a dereference; a dereference is; a method is a method.
    if "RAW_POINTER_DEREFERENCE" not in classify_operations(tokenize("*p")):
        failures.append("tokenizer did not see `*p` as a raw dereference")
    if "RAW_POINTER_DEREFERENCE" in classify_operations(tokenize("x: *const u8")):
        failures.append("tokenizer read the pointer type `*const u8` as a dereference")
    if "RAW_POINTER_WRITE" not in classify_operations(tokenize("p.write(x)")):
        failures.append("tokenizer did not see `p.write(x)` as a raw write")
    if "INLINE_ASM" not in classify_operations(tokenize("asm!(\"nop\")")):
        failures.append("tokenizer did not see `asm!` as inline assembly")

    # The operation-level extractor must see *two* dereferences where the context-level classifier
    # sees one kind -- the distinction this correction is about.
    two = enumerate_operations(tokenize("unsafe { *a = 1; *b = 2; }"))
    derefs = [o for o in two if o[0] == "RAW_POINTER_DEREFERENCE"]
    if len(derefs) != 2:
        failures.append(f"the operation enumerator saw {len(derefs)} dereference(s) in a two-op "
                        f"context, not 2")
    if len(derefs) == 2 and derefs[0][1:] == derefs[1][1:]:
        failures.append("the two operations share a span, so they would share a site id")
    if classify_operations(tokenize("unsafe { *a = 1; *b = 2; }")) != ["RAW_POINTER_DEREFERENCE"]:
        failures.append("the context-level classifier no longer returns one kind for two derefs")

    body = _synthetic_body()
    surface = [e for e in shipped_surface() if e["path"] == "src/aes.rs"]
    if len(body["sites"]) < 2:
        failures.append("the synthetic body's context does not hold several operations")
    control = census_sensitivity_control(body, surface=surface)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-census] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-census] self-test ok: the guard refuses the host; the tokenizer distinguishes a "
          "dereference from a pointer type; the operation enumerator sees two operations where "
          "the context classifier sees one kind; and all six seeded census mutations are caught "
          "with specificity holding")
    return 0


# --------------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------------

def _write_census(path: Path, doc: dict) -> None:
    """Write the census as compact, key-sorted, deterministic JSON.

    A deliberate, documented deviation from `atlas_common.write_json`'s `indent=2`: the census is
    ~120,000 records (one per compiler-reported context and per site), and pretty-printing it
    multiplies the file without adding a byte of evidence. Determinism is preserved -- keys are
    sorted and separators fixed -- and `body_hash` is computed over the body, so nothing that is
    compared depends on the file's whitespace.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _measure() -> int:
    """Run the compiler, build the census, and write it.

    Measurement: it runs clippy and the pinned nightly, so it is refused on the host and is not
    listed among `evidence_determinism.py`'s generators (see that file's why-comment).
    """
    global _CANDIDATE_COMMIT
    _CANDIDATE_COMMIT = _resolve_commit()
    tc = _toolchain()
    expansion = expand_source(tc)
    _run_geiger()
    diagnostics = _clippy_diagnostics()
    body = build_body(tc, expansion, diagnostics)

    # The expanded source's digest is an input: it pins the expansion basis without committing a
    # 34 MB file that the pinned toolchain reproduces.
    inputs = [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-census-tool", path=TOOL),
        InputRef(name="cargo-manifest", path=CARGO_TOML),
        InputRef(name="rust-toolchain", path=TOOLCHAIN_FILE),
        InputRef(name="crate-sources", sha256=content_hash(
            {f["path"]: f["file_sha256"] for f in body["files"]}),
            note=("content hash of the sorted (path, sha256) pairs of every shipped first-party "
                  "file; the crate source tree has no single path to hash")),
        InputRef(name="clippy-json", sha256=sha256_file(WORK / "clippy.json"),
                 note="the raw `--message-format=json` clippy stream the census was derived from"),
    ]
    if expansion["sha256"] != "unknown":
        inputs.append(InputRef(name="expanded-crate-source", sha256=expansion["sha256"],
                               note=expansion["note"]))

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    # The on-disk body is the compact columnar form; `body` stays the view for the checks
    # and the printed counts below.
    encoded = encode_body(body)
    doc = envelope(kind="phase25-source-census", authority=auth.id, inputs=inputs, body=encoded,
                   generator=GENERATOR)
    doc["body_hash"] = content_hash(encoded)
    _write_census(OUT, doc)

    c = body["counts"]
    print(f"[ms-census] {c['files']} shipped file(s) ({c['rust_files']} rust, {c['c_files']} c, "
          f"{c['generated_files']} generated); {c['unsafe_contexts']} unsafe context(s); "
          f"{c['sites']} compiler-derived operation site(s) "
          f"({c['sites']}/{c['unsafe_contexts']} operations per context, max "
          f"{c['max_operations_in_context']} in one context)")
    print(f"  expansion: {expansion['status']} "
          f"(nightly {tc['nightly_rustc']}, sha256 {expansion['sha256'][:16]})")
    print(f"  contexts by kind: {c['contexts_by_kind']}")
    print(f"  sites by kind: {c['sites_by_kind']}")
    loc = body["loc"]
    print(f"  loc: physical={loc['rust_physical_loc']} code={loc['rust_code_loc']} "
          f"safe={loc['safe_rust_code_loc']} unsafe_context={loc['unsafe_context_code_loc']}")
    print(f"  crosschecks: geiger={body['crosschecks']['geiger']['status']} "
          f"residuals={body['crosschecks']['residual_count']} "
          f"uncontracted={c['uncontracted_contexts']} contexts_without_site="
          f"{c['contexts_without_site']}")
    print(f"  -> {rel(OUT)} all_pass={not census_findings(body)}")
    return 0 if not census_findings(body) else 1


def _check() -> int:
    """Re-run the pure checks over the committed census, without a compiler."""
    if not OUT.is_file():
        print(f"[ms-census] {rel(OUT)} is absent; run --measure")
        return 1
    doc = json.loads(OUT.read_text(encoding="utf-8"))
    body = decode_body(doc.get("body", doc))
    problems = census_findings(body)
    if problems:
        print(f"[ms-census] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-census] check ok: {c['files']} file(s), {c['unsafe_contexts']} unsafe context(s), "
          f"{c['sites']} compiler-derived site(s); every check holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="run the compiler and write artifacts/phase25/source-census.json")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed census")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the guard refuses the host and the control is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first: this tool runs the compiler.
    phase25_guard.require_admitted()

    if args.self_test:
        return self_test()

    if args.measure:
        return _measure()

    if args.check:
        return _check()

    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
