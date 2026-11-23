#!/usr/bin/env python3
"""openssl-rs -- classify every unsafe site by obligation and impact (ETP-T4).

Why this exists
---------------
`forensics/tools/unsafe_footprint.py` counts `unsafe` keywords.  A count answers
"how much text says unsafe", not "what must be true for this operation to be
sound" and not "what happens if it is not".  This tool is the ETP-T4 inventory:
one row per lexically identified unsafe construct, with an obligation class, an
impact class, the source-stated contract, the narrowest boundary the site sits
inside, and the control or argument that bears on it -- or `none`.

The scanner is heuristic, and says so everywhere
------------------------------------------------
The unit is a comment/string-aware lexical scan, not a compiler-derived census
and not a HIR/MIR walk.  `unsafe_footprint.code_only` is reused for the
comment/string view, so the two tools cannot disagree about what text is code.
The operation class of a site is a deterministic mapping from the construct's
kind, its name and the tokens in its body.  A site's contract is the contiguous
`SAFETY:` comment (or `# Safety` doc section) immediately above it; whether that
text is an *argument* or a *restatement* is decided by the lexical heuristic
recorded in `heuristic.restatement` below, whose limits are stated there.  None
of these judgements is a soundness result.  The row records what evidence
exists; it does not say the obligation is met.

What "vacuous" means here
-------------------------
Four refusals are implemented, each with a control in
`forensics/tools/tests/test_unsafe_obligations.py`:

* `ET4_DISCHARGE_WITHOUT_CONTROL` -- a record claims a discharge and names no
  control that could fail.
* `ET4_VACUOUS_REPORTED_SATISFIED` -- an obligation whose precondition is
  unreachable in every caller, reported as satisfied.
* `ET4_CALLER_OBLIGATION_UNESTABLISHED` -- a `SAFETY:` comment that cites a
  caller obligation no production caller establishes.
* `ET4_ASSERTION_CANNOT_FAIL` -- a test assertion that is tautological, or a
  test runner that reports success for an inverted assertion.

Modes
-----
    python3 forensics/tools/unsafe_obligations.py inventory
    python3 forensics/tools/unsafe_obligations.py axioms
    python3 forensics/tools/unsafe_obligations.py validate
    python3 forensics/tools/unsafe_obligations.py show <site-id>
    python3 forensics/tools/unsafe_obligations.py summary

Exit status: 0 when the requested operation succeeded; 1 for a refusal; 2 for
a usage error.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import unsafe_footprint as lexical  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"
TOOL = Path(__file__).resolve()
OUTDIR = REPO_ROOT / "evidence" / "etp-t4"
SITES_OUT = OUTDIR / "SAFETY-SITES.json"
AXIOMS_OUT = OUTDIR / "AXIOMS.json"
VACUITY_OUT = OUTDIR / "VACUITY.json"

SITES_SCHEMA = "openssl-rs/etp/unsafe-sites/1"
AXIOMS_SCHEMA = "openssl-rs/etp/axioms/1"
VACUITY_SCHEMA = "openssl-rs/etp/vacuity/1"

# ---------------------------------------------------------------------------
# Closed vocabularies.  The first ten classes are the item's list; the eleventh
# is unavoidable in a complete inventory.  An `unsafe` call whose body does no
# raw work of its own delegates the callee's contract to the caller; folding it
# into `ffi_call` or `raw_dereference` would misdescribe it.
# ---------------------------------------------------------------------------
OBLIGATION_CLASSES = (
    "ownership_adoption",
    "borrowed_view_formation",
    "raw_dereference",
    "ffi_call",
    "callback_reentrancy_edge",
    "cpu_intrinsic",
    "layout_repr_assumption",
    "uninitialised_to_initialised",
    "concurrency_publication",
    "abi_export",
    "delegated_unsafe_contract",
)

IMPACTS = (
    "memory_unsafety",
    "secret_disclosure",
    "cryptographic_wrong_result",
    "availability",
    "compatibility_divergence",
)

# Primary impact first; the full set is what the site can reach if the
# obligation is unmet.  The mapping is a classification, not a measurement.
CLASS_IMPACT: dict[str, tuple[str, ...]] = {
    "ownership_adoption": ("memory_unsafety", "secret_disclosure"),
    "borrowed_view_formation": ("memory_unsafety",),
    "raw_dereference": ("memory_unsafety", "secret_disclosure"),
    "ffi_call": ("memory_unsafety", "compatibility_divergence"),
    "callback_reentrancy_edge": ("memory_unsafety", "availability"),
    "cpu_intrinsic": ("cryptographic_wrong_result", "memory_unsafety"),
    "layout_repr_assumption": ("memory_unsafety", "compatibility_divergence"),
    "uninitialised_to_initialised": ("memory_unsafety", "secret_disclosure"),
    "concurrency_publication": ("memory_unsafety", "availability"),
    "abi_export": ("memory_unsafety", "compatibility_divergence"),
    "delegated_unsafe_contract": ("memory_unsafety",),
}

CONTRACT_STATES = ("absent", "restatement", "argument")
COVERAGE_KINDS = ("none", "argument", "test", "instrument")
BOUNDARY_KINDS = ("UNCONFINED", "owner_type", "constructor", "module", "abi_export")
SITE_KINDS = ("unsafe_block", "unsafe_fn", "unsafe_impl", "unsafe_trait", "unsafe_extern", "export")

# ---------------------------------------------------------------------------
# Restatement heuristic.  This is lexical.  It asks whether the text contains a
# support relation (cause, checked property, reference to a witness) or only
# names the operation/property.  It cannot decide whether an argument is true,
# sufficient, or applicable; it only refuses to call a bare restatement an
# argument.  The limits are part of the record.
# ---------------------------------------------------------------------------
ARGUMENT_MARKERS = (
    "because",
    "since",
    "therefore",
    "thus",
    "hence",
    "as a result",
    "follows",
    "given that",
    "provided that",
    "by construction",
    "invariant",
    "catalogue",
    "outlives",
    "exclusive access",
    "not aliased",
    "no aliasing",
    "provenance",
    "same allocation",
    "same block",
    "within bounds",
    "in bounds",
    "null check",
    "checked",
    "verified",
    "validated",
    "proven",
    "guaranteed",
    "ensured",
    "established",
    "released once",
    "exactly once",
    "points to",
    "lives for",
    "valid for",
    "same type",
    "same layout",
    "repr(c)",
    "line ",
    "docs/",
    "section ",
    "§",
)

REFERENCE_MARKERS = (
    "safety:",
    "# safety",
    "see ",
    "documented at",
    "justified by",
    "proved by",
    "witness",
    "control",
    "test ",
    "miri",
    "asan",
)

RESTATEMENT_PATTERNS = (
    re.compile(r"^(?:this|it)\s+is\s+(?:an?\s+)?unsafe\s+(?:call|operation|block|function)\b"),
    re.compile(r"^(?:calls?|invokes?|dereferences?|reads?|writes?|accesses?|uses?)\s+"
               r"(?:the\s+|an?\s+)?(?:raw\s+|unsafe\s+)?"
               r"(?:pointer|function|operation|block|api)\b"),
    re.compile(r"^(?:the\s+)?(?:pointer|value|caller)\s+(?:is|must\s+be)\s+"
               r"(?:valid|non-null|null|initialised|initialized|aligned)\.?$"),
    re.compile(r"^(?:only\s+)?(?:used|called)\s+(?:internally|here)\b"),
    re.compile(r"^caller\s+(?:must\s+)?(?:ensure|guarantee)s?\s+(?:validity|safety)\.?$"),
    re.compile(r"^(?:the\s+)?(?:pointer|value)\s+is\s+valid\.?$"),
    re.compile(r"^no\s+safety\s+(?:concerns|issues)\b"),
    re.compile(r"^internal\s+(?:helper|use)\b"),
)


def _normalise_contract(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^(?://+[!/]?\s*)+", "", text)
    text = re.sub(r"^(?:SAFETY|#\s*Safety|Safety)\s*:?\s*", "", text, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", text).strip()


def classify_contract(raw: str | None) -> tuple[str, str, str]:
    """`(state, reason, normalised_text)` for a source-stated contract.

    `state` is `absent`, `restatement` or `argument`.  `reason` names the branch
    the lexical heuristic took, so a disagreement can be located without
    guessing.  The function is deterministic and has no side effects.
    """
    if raw is None or not raw.strip():
        return "absent", "no_comment", ""
    body = _normalise_contract(raw)
    if not body:
        return "absent", "empty_after_marker", ""
    words = re.findall(r"[a-z0-9_]+", body.lower())
    if len(words) < 4:
        return "restatement", "too_short", body
    low = body.lower()
    if any(marker in low for marker in ARGUMENT_MARKERS):
        return "argument", "support_marker", body
    if any(marker in low for marker in REFERENCE_MARKERS):
        return "argument", "reference_marker", body
    for pattern in RESTATEMENT_PATTERNS:
        if pattern.search(low):
            return "restatement", "operation_paraphrase", body
    return "restatement", "property_assertion_without_support", body


# ---------------------------------------------------------------------------
# Source scanning
# ---------------------------------------------------------------------------
RE_UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
RE_UNSAFE_FN = re.compile(
    r"\bunsafe\s+(?:extern\s+\"[^\"]*\"\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RE_UNSAFE_IMPL = re.compile(r"\bunsafe\s+impl\b")
RE_UNSAFE_TRAIT = re.compile(r"\bunsafe\s+trait\s+([A-Za-z_][A-Za-z0-9_]*)")
RE_UNSAFE_EXTERN = re.compile(r"\bunsafe\s+extern\s+(?:\"[^\"]*\"\s*)?\{")
RE_FN = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
RE_IMPL = re.compile(r"\bimpl\b")
RE_TRAIT = re.compile(r"\btrait\s+([A-Za-z_][A-Za-z0-9_]*)")
RE_MOD = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)")
RE_TEST_CFG = re.compile(r"#\s*\[\s*cfg\s*\(\s*(?:all\s*\(\s*)?test\b")
RE_EXPORT = re.compile(r"#\s*\[\s*(?:no_mangle|export_name\s*=\s*\"[^\"]*\")\s*\]")
RE_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
RE_BRACE = re.compile(r"[{}]")

OPERATION_PATTERNS: dict[str, re.Pattern[str]] = {
    "transmute": re.compile(r"\btransmute\s*(?:::\s*<[^>]*>)?\s*\("),
    "from_raw_parts": re.compile(r"\bfrom_raw_parts(?:_mut)?\s*(?:::\s*<[^>]*>)?\s*\("),
    "set_len": re.compile(r"\.set_len\s*\("),
    "assume_init": re.compile(
        r"\bassume_init(?:_read|_ref|_mut|_slice_assume_init_ref|_slice_assume_init_mut)?\s*\("
    ),
    "static_mut": re.compile(r"\bstatic\s+mut\b"),
    "intrinsic": re.compile(
        r"(?:\b(?:core|std)::arch\b|\b_mm(?:256|512)?_\w+|\b__m(?:128|256|512)\b|"
        r"\basm!\s*\(|\bglobal_asm!\s*\(|\brdtsc\b|\bcpuid\b)"
    ),
    "maybe_uninit": re.compile(r"\bMaybeUninit\b"),
    "atomic_publication": re.compile(
        r"\bAtomic(?:Ptr|Usize|Isize|Bool|U8|U16|U32|U64|I8|I16|I32|I64)\b|"
        r"\bcompare_exchange(?:_weak)?\s*\(|\bfetch_(?:add|sub|or|and|xor)\s*\("
    ),
}

RAW_OPS = ("transmute", "from_raw_parts", "set_len", "assume_init", "static_mut", "intrinsic")

OWNERSHIP_TOKENS = (
    "from_raw",
    "into_raw",
    "adopt",
    "take_ownership",
    "OwnedBlock",
    "OwnedBuf",
    "OwnedStr",
    "OwnedRaw",
    "OwnedCtx",
    "SecretBuf",
    "CtxDestroy",
    "Box::from_raw",
    "Arc::from_raw",
    "drop_in_place",
    "ManuallyDrop",
    "OPENSSL_clear_free",
)
BORROWED_TOKENS = (
    "from_raw_parts",
    "as_slice",
    "as_mut_slice",
    "as_ref",
    "parts",
    "split_at",
    "from_utf8_unchecked",
    "slice::from_raw",
)
UNINIT_TOKENS = ("MaybeUninit", "assume_init", "set_len", "uninitialized", "zeroed", "alloc_raw")
CONCURRENCY_TOKENS = (
    "static mut",
    "Atomic",
    "Ordering::",
    "compare_exchange",
    "UnsafeCell",
    "Send",
    "Sync",
)
FFI_TOKENS = ("extern \"C\"", "libc::", "::sys::", "ffi::", "OPENSSL_", "CRYPTO_")
CALLBACK_TOKENS = ("callback", "cb", "extern \"C\" fn", "Option<extern")
INTRINSIC_TOKENS = ("core::arch", "std::arch", "_mm", "__m", "asm!", "global_asm!", "rdtsc", "cpuid")
LAYOUT_TOKENS = ("transmute", "repr(C)", "repr(", "offset_of", "union ")


def body_open(code: str, pos: int, matches: dict[int, int]) -> int | None:
    """The first `{` at or after `pos` that is not preceded by a `;`."""
    brace = code.find("{", pos)
    semi = code.find(";", pos)
    if brace < 0 or (0 <= semi < brace):
        return None
    return brace if brace in matches else None


def body_close(code: str, brace: int, matches: dict[int, int]) -> int | None:
    return matches.get(brace)


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


@dataclass
class Decl:
    kind: str
    name: str
    start: int
    body_start: int
    body_end: int
    line: int


@dataclass
class Site:
    id: str
    path: str
    line: int
    column: int
    kind: str
    symbol: str
    start: int
    end: int
    body_start: int
    body_end: int
    text: str


@dataclass
class FileScan:
    path: str
    text: str
    code: str
    code_kept: str
    matches: dict[int, int]
    decls: list[Decl]
    test_ranges: list[tuple[int, int, str]]
    sites: list[Site] = field(default_factory=list)


def _decl_name_impl(header: str) -> str:
    header = re.sub(r"\bimpl\b", "", header, count=1)
    header = re.sub(r"<[^>]*>", " ", header)
    header = re.sub(r"\bwhere\b.*$", " ", header)
    if " for " in header:
        header = header.split(" for ", 1)[1]
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", header)
    return tokens[-1] if tokens else "impl"


def _collect_decls(code: str, matches: dict[int, int], text: str) -> list[Decl]:
    decls: list[Decl] = []
    for m in RE_FN.finditer(code):
        brace = body_open(code, m.end(), matches)
        if brace is None:
            continue
        end = body_close(code, brace, matches)
        if end is None:
            continue
        decls.append(Decl("fn", m.group(1), m.start(), brace, end, line_of(text, m.start())))
    for m in RE_IMPL.finditer(code):
        brace = body_open(code, m.end(), matches)
        if brace is None:
            continue
        end = body_close(code, brace, matches)
        if end is None:
            continue
        decls.append(
            Decl("impl", _decl_name_impl(code[m.start():brace]), m.start(), brace, end,
                 line_of(text, m.start()))
        )
    for m in RE_TRAIT.finditer(code):
        brace = body_open(code, m.end(), matches)
        if brace is None:
            continue
        end = body_close(code, brace, matches)
        if end is None:
            continue
        decls.append(Decl("trait", m.group(1), m.start(), brace, end, line_of(text, m.start())))
    for m in RE_MOD.finditer(code):
        brace = body_open(code, m.end(), matches)
        if brace is None:
            continue
        end = body_close(code, brace, matches)
        if end is None:
            continue
        decls.append(Decl("mod", m.group(1), m.start(), brace, end, line_of(text, m.start())))
    decls.sort(key=lambda d: (d.start, -(d.body_end - d.start)))
    return decls


def _test_ranges(code: str, matches: dict[int, int]) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    for m in RE_TEST_CFG.finditer(code):
        mod = RE_MOD.search(code, m.end(), m.end() + 400)
        if not mod:
            continue
        brace = body_open(code, mod.end(), matches)
        if brace is None:
            continue
        end = body_close(code, brace, matches)
        if end is None:
            continue
        ranges.append((m.start(), end, mod.group(1)))
    return ranges


def _contexts(code: str, code_kept: str, matches: dict[int, int], text: str) -> list[Site]:
    sites: list[Site] = []

    def add(kind: str, name: str, start: int, brace: int) -> None:
        end = body_close(code, brace, matches)
        if end is None:
            return
        line = line_of(text, start)
        col = start - (text.rfind("\n", 0, start) + 1) + 1
        sites.append(Site(
            id=_site_id(path="", start=start, end=end, kind=kind),
            path="", line=line, column=col, kind=kind, symbol=name,
            start=start, end=end, body_start=brace + 1, body_end=end,
            text=code[start:end + 1],
        ))

    for m in RE_UNSAFE_FN.finditer(code_kept):
        brace = body_open(code, m.end(), matches)
        if brace is not None:
            add("unsafe_fn", m.group(1), m.start(), brace)
    for m in RE_UNSAFE_BLOCK.finditer(code):
        brace = m.end() - 1
        if brace in matches:
            add("unsafe_block", "", m.start(), brace)
    for m in RE_UNSAFE_IMPL.finditer(code):
        brace = body_open(code, m.end(), matches)
        if brace is not None:
            header = code[m.start():brace]
            add("unsafe_impl", _decl_name_impl(header), m.start(), brace)
    for m in RE_UNSAFE_TRAIT.finditer(code):
        brace = body_open(code, m.end(), matches)
        if brace is not None:
            add("unsafe_trait", m.group(1), m.start(), brace)
    for m in RE_UNSAFE_EXTERN.finditer(code_kept):
        brace = m.end() - 1
        if brace in matches:
            add("unsafe_extern", "", m.start(), brace)
    sites.sort(key=lambda s: (s.start, -(s.end - s.start)))
    return sites


def _site_id(path: str, start: int, end: int, kind: str) -> str:
    digest = hashlib.sha256(f"{path}\0{start}\0{end}\0{kind}".encode("utf-8")).hexdigest()
    return "us-" + digest[:16]


def _comment_above(text: str, pos: int, max_lines: int = 40) -> tuple[str | None, str]:
    """The contiguous comment/doc block immediately above `pos`.

    Returns `(raw_comment_text, source)` where source is `immediate`,
    `enclosing` or `none`.  Attributes and blank lines between comments and the
    declaration are tolerated; the first code line stops the walk.
    """
    line_start = text.rfind("\n", 0, pos) + 1
    lines: list[str] = []
    cursor = line_start
    blank_run = 0
    for _ in range(max_lines):
        if cursor == 0:
            break
        prev_end = cursor - 1
        prev_start = text.rfind("\n", 0, prev_end) + 1
        raw = text[prev_start:prev_end]
        stripped = raw.strip()
        if not stripped:
            blank_run += 1
            if blank_run > 2:
                break
            cursor = prev_start
            continue
        if stripped.startswith(("//", "/*", "*", "///", "//!", "#[")):
            lines.append(raw)
            blank_run = 0
            cursor = prev_start
            continue
        break
    if not lines:
        return None, "none"
    block = "\n".join(reversed(lines))
    if "SAFETY" in block or "Safety" in block:
        return block, "immediate"
    return block if block else None, "immediate"


def _extract_safety(text: str) -> str | None:
    """The SAFETY paragraph from a comment block, or None."""
    lines = text.split("\n")
    out: list[str] = []
    active = False
    for line in lines:
        stripped = re.sub(r"^\s*(?://+[!/]?|/\*+|\*+)\s?", "", line)
        if re.search(r"\bSAFETY\s*:|#\s*Safety\b|\bSafety\s*:", stripped, re.IGNORECASE):
            active = True
            out.append(stripped)
            continue
        if active:
            if stripped.startswith(("#", "///")) and "Safety" not in stripped:
                continue
            out.append(stripped)
    return "\n".join(out).strip() if out else None


def _feature_flags(site: Site) -> dict[str, bool]:
    body = site.text
    name = site.symbol
    low = body.lower()
    return {
        "ownership": any(tok in body for tok in OWNERSHIP_TOKENS)
        or any(tok in name for tok in ("adopt", "from_raw", "into_raw", "take")),
        "borrowed": any(tok in body for tok in BORROWED_TOKENS)
        or any(tok in name for tok in ("as_slice", "as_ref", "parts", "get0", "get1")),
        "uninit": any(tok in body for tok in UNINIT_TOKENS),
        "concurrency": any(tok in body for tok in CONCURRENCY_TOKENS),
        "ffi": any(tok in body for tok in FFI_TOKENS),
        "callback": any(tok in low for tok in CALLBACK_TOKENS),
        "intrinsic": any(tok in body for tok in INTRINSIC_TOKENS),
        "layout": any(tok in body for tok in LAYOUT_TOKENS),
        "raw_deref": bool(re.search(r"(?:\*\s*(?:mut|const)\s+[A-Za-z_(]|\.offset\s*\(|\.add\s*\(|"
                                    r"\.sub\s*\(|ptr::(?:read|write|copy|swap))", body)),
        "export": False,
        "send_sync": ("Send" in body or "Sync" in body),
    }


def classify_site(site: Site) -> str:
    flags = _feature_flags(site)
    kind = site.kind
    if kind == "export":
        return "abi_export"
    if kind == "unsafe_impl":
        if flags["send_sync"]:
            return "concurrency_publication"
        if flags["layout"]:
            return "layout_repr_assumption"
        return "delegated_unsafe_contract"
    if kind == "unsafe_trait":
        return "delegated_unsafe_contract"
    if kind == "unsafe_extern":
        return "ffi_call"
    if flags["ownership"]:
        return "ownership_adoption"
    if flags["borrowed"]:
        return "borrowed_view_formation"
    if flags["uninit"]:
        return "uninitialised_to_initialised"
    if flags["intrinsic"]:
        return "cpu_intrinsic"
    if flags["layout"]:
        return "layout_repr_assumption"
    if flags["concurrency"]:
        return "concurrency_publication"
    if flags["ffi"]:
        return "ffi_call"
    if flags["callback"]:
        return "callback_reentrancy_edge"
    if flags["raw_deref"]:
        return "raw_dereference"
    return "delegated_unsafe_contract"


OWNER_TYPES = (
    "OwnedBlock", "OwnedBuf", "OwnedStr", "OwnedRaw", "OwnedCtx", "SecretBuf",
    "CtxDestroy", "ManuallyDrop",
)


def classify_boundary(site: Site, module: str, path: str) -> tuple[str, str]:
    if site.kind == "export":
        return "abi_export", f"export:{site.symbol}"
    for owner in OWNER_TYPES:
        if owner in site.text or owner in site.symbol:
            return "owner_type", f"owner:{owner}"
    if any(tok in site.symbol for tok in ("adopt", "from_raw", "into_raw", "take")):
        return "constructor", f"constructor:{site.symbol}"
    if module in lexical.BOUNDARY_MODULES and (
        path.startswith("src/runtime/mem")
        or path.startswith("src/runtime/bio/")
        or path.startswith("src/runtime/owned")
        or path.startswith("src/ffi/")
        or path.startswith("src/dso/")
    ):
        return "module", f"module:{path}"
    return "UNCONFINED", "UNCONFINED"


def classify_coverage(site: Site, path: str, in_test: str | None,
                      contract_state: str) -> tuple[str, str]:
    if in_test:
        return "test", f"test-module:{in_test}"
    if path.endswith("runtime/miri_tcb.rs") or site.symbol.startswith("miri_"):
        return "instrument", "miri-tcb-suite"
    if path in ("src/runtime/mem.rs", "src/async/arch/async_posix.rs") and (
        "as *mut ()" in site.text or "transmute" in site.text
    ):
        return "instrument", "provenance-court"
    if contract_state == "argument":
        return "argument", "source-contract"
    return "none", "none"


class Scanner:
    def __init__(self, src: Path = SRC) -> None:
        self.src = src
        self.files: list[str] = []
        self.scans: dict[str, FileScan] = {}
        self.sites: list[Site] = []
        self.operations: list[dict[str, Any]] = []
        self.contracts: dict[str, str] = {}
        self.contract_by_prefix: dict[str, str] = {}
        self.source_hash = ""
        self.total_lines = 0

    def _read(self) -> None:
        digest = hashlib.sha256()
        files = sorted(self.src.rglob("*.rs"))
        for path in files:
            rel = path.relative_to(REPO_ROOT).as_posix()
            text = path.read_text(encoding="utf-8", errors="replace")
            self.total_lines += text.count("\n") + (0 if text.endswith("\n") or not text else 1)
            digest.update(rel.encode("utf-8"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest().encode())
            digest.update(b"\n")
            code = lexical.code_only(text)
            code_kept = lexical.code_only(text, keep_strings=True)
            matches: dict[int, int] = {}
            stack: list[int] = []
            for m in RE_BRACE.finditer(code):
                if m.group() == "{":
                    stack.append(m.start())
                elif stack:
                    opening = stack.pop()
                    matches[opening] = m.start()
                    matches[m.start()] = opening
            scan = FileScan(
                path=rel, text=text, code=code, code_kept=code_kept, matches=matches,
                decls=_collect_decls(code, matches, text),
                test_ranges=_test_ranges(code, matches),
            )
            scan.sites = _contexts(code, code_kept, matches, text)
            for site in scan.sites:
                site.path = rel
                site.id = _site_id(rel, site.start, site.end, site.kind)
            self.scans[rel] = scan
            self.files.append(rel)
        self.source_hash = digest.hexdigest()

    def _enclosing_decl(self, scan: FileScan, pos: int) -> Decl | None:
        best: Decl | None = None
        for decl in scan.decls:
            if decl.start <= pos <= decl.body_end:
                if best is None or (decl.body_end - decl.start) < (best.body_end - best.start):
                    best = decl
        return best

    def _enclosing_site(self, scan: FileScan, pos: int) -> Site | None:
        best: Site | None = None
        for site in scan.sites:
            if site.start <= pos <= site.end:
                if best is None or (site.end - site.start) < (best.end - best.start):
                    best = site
        return best

    def _in_test(self, scan: FileScan, pos: int) -> str | None:
        for start, end, name in scan.test_ranges:
            if start <= pos <= end:
                return name
        return None

    def _exports(self, scan: FileScan) -> list[Site]:
        out: list[Site] = []
        for m in RE_EXPORT.finditer(scan.code_kept):
            fn = RE_FN.search(scan.code, m.end(), m.end() + 800)
            if not fn:
                continue
            brace = body_open(scan.code, fn.end(), scan.matches)
            if brace is None:
                continue
            end = body_close(scan.code, brace, scan.matches)
            if end is None:
                continue
            body = scan.code[brace:end]
            raw_work = bool(
                re.search(r"\bunsafe\b|\*\s*(?:mut|const)\s+[A-Za-z_(]|from_raw|transmute|"
                          r"static\s+mut|ptr::", body)
            )
            if not raw_work:
                continue
            name = fn.group(1)
            line = line_of(scan.text, m.start())
            col = m.start() - (scan.text.rfind("\n", 0, m.start()) + 1) + 1
            out.append(Site(
                id=_site_id(scan.path, m.start(), end, "export"), path=scan.path,
                line=line, column=col, kind="export", symbol=name,
                start=m.start(), end=end, body_start=brace + 1, body_end=end,
                text=scan.code[m.start():end + 1],
            ))
        return out

    def build(self) -> None:
        self._read()
        for rel in self.files:
            scan = self.scans[rel]
            exports = self._exports(scan)
            contexts = scan.sites
            # An export whose declaration is the same source construct as an
            # unsafe fn is the same site; the ABI class wins.
            export_ranges = {(e.body_start, e.body_end) for e in exports}
            kept: list[Site] = []
            for site in contexts:
                if site.kind == "unsafe_fn" and (site.body_start, site.body_end) in export_ranges:
                    continue
                kept.append(site)
            scan.sites = sorted(kept + exports, key=lambda s: (s.start, -(s.end - s.start)))
            for site in scan.sites:
                decl = self._enclosing_decl(scan, site.start)
                if site.kind in ("unsafe_fn", "unsafe_impl", "unsafe_trait", "export") \
                        and site.symbol:
                    symbol = site.symbol
                elif decl is not None and decl.kind == "fn":
                    symbol = decl.name
                elif decl is not None:
                    symbol = f"{decl.kind}:{decl.name}"
                else:
                    symbol = f"file:{Path(rel).stem}"
                site.symbol = symbol
                in_test = self._in_test(scan, site.start)
                raw_comment, _ = _comment_above(scan.text, site.start)
                contract = _extract_safety(raw_comment) if raw_comment else None
                if contract is None:
                    enclosing = self._enclosing_decl(scan, site.start)
                    if enclosing is not None:
                        doc, _ = _comment_above(scan.text, enclosing.start)
                        contract = _extract_safety(doc) if doc else None
                state, reason, normalised = classify_contract(contract)
                if normalised:
                    full = hashlib.sha256(normalised.encode()).hexdigest()
                    self.contracts[full] = normalised
                    self.contract_by_prefix[full[:16]] = normalised
                klass = classify_site(site)
                impacts = CLASS_IMPACT[klass]
                parts = rel.split("/")
                module = parts[1] if len(parts) > 2 else Path(rel).stem
                bkind, bid = classify_boundary(site, module, rel)
                ckind, cid = classify_coverage(site, rel, in_test, state)
                self.sites.append({
                    "id": site.id, "path": rel, "line": site.line, "column": site.column,
                    "kind": site.kind, "symbol": symbol, "class": klass,
                    "impact": impacts[0], "impacts": list(impacts),
                    "contract_state": state, "contract_reason": reason,
                    "contract_sha256": hashlib.sha256(normalised.encode()).hexdigest()[:16]
                    if normalised else "",
                    "boundary_kind": bkind, "boundary_id": bid,
                    "coverage_kind": ckind, "coverage_id": cid,
                    "_site": site,
                })
            self._operations(scan)

    def _operations(self, scan: FileScan) -> None:
        contexts = sorted(scan.sites, key=lambda s: (s.end - s.start))
        for op, pattern in OPERATION_PATTERNS.items():
            for m in pattern.finditer(scan.code):
                pos = m.start()
                enclosing = None
                for site in contexts:
                    if site.start <= pos <= site.end:
                        enclosing = site
                        break
                if enclosing is None and op in RAW_OPS:
                    # An operation outside every unsafe construct is itself a
                    # site: the scanner records it rather than dropping it.
                    line = line_of(scan.text, pos)
                    self.operations.append({
                        "id": "op-" + hashlib.sha256(
                            f"{scan.path}\0{pos}\0{op}".encode()).hexdigest()[:16],
                        "path": scan.path, "line": line, "kind": op,
                        "enclosing_site": "", "standalone": True,
                    })
                    continue
                if enclosing is not None:
                    self.operations.append({
                        "id": "op-" + hashlib.sha256(
                            f"{scan.path}\0{pos}\0{op}".encode()).hexdigest()[:16],
                        "path": scan.path, "line": line_of(scan.text, pos), "kind": op,
                        "enclosing_site": enclosing.id, "standalone": False,
                    })


# ---------------------------------------------------------------------------
# Call graph for vacuity.  Identifier-followed-by-`(` is the call witness; it is
# a lexical over-approximation (method calls, definitions and macro uses are all
# matched), so every finding says `lexical_call_witness`.
# ---------------------------------------------------------------------------
def build_call_index(scans: dict[str, FileScan], names: set[str]) -> dict[str, list[tuple[str, int]]]:
    index: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for rel, scan in scans.items():
        for m in RE_CALL.finditer(scan.code):
            name = m.group(1)
            if name in names:
                index[name].append((rel, m.start()))
    return index


def _caller_evidence(scanner: Scanner, rel: str, pos: int) -> dict[str, Any]:
    scan = scanner.scans[rel]
    decl = scanner._enclosing_decl(scan, pos)
    site = scanner._enclosing_site(scan, pos)
    comment, _ = _comment_above(scan.text, pos)
    safety = _extract_safety(comment) if comment else None
    return {
        "path": rel,
        "line": line_of(scan.text, pos),
        "symbol": decl.name if decl else f"file:{Path(rel).stem}",
        "test_module": scanner._in_test(scan, pos) is not None,
        "safety_comment": safety is not None,
        "inside_unsafe": site is not None,
    }


def vacuity(scanner: Scanner) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    rows = scanner.sites
    caller_re = re.compile(r"\bcaller\b|caller.s|\bprecondition\b", re.IGNORECASE)
    unsafe_fns = {
        (row["path"], row["symbol"]): row
        for row in rows if row["kind"] == "unsafe_fn"
    }
    abi_symbols = {
        (row["path"], row["symbol"])
        for row in rows if row["kind"] == "export"
    }
    targets = [
        row for row in rows
        if row["kind"] == "unsafe_fn" and row["contract_state"] != "absent"
        and caller_re.search(scanner.contract_by_prefix.get(row["contract_sha256"], ""))
    ]

    index = build_call_index(scanner.scans, {row["symbol"] for row in targets})
    for row in targets:
        site: Site = row["_site"]
        callers = []
        for rel, pos in index.get(row["symbol"], []):
            if rel == row["path"] and site.start <= pos <= site.end:
                continue  # recursive or the definition itself
            callers.append(_caller_evidence(scanner, rel, pos))
        production = [c for c in callers if not c["test_module"]]
        established = [
            c for c in production
            if c["safety_comment"] or c["inside_unsafe"]
        ]
        if not production:
            status = "VACUOUS_PRECONDITION"
            scope = "no_production_caller"
            detail = "no production caller exists; the precondition is unreachable"
        elif not established:
            status = "CALLER_OBLIGATION_UNESTABLISHED"
            scope = "unsafe_fn_caller_uncontracted"
            detail = "production callers exist but none carries a SAFETY contract or an unsafe context"
        else:
            status = "CITED_BY_CALLER"
            scope = "caller_cites_contract"
            detail = f"{len(established)} production caller(s) cite a contract; citation is not proof"
        findings.append({
            "site": row["id"], "path": row["path"], "line": row["line"],
            "symbol": row["symbol"], "status": status, "scope": scope,
            "detail": detail, "production_callers": len(production),
            "test_callers": len(callers) - len(production),
            "witness": "lexical_call_witness",
        })

    # Caller obligations stated inside another construct.  A block in an unsafe
    # fn that states its own contract is covered by that contract; a block in a
    # safe fn is not, because a safe caller has no way to establish an unsafe
    # precondition.  Exported functions delegate to the C ABI contract, and
    # unsafe impl/trait sites delegate to the implementer, so those are recorded
    # as separate scopes rather than as Rust-caller failures.
    seen: set[tuple[str, ...]] = set()
    for row in rows:
        if row["kind"] in ("unsafe_fn",):
            continue
        text = scanner.contract_by_prefix.get(row["contract_sha256"], "")
        if not caller_re.search(text):
            continue
        key = (row["path"], row["symbol"])
        if row["kind"] == "unsafe_block":
            if key in abi_symbols:
                scope, status = "abi_export_contract", "EXTERNAL_CALLER_CONTRACT"
                detail = "the obligation is delegated to the documented C ABI caller"
            elif key in unsafe_fns and unsafe_fns[key]["contract_state"] != "absent":
                continue
            elif key in unsafe_fns:
                scope, status = "unsafe_fn_without_contract", "CALLER_OBLIGATION_UNESTABLISHED"
                detail = "the block cites a caller obligation, but its unsafe fn states no contract"
            else:
                scope, status = "safe_api_escape", "VACUOUS_PRECONDITION"
                detail = (
                    "a safe function's SAFETY comment cites a caller obligation; a safe caller "
                    "cannot establish an unsafe precondition, so the stated precondition is not "
                    "reachable through the safe API"
                )
        elif row["kind"] == "export":
            scope, status = "abi_export_contract", "EXTERNAL_CALLER_CONTRACT"
            detail = "the obligation is delegated to the documented C ABI caller"
        elif row["kind"] in ("unsafe_impl", "unsafe_trait"):
            scope, status = "implementer_obligation", "IMPLEMENTER_OBLIGATION"
            detail = "the contract is an implementer obligation, not a caller precondition"
        else:
            scope, status = "extern_block_contract", "EXTERNAL_CALLER_CONTRACT"
            detail = "the obligation belongs to the external symbol's documented contract"
        dedupe = (scope, row["path"], row["symbol"])
        if dedupe in seen:
            continue
        seen.add(dedupe)
        findings.append({
            "site": row["id"], "path": row["path"], "line": row["line"],
            "symbol": row["symbol"], "status": status, "scope": scope,
            "detail": detail, "production_callers": 0, "test_callers": 0,
            "witness": "lexical_contract_witness",
        })

    # Discharge register.  A discharge is a claim, not a row; the only scoped
    # verdict found by a literal search is recorded with the controls its own
    # receipt names.
    discharges = [
        {
            "id": "DISC-OWNEDSTR-OB2",
            "source": "forensics/memory-safety/campaign/safe-c33/OB2-CHECKS.md",
            "claim": "SAFETY_DISCHARGED, scoped to OwnedStr only",
            "controls": [
                "OwnedStr ownership-transition model with three negative controls",
                "nine model/correspondence tests",
                "focused AddressSanitizer runs over runtime::owned_str, runtime::err and x509::v3_prn",
            ],
            "control_could_fail": True,
            "state": "CONTROLLED",
            "note": "the receipt's own controls are named; this register does not adjudicate their sufficiency",
        }
    ]
    refusals: list[dict[str, Any]] = []
    for entry in discharges:
        if not entry["controls"] or not entry["control_could_fail"]:
            refusals.append({
                "code": "ET4_DISCHARGE_WITHOUT_CONTROL",
                "id": entry["id"],
                "detail": "a discharge is recorded with no control that could fail",
            })
    vacuous_satisfied = [f for f in findings if f["status"] == "VACUOUS_PRECONDITION"
                         and f.get("reported_satisfied")]
    for entry in vacuous_satisfied:
        refusals.append({
            "code": "ET4_VACUOUS_REPORTED_SATISFIED",
            "id": entry["site"],
            "detail": "an unreachable precondition is reported as satisfied",
        })
    caller_refusals = [f for f in findings if f["status"] == "CALLER_OBLIGATION_UNESTABLISHED"]
    return {
        "discharges": discharges,
        "findings": findings,
        "refusals": refusals,
        "summary": {
            "discharges": len(discharges),
            "discharge_refusals": len([r for r in refusals
                                       if r["code"] == "ET4_DISCHARGE_WITHOUT_CONTROL"]),
            "unsafe_fns_with_caller_contract": len(targets),
            "vacuous_precondition": len([f for f in findings
                                         if f["status"] == "VACUOUS_PRECONDITION"]),
            "safe_api_escape": len([f for f in findings
                                     if f.get("scope") == "safe_api_escape"]),
            "no_production_caller": len([f for f in findings
                                          if f.get("scope") == "no_production_caller"]),
            "caller_obligation_unestablished": len(caller_refusals),
            "unsafe_fn_without_contract": len([f for f in findings
                                                if f.get("scope") == "unsafe_fn_without_contract"]),
            "external_caller_contract": len([f for f in findings
                                              if f["status"] == "EXTERNAL_CALLER_CONTRACT"]),
            "implementer_obligation": len([f for f in findings
                                            if f["status"] == "IMPLEMENTER_OBLIGATION"]),
            "cited_by_caller": len([f for f in findings if f["status"] == "CITED_BY_CALLER"]),
            "vacuous_reported_satisfied": len(vacuous_satisfied),
        },
    }


# ---------------------------------------------------------------------------
# Tautological assertions.  Lexical and deliberately narrow; a finding is a
# prompt for review, not a verdict on the test.
# ---------------------------------------------------------------------------
ASSERTION_PATTERNS = (
    ("assert_true", re.compile(r"assert!\s*\(\s*true\s*\)")),
    ("assert_false_negated", re.compile(r"assert!\s*\(\s*!\s*false\s*\)")),
    ("assert_self_eq", re.compile(r"assert_eq!\s*\(\s*([A-Za-z_][A-Za-z0-9_:.]*)\s*,\s*\1\s*\)")),
    ("assert_self_ne", re.compile(r"assert_ne!\s*\(\s*([A-Za-z_][A-Za-z0-9_:.]*)\s*,\s*\1\s*\)")),
    ("assert_self_cmp", re.compile(
        r"assert!\s*\(\s*([A-Za-z_][A-Za-z0-9_:.]*)\s*==\s*\1\s*\)")),
    ("assert_true_or", re.compile(r"assert!\s*\(\s*true\s*\|\|")),
    ("assert_false_and", re.compile(r"assert!\s*\(\s*false\s*&&")),
    ("assert_literal_eq", re.compile(r"assert!\s*\(\s*([0-9]+)\s*==\s*\1\s*\)")),
)


def tautologies(scanner: Scanner) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    for rel, scan in scanner.scans.items():
        for start, end, name in scan.test_ranges:
            body = scan.code[start:end]
            for kind, pattern in ASSERTION_PATTERNS:
                for m in pattern.finditer(body):
                    pos = start + m.start()
                    found.append({
                        "path": rel, "line": line_of(scan.text, pos),
                        "test_module": name, "kind": kind,
                        "detail": "the assertion is true for every input",
                    })
        for m in re.finditer(r"#\s*\[\s*ignore\b[^\]]*\]", scan.code):
            ignored.append({"path": rel, "line": line_of(scan.text, m.start()),
                            "detail": "test is not executed by the default run"})
    return found + ignored


# ---------------------------------------------------------------------------
# Suppressions and test-only code, for the axioms register.
# ---------------------------------------------------------------------------
RE_SUPPRESSION = re.compile(
    r"#!?\[(allow|expect)\s*\(([^]]*)\)\]|"
    r"#!?\[cfg_attr\s*\([^]]*,\s*(allow|expect)\s*\(([^]]*)\)\)\]"
)


def suppressions(scanner: Scanner) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    by_lint: Counter[str] = Counter()
    for rel, scan in scanner.scans.items():
        for m in RE_SUPPRESSION.finditer(scan.code):
            kind = m.group(1) or m.group(3)
            lints = (m.group(2) or m.group(4) or "").strip()
            first = lints.split(",")[0].strip() if lints else "UNKNOWN"
            by_lint[first] += 1
            rows.append({
                "path": rel, "line": line_of(scan.text, m.start()),
                "attribute": kind, "lints": lints,
            })
    test_modules = []
    for rel, scan in scanner.scans.items():
        for start, _end, name in scan.test_ranges:
            test_modules.append({"path": rel, "line": line_of(scan.text, start),
                                 "module": name})
    return {
        "total": len(rows),
        "by_lint": dict(sorted(by_lint.items(), key=lambda kv: (-kv[1], kv[0]))),
        "occurrences": rows,
        "test_modules": test_modules,
    }


# ---------------------------------------------------------------------------
# Axiom register
# ---------------------------------------------------------------------------
def axioms_register(supp: dict[str, Any]) -> dict[str, Any]:
    axioms = [
        {
            "id": "AX-ALLOC-SEAM",
            "kind": "allocator_behaviour",
            "statement": "The CRYPTO_* seam preserves the authority's allocation, alignment, zero-initialisation and release semantics.",
            "used_for": "Every ownership-adoption and raw-dereference obligation whose extent comes from a CRYPTO_* allocation.",
            "falsified_by": "A block whose allocator is not the seam, an alignment the seam does not guarantee, a free path that does not match the allocation, or a size that overflows before the allocator sees it.",
            "checked_by": "artifacts/phase18/asan.json; forensics/tools/ownership_audit.py; src/runtime/mem.rs tests",
            "status": "PARTIAL",
        },
        {
            "id": "AX-ALLOC-FAILURE",
            "kind": "allocator_behaviour",
            "statement": "A failed allocation returns null and every caller handles it before forming a reference.",
            "used_for": "Fallible allocation obligations and the claim that overflow is routed to the OpenSSL failure semantics rather than a panic.",
            "falsified_by": "An infallible allocation on a secret-bearing path or an unchecked null that reaches a dereference.",
            "checked_by": "forensics/memory-safety/campaign/safe-c33/CLOSURE.md (OBL-T22-RESIDUAL open)",
            "status": "PARTIAL",
        },
        {
            "id": "AX-ALLOC-METADATA",
            "kind": "allocator_behaviour",
            "statement": "Allocator metadata is outside every owner's extent, and mem::forget/abort bypass Drop.",
            "used_for": "Scoping what an owner's Drop can guarantee.",
            "falsified_by": "An owner that reasons about a header it does not own, or a cleanup claim that assumes Drop runs on abort.",
            "checked_by": "evidence/etp4/VERIFICATION-RECEIPT.md (non-claims)",
            "status": "UNCHECKED",
        },
        {
            "id": "AX-RUST-UB-MODEL",
            "kind": "language_model",
            "statement": "The Rust abstract machine's validity, aliasing and provenance rules are the definition of memory unsafety used to classify impact.",
            "used_for": "Impact class memory_unsafety and every SAFETY contract.",
            "falsified_by": "A compiler or language revision that changes the model, or a claim that relies on behaviour the model leaves unspecified.",
            "checked_by": "docs/UNSAFE.md; docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md",
            "status": "PARTIAL",
        },
        {
            "id": "AX-COMPILER-IDENTITY",
            "kind": "codegen",
            "statement": "Code-generation results are bound to rustc 1.98.1, its LLVM, x86_64-unknown-linux-gnu, release opt-level 3, codegen-units 16, lto=false, overflow-checks=true and panic=unwind.",
            "used_for": "Every timing and branch-audit result; no result transfers to another target or profile.",
            "falsified_by": "A toolchain, profile, linker or target change, or a source edit in a checked function.",
            "checked_by": "docs/CODE-GENERATION-ASSURANCE.md; courts/phase18/timing/binary_branch_audit.py",
            "status": "CHECKED",
        },
        {
            "id": "AX-CODEGEN-BRANCHLESS",
            "kind": "codegen",
            "statement": "A branchless source expression can be compiled to a branch, so constant-time claims require emitted-code evidence.",
            "used_for": "Refusing source-level constant-time arguments.",
            "falsified_by": "A compiler that preserves branchlessness (would weaken the axiom, not the obligation) or a claim that cites source text only.",
            "checked_by": "courts/phase18/timing/binary_branch_audit.py; docs/CODE-GENERATION-ASSURANCE.md",
            "status": "CHECKED",
        },
        {
            "id": "AX-CPU-VARIABLE-LATENCY",
            "kind": "cpu_behaviour",
            "statement": "Instructions used by the audited primitives have data-dependent latency and are not exhaustively modelled.",
            "used_for": "The non-claim that a branch-free instruction stream is constant-time.",
            "falsified_by": "A per-instruction latency model for the exact CPU, which does not exist here.",
            "checked_by": "NONE",
            "status": "UNCHECKED",
        },
        {
            "id": "AX-CPU-FREQUENCY",
            "kind": "cpu_behaviour",
            "statement": "Frequency scaling, SMI, cache state and sibling activity perturb wall-clock timing measurements.",
            "used_for": "Interpreting dudect, perf and TSC results; it is why a low t is not a constant-time proof.",
            "falsified_by": "A measurement environment that excludes every listed effect.",
            "checked_by": "docs/INSTRUMENT-QUALIFICATION.md (dudect limits)",
            "status": "PARTIAL",
        },
        {
            "id": "AX-PMU-COUNTERS",
            "kind": "instrument_model",
            "statement": "PMU counters and perf events measure what their names claim, at the recorded privilege and virtualisation level.",
            "used_for": "Performance and timing evidence.",
            "falsified_by": "Counter multiplexing, virtualisation, or an event mapping that differs from the documented one.",
            "checked_by": "docs/INSTRUMENT-QUALIFICATION.md",
            "status": "PARTIAL",
        },
        {
            "id": "AX-VALGRIND-MODEL",
            "kind": "instrument_model",
            "statement": "Valgrind Memcheck models definedness and addressability, not timing, concurrency or compiler optimisation.",
            "used_for": "Interpreting ctgrind and memory-error observations.",
            "falsified_by": "A defect class outside definedness/addressability, or an uninstrumented path.",
            "checked_by": "docs/INSTRUMENT-QUALIFICATION.md",
            "status": "PARTIAL",
        },
        {
            "id": "AX-CTGRIND-MODEL",
            "kind": "instrument_model",
            "statement": "ctgrind marks secret bytes undefined and reports secret-dependent branches and memory addresses, not cache or microarchitectural leakage.",
            "used_for": "Constant-time evidence at the instruction-semantics level.",
            "falsified_by": "Secret-dependent behaviour with no branch or secret address, or a path Valgrind does not execute.",
            "checked_by": "docs/INSTRUMENT-QUALIFICATION.md",
            "status": "PARTIAL",
        },
        {
            "id": "AX-DUDECT-MODEL",
            "kind": "instrument_model",
            "statement": "dudect's t-statistic is a statistical screen with false negatives; a low t is not evidence of constant time.",
            "used_for": "Timing-screen interpretation only.",
            "falsified_by": "A leakage signal below the chosen threshold, or a measurement whose classes are not the secret classes.",
            "checked_by": "docs/INSTRUMENT-QUALIFICATION.md; courts/phase18/timing",
            "status": "PARTIAL",
        },
        {
            "id": "AX-MIRI-MODEL",
            "kind": "instrument_model",
            "statement": "Miri models the Rust abstract machine within its admitted suite and refuses libc, DSOs, fibres, getrandom and rdtsc.",
            "used_for": "Aliasing and validity observations on the admitted TCB suite.",
            "falsified_by": "A defect outside the admitted suite, or a model gap in the supported subset.",
            "checked_by": "forensics/miri-tcb-suite.json; artifacts/phase18/miri-tcb.json",
            "status": "PARTIAL",
        },
        {
            "id": "AX-ASAN-MODEL",
            "kind": "instrument_model",
            "statement": "AddressSanitizer detects the addressability errors it instruments; a clean run is a bounded observation, not a proof.",
            "used_for": "Interpreting the ASan layers and downstream consumer runs.",
            "falsified_by": "An uninstrumented path, a shadow-memory conflict (OpenSSH seccomp), or a defect ASan does not model.",
            "checked_by": "artifacts/phase18/asan.json; artifacts/phase18/asan-downstream.json",
            "status": "PARTIAL",
        },
        {
            "id": "AX-AUTHORITY-PARITY",
            "kind": "authority_behaviour",
            "statement": "The pinned OpenSSL authority's documented and observed behaviour is the compatibility target.",
            "used_for": "Every differential court and compatibility claim.",
            "falsified_by": "An authority behaviour that differs from its documentation, or a candidate that matches an undocumented accident.",
            "checked_by": "docs/PARITY_MODEL.md; docs/AUTHORITY_POLICY.md",
            "status": "PARTIAL",
        },
        {
            "id": "AX-AUTHORITY-UB",
            "kind": "authority_behaviour",
            "statement": "The authority may contain undefined behaviour; the candidate does not reproduce it merely because one run did.",
            "used_for": "Divergence classification.",
            "falsified_by": "A candidate that imitates an authority UB and calls the result compatibility.",
            "checked_by": "docs/UNSAFE.md section 5; docs/SECURITY_DIVERGENCE_POLICY.md",
            "status": "CHECKED",
        },
        {
            "id": "AX-ATOMIC-ORDERING",
            "kind": "concurrency_model",
            "statement": "The atomic orderings used for publication and reference counting are sufficient for their stated invariants.",
            "used_for": "Concurrency-publication obligations and refcount transitions.",
            "falsified_by": "A publication that needs Acquire/Release but uses Relaxed, or a refcount transition that races.",
            "checked_by": "docs/CONCURRENCY_MODEL.md (loom where useful; not exhaustive)",
            "status": "PARTIAL",
        },
        {
            "id": "AX-LIBC-ABI",
            "kind": "platform_abi",
            "statement": "libc signatures, errno semantics and the C ABI used at the seam match the target libc.",
            "used_for": "FFI-call and ABI-export obligations.",
            "falsified_by": "A libc version or target with different signatures, errno rules or calling convention.",
            "checked_by": "NONE",
            "status": "UNCHECKED",
        },
        {
            "id": "AX-OS-SYSCALL",
            "kind": "platform_abi",
            "statement": "The syscalls used for randomness, threads, memory and time have the documented behaviour on the target kernel.",
            "used_for": "Runtime and async obligations.",
            "falsified_by": "A kernel or sandbox that changes a return value or blocks a syscall.",
            "checked_by": "NONE",
            "status": "UNCHECKED",
        },
        {
            "id": "AX-REPR-C",
            "kind": "layout_model",
            "statement": "repr(C) layouts, field order, padding and alignment match the C authority's visible layout.",
            "used_for": "Layout/repr obligations and ABI exports.",
            "falsified_by": "A field, packing or target change, or a C compiler with a different layout rule.",
            "checked_by": "docs/ABI_POLICY.md; artifacts/phase2/libcrypto.ld; ABI layout courts",
            "status": "PARTIAL",
        },
        {
            "id": "AX-PANIC-UNWIND",
            "kind": "runtime_model",
            "statement": "Panics do not unwind across the C ABI, and guard_ffi's catch_unwind contains the unwind.",
            "used_for": "ABI-export obligations and panic-safety classifications.",
            "falsified_by": "A panic that escapes, or a partially mutated state after a caught panic.",
            "checked_by": "docs/UNSAFE.md section 3; panic-guard tests",
            "status": "PARTIAL",
        },
        {
            "id": "AX-OVERFLOW-CHECKS",
            "kind": "build_profile",
            "statement": "Release builds enable overflow-checks, so arithmetic overflow panics rather than wrapping.",
            "used_for": "Fallible arithmetic obligations.",
            "falsified_by": "A profile that disables overflow-checks, or arithmetic on raw pointers that bypasses the check.",
            "checked_by": "Cargo.toml; docs/CODE-GENERATION-ASSURANCE.md",
            "status": "CHECKED",
        },
        {
            "id": "AX-SECRET-CLEANSE",
            "kind": "secret_model",
            "statement": "OPENSSL_cleanse writes the whole secret-bearing extent and is not optimised away.",
            "used_for": "Secret-lifetime obligations.",
            "falsified_by": "An optimiser that elides the write, a length that does not cover spare capacity, or a copy outside the cleansed extent.",
            "checked_by": "evidence/etp4/VERIFICATION-RECEIPT.md (bounded observations)",
            "status": "PARTIAL",
        },
        {
            "id": "AX-CONSTANT-TIME-MEMCMP",
            "kind": "secret_model",
            "statement": "CRYPTO_memcmp accumulates over the full length with no secret-dependent early exit.",
            "used_for": "Constant-time comparison obligations.",
            "falsified_by": "A length that depends on the secret, or a compiler transformation that introduces a branch.",
            "checked_by": "binary_branch_audit; ctgrind cases",
            "status": "PARTIAL",
        },
        {
            "id": "AX-PROVIDER-DISPATCH",
            "kind": "indirection_model",
            "statement": "Provider and ENGINE dispatch tables contain valid function pointers for every reachable method.",
            "used_for": "Callback and delegated-contract obligations.",
            "falsified_by": "A missing or mismatched method, or a table mutated after publication.",
            "checked_by": "docs/PROVIDER_MODEL.md; dispatch courts",
            "status": "PARTIAL",
        },
        {
            "id": "AX-CALLBACK-LIFETIME",
            "kind": "callback_model",
            "statement": "An application callback may re-enter the library, and a borrowed pointer held across it remains valid only under the documented contract.",
            "used_for": "Callback/reentrancy-edge obligations.",
            "falsified_by": "A callback that frees or mutates the parent, or a lock held across the call.",
            "checked_by": "docs/OWNERSHIP_MODEL.md; callback enumeration gate",
            "status": "PARTIAL",
        },
        {
            "id": "AX-THREAD-LOCAL",
            "kind": "concurrency_model",
            "statement": "Thread-local storage and the error queue are isolated per thread as the authority documents.",
            "used_for": "Concurrency obligations.",
            "falsified_by": "A queue shared across threads, or TLS destroyed at the wrong time.",
            "checked_by": "docs/CONCURRENCY_MODEL.md; multi-threaded courts",
            "status": "PARTIAL",
        },
        {
            "id": "AX-FORK-BEHAVIOUR",
            "kind": "process_model",
            "statement": "Fork and process interaction, including DRBG reseeding, follows the authority where observable.",
            "used_for": "Process-related obligations.",
            "falsified_by": "A forked child that reuses parent state without the documented reseed.",
            "checked_by": "docs/CONCURRENCY_MODEL.md section 5",
            "status": "PARTIAL",
        },
        {
            "id": "AX-TEST-HARNESS",
            "kind": "harness_model",
            "statement": "The test runner reports an inverted assertion as a failure and a passing test as a pass.",
            "used_for": "Every control that relies on a test result.",
            "falsified_by": "A runner that swallows assertion failures or a test that is filtered out.",
            "checked_by": "forensics/tools/tests/test_unsafe_obligations.py (inverted-assertion control)",
            "status": "CHECKED",
        },
        {
            "id": "AX-JSON-VALIDATION",
            "kind": "harness_model",
            "statement": "python3 -m json.tool establishes syntactic validity, not schema or semantic correctness.",
            "used_for": "The evidence validation step.",
            "falsified_by": "A syntactically valid document that violates the schema or the counts.",
            "checked_by": "forensics/tools/unsafe_obligations.py validate",
            "status": "CHECKED",
        },
        {
            "id": "AX-SCANNER-LEXICAL",
            "kind": "scanner_model",
            "statement": "unsafe_footprint.code_only blanks comments and string literals while preserving character positions, so the scanner sees code and not prose.",
            "used_for": "Every site, class and contract in this inventory.",
            "falsified_by": "A Rust lexical form the best-effort lexer mishandles (raw strings, nested block comments, char literals versus lifetimes).",
            "checked_by": "forensics/tools/tests (code_only controls); this item is heuristic",
            "status": "PARTIAL",
        },
        {
            "id": "AX-SITE-STABILITY",
            "kind": "identity_model",
            "statement": "The source tree digest recorded in the inventory equals the tree the rows were derived from.",
            "used_for": "Binding the inventory to a candidate.",
            "falsified_by": "A source edit after the scan, or a file order or encoding change.",
            "checked_by": "forensics/tools/unsafe_obligations.py validate",
            "status": "CHECKED",
        },
        {
            "id": "AX-GIT-BLOB",
            "kind": "identity_model",
            "statement": "Git blob digests at a named commit identify the cited artefact.",
            "used_for": "The T1 graph's digests.",
            "falsified_by": "A rewritten history or a path read from the working tree while the graph claims a commit.",
            "checked_by": "forensics/tools/traceability.py",
            "status": "CHECKED",
        },
        {
            "id": "AX-COURT-CAP",
            "kind": "venue_model",
            "statement": "The court's cgroup memory cap and RLIMIT_DATA bound the run without changing program semantics.",
            "used_for": "Every Python and Rust result produced in the court.",
            "falsified_by": "A run whose result depends on the cap, or a run outside the court.",
            "checked_by": "docker/openssl-rs-court.sh (infrastructure, out of conversion scope)",
            "status": "PARTIAL",
        },
        {
            "id": "AX-SUPPRESSION-SCOPE",
            "kind": "suppression_model",
            "statement": "An allow/expect attribute suppresses a lint diagnostic and does not change runtime behaviour or discharge a contract.",
            "used_for": "Interpreting the suppression register.",
            "falsified_by": "An attribute that changes code generation, or a suppression used as a safety argument.",
            "checked_by": "this register; the attributes are recorded, not adjudicated",
            "status": "UNCHECKED",
        },
        {
            "id": "AX-TEST-ONLY",
            "kind": "suppression_model",
            "statement": "Code under cfg(test) is absent from the release configuration and cannot be the control for a production obligation.",
            "used_for": "Coverage classification and the test-only bypass register.",
            "falsified_by": "A cfg(test) item compiled into release, or a production obligation whose only control is a test-only model.",
            "checked_by": "Cargo.toml; this register",
            "status": "PARTIAL",
        },
        {
            "id": "AX-AUTHORITY-VERSION",
            "kind": "authority_behaviour",
            "statement": "The authority version named by each court is the version that produced the observed behaviour.",
            "used_for": "Differential compatibility results.",
            "falsified_by": "A version banner that differs from the linked library, or an unpinned authority build.",
            "checked_by": "evidence/etp5/IDENTITY.md (open provenance gaps)",
            "status": "PARTIAL",
        },
    ]
    unchecked = [a["id"] for a in axioms if a["status"] == "UNCHECKED"]
    return {
        "schema": AXIOMS_SCHEMA,
        "kind": "axiom-and-admitted-result-register",
        "item": "ETP-T4 of docs/ETP-TODO.md",
        "identity": {
            "scanner": "forensics/tools/unsafe_obligations.py",
            "scanner_sha256": hashlib.sha256(TOOL.read_bytes()).hexdigest(),
            "heuristic": True,
        },
        "vocabularies": {"status": ["CHECKED", "PARTIAL", "UNCHECKED"]},
        "axioms": axioms,
        "suppressions": supp,
        "summary": {
            "axioms": len(axioms),
            "checked": len([a for a in axioms if a["status"] == "CHECKED"]),
            "partial": len([a for a in axioms if a["status"] == "PARTIAL"]),
            "unchecked": len(unchecked),
            "unchecked_ids": unchecked,
            "suppressions": supp["total"],
            "test_modules": len(supp["test_modules"]),
        },
        "non_claims": [
            "An axiom is a stated premise, not a verified fact; its status says what checks exist, not that it is true.",
            "A CHECKED axiom was checked for the scope named in checked_by, not universally.",
            "A suppression is recorded, never adjudicated; recording it does not make it safe.",
            "The absence of a finding is not the absence of an unchecked axiom.",
        ],
    }


# ---------------------------------------------------------------------------
# Inventory assembly
# ---------------------------------------------------------------------------
def encode_sites(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Indexed columnar rows.  Every row is still a record; repeated strings live in tables."""
    ordered = sorted(rows, key=lambda r: (r["path"], r["line"], r["kind"], r["id"]))
    paths = sorted({r["path"] for r in ordered})
    symbols = sorted({r["symbol"] for r in ordered})
    boundaries = sorted({r["boundary_id"] for r in ordered})
    coverages = sorted({r["coverage_id"] for r in ordered})
    reasons = sorted({r["contract_reason"] for r in ordered})
    pid = {v: i for i, v in enumerate(paths)}
    sid = {v: i for i, v in enumerate(symbols)}
    bid = {v: i for i, v in enumerate(boundaries)}
    cid = {v: i for i, v in enumerate(coverages)}
    rid = {v: i for i, v in enumerate(reasons)}
    knd = {v: i for i, v in enumerate(SITE_KINDS)}
    cls = {v: i for i, v in enumerate(OBLIGATION_CLASSES)}
    imp = {v: i for i, v in enumerate(IMPACTS)}
    cst = {v: i for i, v in enumerate(CONTRACT_STATES)}
    bkd = {v: i for i, v in enumerate(BOUNDARY_KINDS)}
    cov = {v: i for i, v in enumerate(COVERAGE_KINDS)}
    encoded = []
    for r in ordered:
        mask = sum(1 << imp[i] for i in r["impacts"] if i in imp)
        encoded.append([
            r["id"], pid[r["path"]], r["line"], r["column"], knd[r["kind"]],
            sid[r["symbol"]], cls[r["class"]], imp[r["impact"]], mask,
            cst[r["contract_state"]], rid[r["contract_reason"]], r["contract_sha256"],
            bkd[r["boundary_kind"]], bid[r["boundary_id"]], cov[r["coverage_kind"]],
            cid[r["coverage_id"]],
        ])
    return {
        "encoding": "indexed-v1",
        "columns": ["id", "path", "line", "column", "kind", "symbol", "class",
                    "impact", "impacts", "contract_state", "contract_reason",
                    "contract_sha256", "boundary_kind", "boundary_id",
                    "coverage_kind", "coverage_id"],
        "tables": {"path": paths, "symbol": symbols, "boundary_id": boundaries,
                   "coverage_id": coverages, "contract_reason": reasons},
        "vocabularies": {
            "kind": list(SITE_KINDS),
            "class": list(OBLIGATION_CLASSES),
            "impact": list(IMPACTS),
            "contract_state": list(CONTRACT_STATES),
            "boundary_kind": list(BOUNDARY_KINDS),
            "coverage_kind": list(COVERAGE_KINDS),
        },
        "rows": encoded,
    }


def decode_sites(block: dict[str, Any]) -> list[dict[str, Any]]:
    """Invert `encode_sites`; the validator and the `show` mode read through this."""
    if block.get("encoding") != "indexed-v1":
        return [dict(zip(block["columns"], row)) for row in block["rows"]]
    tables = block["tables"]
    vocab = block["vocabularies"]
    out = []
    for row in block["rows"]:
        mask = row[8]
        impacts = [name for bit, name in enumerate(vocab["impact"]) if mask & (1 << bit)]
        out.append({
            "id": row[0],
            "path": tables["path"][row[1]],
            "line": row[2],
            "column": row[3],
            "kind": vocab["kind"][row[4]],
            "symbol": tables["symbol"][row[5]],
            "class": vocab["class"][row[6]],
            "impact": vocab["impact"][row[7]],
            "impacts": impacts,
            "contract_state": vocab["contract_state"][row[9]],
            "contract_reason": tables["contract_reason"][row[10]],
            "contract_sha256": row[11],
            "boundary_kind": vocab["boundary_kind"][row[12]],
            "boundary_id": tables["boundary_id"][row[13]],
            "coverage_kind": vocab["coverage_kind"][row[14]],
            "coverage_id": tables["coverage_id"][row[15]],
        })
    return out


def _git(*args: str) -> str | None:
    """Return stripped git output, or None when git is absent or refuses."""
    try:
        result = subprocess.run(
            ["git", "-c", "safe.directory=*", "-C", str(REPO_ROOT), *args],
            capture_output=True, text=True, check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _worktree_state() -> str:
    """Describe the scanned source tree honestly; git identity is provenance, not a binding."""
    changed = _git("status", "--porcelain", "--", "src")
    if changed is None:
        return "git unavailable; the source tree digest is the live binding"
    if changed:
        return "src had uncommitted changes at the scan: " + " ".join(changed.splitlines())
    return (
        "src unchanged at the scan; the evidence files are regenerated in the working "
        "tree before the evidence commit"
    )


def build_inventory() -> dict[str, Any]:
    scanner = Scanner()
    scanner.build()
    vac = vacuity(scanner)
    taut = tautologies(scanner)
    supp = suppressions(scanner)

    rows = sorted(scanner.sites, key=lambda r: (r["path"], r["line"], r["kind"], r["id"]))
    ops = []
    for op in sorted(scanner.operations, key=lambda o: (o["path"], o["line"], o["kind"], o["id"])):
        ops.append([op["id"], op["path"], op["line"], op["kind"],
                    op["enclosing_site"], int(op["standalone"])])

    by_class = Counter(r["class"] for r in rows)
    by_impact = Counter(r["impact"] for r in rows)
    by_impact_any = Counter()
    for r in rows:
        for impact in r["impacts"]:
            by_impact_any[impact] += 1
    contract = Counter(r["contract_state"] for r in rows)
    coverage = Counter(r["coverage_kind"] for r in rows)
    boundary = Counter(r["boundary_kind"] for r in rows)
    op_kinds = Counter(o[3] for o in ops)

    vacuity_failures = [
        f for f in vac["findings"]
        if f["status"] in ("VACUOUS_PRECONDITION", "CALLER_OBLIGATION_UNESTABLISHED")
    ]
    ignored = [t for t in taut if "test is not executed" in t["detail"]]
    taut_findings = [t for t in taut if "test is not executed" not in t["detail"]]

    by_class_detail = {}
    for klass in OBLIGATION_CLASSES:
        subset = [r for r in rows if r["class"] == klass]
        controlled = [r for r in subset if r["coverage_kind"] in ("test", "instrument")]
        uncovered = [
            r for r in subset
            if r["contract_state"] != "argument"
            and r["coverage_kind"] not in ("test", "instrument")
        ]
        by_class_detail[klass] = {
            "sites": len(subset),
            "contract_argument": sum(1 for r in subset if r["contract_state"] == "argument"),
            "contract_restatement": sum(1 for r in subset if r["contract_state"] == "restatement"),
            "contract_absent": sum(1 for r in subset if r["contract_state"] == "absent"),
            "controlled": len(controlled),
            "sites_without_contract_or_control": len(uncovered),
        }

    summary = {
        "sites": len(rows),
        "by_class": {k: by_class.get(k, 0) for k in OBLIGATION_CLASSES},
        "by_class_detail": by_class_detail,
        "by_impact_primary": {k: by_impact.get(k, 0) for k in IMPACTS},
        "by_impact_any": {k: by_impact_any.get(k, 0) for k in IMPACTS},
        "contract_absent": contract.get("absent", 0),
        "contract_restatement": contract.get("restatement", 0),
        "contract_argument": contract.get("argument", 0),
        "coverage_none": coverage.get("none", 0),
        "coverage_argument_only": coverage.get("argument", 0),
        "coverage_test": coverage.get("test", 0),
        "coverage_instrument": coverage.get("instrument", 0),
        "boundary_unconfined": boundary.get("UNCONFINED", 0),
        "by_boundary_kind": {k: boundary.get(k, 0) for k in BOUNDARY_KINDS},
        "operations": len(ops),
        "by_operation_kind": {k: op_kinds.get(k, 0) for k in sorted(OPERATION_PATTERNS)},
        "vacuity": vac["summary"],
        "tautological_assertions": len(taut_findings),
        "ignored_tests": len(ignored),
        "suppressions": supp["total"],
        "test_modules": len(supp["test_modules"]),
    }

    document = {
        "schema": SITES_SCHEMA,
        "kind": "unsafe-site-obligation-inventory",
        "item": "ETP-T4 of docs/ETP-TODO.md",
        "identity": {
            "commit": _git("rev-parse", "HEAD") or "UNRECORDED",
            "branch": _git("rev-parse", "--abbrev-ref", "HEAD") or "UNRECORDED",
            "worktree_state": _worktree_state(),
            "source_tree_sha256": scanner.source_hash,
            "source_files": len(scanner.files),
            "source_lines": scanner.total_lines,
            "scanner": "forensics/tools/unsafe_obligations.py",
            "scanner_sha256": hashlib.sha256(TOOL.read_bytes()).hexdigest(),
            "heuristic": True,
            "granularity": "one row per lexical unsafe construct (block, fn, impl, trait, extern "
                           "block, export) plus operation rows for named raw operations; not a "
                           "compiler-derived census and not a HIR/MIR walk",
            "settling_method": "re-run `python3 forensics/tools/unsafe_obligations.py inventory`; "
                               "the source_tree_sha256 in this file must equal the tree the rows "
                               "describe",
        },
        "vocabularies": {
            "obligation_class": list(OBLIGATION_CLASSES),
            "impact": list(IMPACTS),
            "contract_state": list(CONTRACT_STATES),
            "coverage_kind": list(COVERAGE_KINDS),
            "boundary_kind": list(BOUNDARY_KINDS),
            "site_kind": ["unsafe_block", "unsafe_fn", "unsafe_impl", "unsafe_trait",
                          "unsafe_extern", "export"],
        },
        "impact_by_class": {k: list(v) for k, v in CLASS_IMPACT.items()},
        "heuristic": {
            "restatement": {
                "rule": "a contract is an ARGUMENT when its normalised text contains a support "
                        "marker (cause, checked property, witness/reference) and a RESTATEMENT "
                        "when it only names the operation or asserts a property with no support; "
                        "fewer than four words is a restatement by length",
                "argument_markers": list(ARGUMENT_MARKERS),
                "reference_markers": list(REFERENCE_MARKERS),
                "limits": [
                    "lexical, not semantic: a true argument written without a listed marker is "
                    "classified as a restatement",
                    "a restatement that names a marker word is classified as an argument",
                    "the classification says what the text contains, not whether the argument is "
                    "true, sufficient or applicable",
                ],
            },
            "class": "deterministic mapping from construct kind, symbol and body tokens; the "
                     "operation kind is a classification, not a compiler fact",
            "boundary": "the narrowest named owner type, export, constructor or boundary module "
                        "that encloses the site; otherwise UNCONFINED",
            "coverage": "a test module or a named instrument when the site is inside one, the "
                        "source contract when it is an argument, otherwise none; an argument is "
                        "not a control",
        },
        "summary": summary,
        "sites": encode_sites(rows),
        "operations": {
            "columns": ["id", "path", "line", "kind", "enclosing_site", "standalone"],
            "rows": ops,
        },
        "contracts": {
            "note": "unique normalised contract texts, keyed by the first 16 hex of their SHA-256; "
                    "a row carries the same prefix in contract_sha256",
            "entries": {k[:16]: v for k, v in sorted(scanner.contracts.items())},
        },
        "vacuity": vac,
        "assertions": {
            "tautological": taut_findings,
            "ignored": ignored,
        },
        "suppressions": {
            "total": supp["total"],
            "by_lint": supp["by_lint"],
            "test_modules": supp["test_modules"],
        },
        "non_claims": [
            "A row records a lexical classification, not a proof; an unsafe site is not by itself a defect.",
            "A SAFETY comment is the author's statement, not an established precondition.",
            "An impact class names what the unmet obligation can reach, not what a run observed.",
            "A site with no control is an orphan, not a discharged obligation.",
            "The scanner is heuristic; its limits are stated in heuristic.restatement and in the tool docstring.",
            "This inventory does not modify src/ and does not fix any site it records.",
        ],
    }
    return {"document": document, "axioms": axioms_register(supp), "vacuity": vac}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
class Refusal(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _load(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Refusal("ET4_JSON", f"{path}: {exc}") from exc


def _source_hash() -> str:
    digest = hashlib.sha256()
    for path in sorted((REPO_ROOT / "src").rglob("*.rs")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest().encode())
        digest.update(b"\n")
    return digest.hexdigest()


def validate(sites_path: Path = SITES_OUT, axioms_path: Path = AXIOMS_OUT) -> list[str]:
    problems: list[str] = []
    doc = _load(sites_path)
    ax = _load(axioms_path)
    if doc.get("schema") != SITES_SCHEMA:
        raise Refusal("ET4_SCHEMA", f"{sites_path}: schema {doc.get('schema')!r}")
    if ax.get("schema") != AXIOMS_SCHEMA:
        raise Refusal("ET4_SCHEMA", f"{axioms_path}: schema {ax.get('schema')!r}")
    ident = doc["identity"]
    actual = _source_hash()
    if ident["source_tree_sha256"] != actual:
        problems.append(
            f"ET4_SOURCE_DRIFT: inventory records {ident['source_tree_sha256']}, tree is {actual}"
        )
    if ident["scanner_sha256"] != hashlib.sha256(TOOL.read_bytes()).hexdigest():
        problems.append("ET4_SCANNER_DRIFT: the scanner changed after the inventory was written")
    vocab = doc["vocabularies"]
    rows = decode_sites(doc["sites"])
    if len(rows) != doc["summary"]["sites"]:
        problems.append(
            f"ET4_COUNT: summary.sites={doc['summary']['sites']} rows={len(rows)}"
        )
    by_class = Counter()
    by_impact = Counter()
    contract = Counter()
    coverage = Counter()
    boundary = Counter()
    for row in rows:
        klass = row["class"]
        if klass not in vocab["obligation_class"]:
            problems.append(f"ET4_VOCAB: {row['id']} class {klass!r}")
        by_class[klass] += 1
        impact = row["impact"]
        if impact not in vocab["impact"]:
            problems.append(f"ET4_VOCAB: {row['id']} impact {impact!r}")
        by_impact[impact] += 1
        state = row["contract_state"]
        if state not in vocab["contract_state"]:
            problems.append(f"ET4_VOCAB: {row['id']} contract_state {state!r}")
        contract[state] += 1
        cov = row["coverage_kind"]
        if cov not in vocab["coverage_kind"]:
            problems.append(f"ET4_VOCAB: {row['id']} coverage_kind {cov!r}")
        coverage[cov] += 1
        bk = row["boundary_kind"]
        if bk not in vocab["boundary_kind"]:
            problems.append(f"ET4_VOCAB: {row['id']} boundary_kind {bk!r}")
        boundary[bk] += 1
    summary = doc["summary"]
    for label, counter, key in (
        ("by_class", by_class, "obligation_class"),
        ("by_impact_primary", by_impact, "impact"),
    ):
        for name in vocab[key]:
            if summary[label].get(name, 0) != counter.get(name, 0):
                problems.append(
                    f"ET4_COUNT: {label}.{name}={summary[label].get(name, 0)} rows={counter.get(name, 0)}"
                )
    if (summary["contract_absent"] + summary["contract_restatement"]
            + summary["contract_argument"]) != summary["sites"]:
        problems.append("ET4_COUNT: contract states do not sum to the site count")
    if (summary["coverage_none"] + summary["coverage_argument_only"]
            + summary["coverage_test"] + summary["coverage_instrument"]) != summary["sites"]:
        problems.append("ET4_COUNT: coverage kinds do not sum to the site count")
    if summary["contract_absent"] != contract.get("absent", 0):
        problems.append("ET4_COUNT: contract_absent")
    if summary["contract_restatement"] != contract.get("restatement", 0):
        problems.append("ET4_COUNT: contract_restatement")
    if summary["contract_argument"] != contract.get("argument", 0):
        problems.append("ET4_COUNT: contract_argument")
    if summary["coverage_none"] != coverage.get("none", 0):
        problems.append("ET4_COUNT: coverage_none")
    if summary["coverage_argument_only"] != coverage.get("argument", 0):
        problems.append("ET4_COUNT: coverage_argument_only")
    if summary["coverage_test"] != coverage.get("test", 0):
        problems.append("ET4_COUNT: coverage_test")
    if summary["coverage_instrument"] != coverage.get("instrument", 0):
        problems.append("ET4_COUNT: coverage_instrument")
    if summary["boundary_unconfined"] != boundary.get("UNCONFINED", 0):
        problems.append("ET4_COUNT: boundary_unconfined")
    detail = summary.get("by_class_detail", {})
    for klass in vocab["obligation_class"]:
        entry = detail.get(klass)
        if not isinstance(entry, dict):
            problems.append(f"ET4_COUNT: by_class_detail has no {klass}")
            continue
        if entry.get("sites") != by_class.get(klass, 0):
            problems.append(f"ET4_COUNT: by_class_detail.{klass}.sites")
        if (entry.get("contract_argument", 0) + entry.get("contract_restatement", 0)
                + entry.get("contract_absent", 0)) != entry.get("sites", 0):
            problems.append(f"ET4_COUNT: by_class_detail.{klass} contract states")
        if entry.get("sites_without_contract_or_control", 0) > entry.get("sites", 0):
            problems.append(f"ET4_COUNT: by_class_detail.{klass} uncovered > sites")
    for entry in doc.get("assertions", {}).get("tautological", []):
        problems.append(
            f"ET4_ASSERTION_CANNOT_FAIL: {entry.get('path')}:{entry.get('line')} "
            f"({entry.get('kind')})"
        )
    vac = doc.get("vacuity", {})
    for entry in vac.get("discharges", []):
        if not entry.get("controls") or not entry.get("control_could_fail"):
            problems.append(
                f"ET4_DISCHARGE_WITHOUT_CONTROL: {entry.get('id')}"
            )
    for finding in vac.get("findings", []):
        if finding.get("status") == "VACUOUS_PRECONDITION" and finding.get("reported_satisfied"):
            problems.append(
                f"ET4_VACUOUS_REPORTED_SATISFIED: {finding.get('site')}"
            )
        if finding.get("status") == "SATISFIED" and not finding.get("witness"):
            problems.append(
                f"ET4_CALLER_OBLIGATION_UNESTABLISHED: {finding.get('site')}"
            )
    ax_summary = ax["summary"]
    unchecked = [a["id"] for a in ax["axioms"] if a["status"] == "UNCHECKED"]
    if ax_summary["axioms"] != len(ax["axioms"]):
        problems.append("ET4_COUNT: axioms")
    if ax_summary["unchecked"] != len(unchecked):
        problems.append("ET4_COUNT: unchecked")
    if ax_summary["unchecked_ids"] != unchecked:
        problems.append("ET4_COUNT: unchecked_ids")
    for axiom in ax["axioms"]:
        for key in ("statement", "used_for", "falsified_by", "checked_by", "status"):
            if not axiom.get(key):
                problems.append(f"ET4_AXIOM: {axiom.get('id')} has no {key}")
    if ax["suppressions"]["total"] != len(ax["suppressions"]["occurrences"]):
        problems.append("ET4_COUNT: suppressions")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="unsafe_obligations.py", add_help=True)
    parser.add_argument("mode", choices=["inventory", "axioms", "all", "validate",
                                         "summary", "show"])
    parser.add_argument("site", nargs="?")
    args = parser.parse_args(argv)
    try:
        if args.mode in ("inventory", "axioms", "all"):
            built = build_inventory()
            OUTDIR.mkdir(parents=True, exist_ok=True)
            if args.mode in ("inventory", "all"):
                SITES_OUT.write_text(
                    json.dumps(built["document"], indent=1, sort_keys=False) + "\n",
                    encoding="utf-8",
                )
            if args.mode in ("axioms", "all"):
                AXIOMS_OUT.write_text(
                    json.dumps(built["axioms"], indent=1, sort_keys=False) + "\n",
                    encoding="utf-8",
                )
                VACUITY_OUT.write_text(
                    json.dumps(built["vacuity"], indent=1, sort_keys=False) + "\n",
                    encoding="utf-8",
                )
            if args.mode in ("inventory", "all"):
                s = built["document"]["summary"]
                print(f"[etp-t4] sites={s['sites']} operations={s['operations']} "
                      f"absent={s['contract_absent']} restatement={s['contract_restatement']} "
                      f"argument={s['contract_argument']} none={s['coverage_none']} "
                      f"unconfined={s['boundary_unconfined']}")
            return 0
        if args.mode == "validate":
            problems = validate()
            if problems:
                for problem in problems:
                    print(problem, file=sys.stderr)
                return 1
            print("[etp-t4] inventory and axioms validate: 0 problems")
            return 0
        if args.mode == "summary":
            doc = _load(SITES_OUT)
            ax = _load(AXIOMS_OUT)
            print(json.dumps({"sites": doc["summary"], "axioms": ax["summary"]},
                             indent=2, sort_keys=True))
            return 0
        if args.mode == "show":
            if not args.site:
                parser.error("show requires a site id")
            doc = _load(SITES_OUT)
            for row in decode_sites(doc["sites"]):
                if row["id"] == args.site:
                    print(json.dumps(row, indent=2, sort_keys=True))
                    return 0
            print(f"site {args.site!r} not found", file=sys.stderr)
            return 1
        parser.error("unknown mode")
    except Refusal as exc:
        print(f"{exc.code}: {exc.detail}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
